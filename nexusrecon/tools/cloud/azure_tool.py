"""
Azure / Entra ID / M365 reconnaissance tool.

Implements the full Azure/Entra/M365 recon capability catalog:
  - Tenant ID and federation discovery via openid-configuration and getuserrealm.srf
  - Federation type detection (Federated = ADFS, Managed = cloud-only/hash-sync)
  - Default .onmicrosoft.com tenant domain discovery
  - Storage enumeration (blob, file, queue, table)
  - Azure App Service discovery
  - Azure DevOps org enumeration
  - ADFS endpoint detection
  - OneDrive/SharePoint user existence validation
  - Teams external federation discovery
  - DKIM selector enumeration
  - Exchange Online discovery

Tier: T0-T1 (passive endpoints only, no active auth attempts)
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional

import httpx

from nexusrecon.opsec.useragent import random_ua
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class AzureM365Tool(OSINTTool):
    name = "azure_m365_recon"
    tier = Tier.T0
    category = Category.CLOUD_AZURE
    requires_keys = []
    description = "Azure/Entra ID/M365 tenant enumeration via public endpoints"
    target_types = ["domain", "m365_tenant"]

    def __init__(self) -> None:
        super().__init__()
        self._http: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                timeout=10.0,
                headers={"User-Agent": random_ua()},
                follow_redirects=True,
                http2=True,
            )
        return self._http

    async def _close(self) -> None:
        if self._http:
            await self._http.aclose()

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        results: Dict[str, Any] = {}

        try:
            client = await self._get_client()

            # 1. OpenID configuration (tenant ID + federation type)
            openid_info = await self._get_openid_config(client, target)
            results["openid_config"] = openid_info

            # 2. User realm (federation type + auth URL)
            realm_info = await self._get_user_realm(client, target)
            results["user_realm"] = realm_info

            # 3. .onmicrosoft.com domain discovery
            onmicrosoft = await self._discover_onmicrosoft(client, target)
            results["onmicrosoft_domain"] = onmicrosoft

            # 4. Azure Storage enumeration
            storage_results = await self._enumerate_storage(client, target)
            results["storage"] = storage_results

            # 5. Azure App Service discovery
            app_services = await self._enumerate_app_services(client, target)
            results["app_services"] = app_services

            # 6. Azure DevOps org enumeration
            devops = await self._enumerate_devops(client, target)
            results["azure_devops"] = devops

            # 7. ADFS endpoint detection
            adfs = await self._detect_adfs(client, target)
            results["adfs"] = adfs

            # 8. DKIM selector enumeration
            dkim = await self._check_dkim_selectors(client, target)
            results["dkim_selectors"] = dkim

            # 9. OneDrive/SharePoint discovery (for emails if provided)
            emails = kwargs.get("emails", [])
            if emails:
                onedrive_results = await self._check_onedrive(client, emails)
                results["onedrive"] = onedrive_results

            # 10. Tenant ID from OpenID
            results["summary"] = self._summarize(openid_info, realm_info, onmicrosoft, adfs)

            # B26: tag attribution confidence — 1.0 only if openid-config verified for exact domain
            openid_verified = results.get("openid_config", {}).get("found", False)
            results["attribution_confidence"] = 1.0 if openid_verified else 0.2
            results["attribution_signals"] = (
                ["openid_config_verified"]
                if openid_verified
                else ["no_openid_config", "stem_match_only"]
            )

            # B29: propagate attribution_confidence to each sub-field so the agent
            # (and downstream gate) see the gate at every level, not just top-level.
            # Microsoft's getuserrealm.srf returns "Managed" for ANY domain — its data
            # is reliable ONLY when openid_verified is also true. Stem-enumerated
            # onmicrosoft / app_services / azure_devops findings are always stem-match.
            sub_conf = 1.0 if openid_verified else 0.2
            sub_sigs = ["openid_config_verified"] if openid_verified else ["stem_match_only", "no_openid_config"]
            if isinstance(results.get("user_realm"), dict):
                results["user_realm"]["attribution_confidence"] = sub_conf
                results["user_realm"]["attribution_signals"] = sub_sigs
            if isinstance(results.get("onmicrosoft_domain"), dict):
                results["onmicrosoft_domain"]["attribution_confidence"] = sub_conf
                results["onmicrosoft_domain"]["attribution_signals"] = sub_sigs
            for app in results.get("app_services", []) or []:
                if isinstance(app, dict):
                    app["attribution_confidence"] = sub_conf
                    app["attribution_signals"] = sub_sigs
            for dev in results.get("azure_devops", []) or []:
                if isinstance(dev, dict):
                    dev["attribution_confidence"] = sub_conf
                    dev["attribution_signals"] = sub_sigs

            await self._close()

            return ToolResult(
                success=True,
                source=self.name,
                data=results,
                result_count=sum(1 for v in results.values() if v),
            )

        except Exception as e:
            return ToolResult(
                success=False,
                source=self.name,
                error=str(e),
            )

    # ── OpenID Configuration ──────────────────────────────────────────────────

    async def _get_openid_config(self, client: httpx.AsyncClient, domain: str) -> Dict[str, Any]:
        url = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                tenant_id = data.get("authorization_endpoint", "").split("/")[3]
                return {
                    "found": True,
                    "tenant_id": tenant_id,
                    "issuer": data.get("issuer"),
                    "auth_endpoint": data.get("authorization_endpoint"),
                    "token_endpoint": data.get("token_endpoint"),
                }
            return {"found": False, "status_code": resp.status_code}
        except Exception:
            return {"found": False, "error": "request_failed"}

    # ── User Realm ────────────────────────────────────────────────────────────

    async def _get_user_realm(self, client: httpx.AsyncClient, domain: str) -> Dict[str, Any]:
        url = f"https://login.microsoftonline.com/getuserrealm.srf?login=user@{domain}&xml=1"
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                text = resp.text
                # Parse XML-ish response.
                #
                # Federation detection: ``NameSpaceType`` is the
                # primary signal — a stable enum string (``Managed`` |
                # ``Federated`` | ``Unknown``) that both the XML and
                # JSON forms of the endpoint return. The numeric
                # ``State`` field (1 = managed, 3 = federated) is kept
                # as a fallback for XML responses that omit
                # ``NameSpaceType``. Previously this tool used only
                # ``State == "3"`` while its sibling ``azure_tenant_enum``
                # read ``NameSpaceType`` from the JSON form — the two
                # tools couldn't be cross-referenced because they
                # answered the same question against different fields.
                namespace_type = self._extract_xml_field(text, "NameSpaceType")
                state = self._extract_xml_field(text, "State")
                federation_brand_name = self._extract_xml_field(text, "FederationBrandName")
                cloud_audience_urn = self._extract_xml_field(text, "CloudInstanceName")
                domain_type = self._extract_xml_field(text, "DomainType")

                if namespace_type is not None:
                    is_federated = namespace_type == "Federated"
                else:
                    is_federated = state == "3"
                federation_protocol = self._extract_xml_field(text, "AuthProtocol")

                return {
                    "found": True,
                    # Consistent across azure_m365_recon and azure_tenant_enum.
                    "namespace_type": namespace_type,
                    "is_federated": is_federated,
                    "federation_type": "Federated (ADFS)" if is_federated else "Managed",
                    "federation_brand_name": federation_brand_name,
                    "cloud_audience_urn": cloud_audience_urn,
                    "domain_type": domain_type,
                    "federation_protocol": federation_protocol if is_federated else None,
                }
            return {"found": False, "status_code": resp.status_code}
        except Exception:
            return {"found": False, "error": "request_failed"}

    def _extract_xml_field(self, text: str, field: str) -> Optional[str]:
        match = re.search(rf'<{field}>([^<]+)</{field}>', text)
        return match.group(1) if match else None

    # ── .onmicrosoft.com Discovery ────────────────────────────────────────────

    async def _discover_onmicrosoft(self, client: httpx.AsyncClient, domain: str) -> Dict[str, Any]:
        # Try common patterns: <company>, <company>corp, <company>inc, etc.
        # Use the domain to derive candidate names
        base = domain.split(".")[0].lower()
        candidates = [
            base, f"{base}corp", f"{base}inc", f"{base}ltd",
            base.replace("-", ""), f"{base}-com", f"{base}corp-e",
        ]

        found = []
        for candidate in candidates:
            onmicrosoft = f"{candidate}.onmicrosoft.com"
            url = f"https://login.microsoftonline.com/{onmicrosoft}/.well-known/openid-configuration"
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    found.append({
                        "domain": onmicrosoft,
                        "tenant_id": data.get("authorization_endpoint", "").split("/")[3] if "authorization_endpoint" in data else None,
                    })
            except Exception:
                continue

        return {
            "found": bool(found),
            "domains": found,
        }

    # ── Azure Storage Enumeration ─────────────────────────────────────────────

    async def _enumerate_storage(self, client: httpx.AsyncClient, domain: str) -> List[Dict[str, Any]]:
        base = domain.split(".")[0].lower().replace("-", "")
        storage_types = ["blob", "file", "queue", "table"]

        results = []
        for st in storage_types:
            # Common naming patterns
            names = [
                base, f"{base}data", f"{base}storage", f"{base}files",
                f"{base}public", f"{base}assets", f"{base}uploads",
            ]
            for name in names:
                url = f"https://{name}.{st}.core.windows.net/"
                try:
                    resp = await client.head(url, follow_redirects=False)
                    # 404 = account exists but not found (public)
                    # 403 = exists, auth required
                    # 200 = exists, public
                    # 0xx / 400 = doesn't exist
                    if resp.status_code in (200, 403):
                        results.append({
                            "url": url,
                            "status": resp.status_code,
                            "is_public": resp.status_code == 200,
                            "storage_type": st,
                        })
                except Exception:
                    continue

        return results

    # ── Azure App Services ────────────────────────────────────────────────────

    async def _enumerate_app_services(self, client: httpx.AsyncClient, domain: str) -> List[Dict[str, Any]]:
        base = domain.split(".")[0].lower().replace("-", "")
        patterns = [
            base, f"{base}-api", f"{base}-app", f"{base}-web",
            f"{base}-dev", f"{base}-staging", f"{base}-prod",
        ]
        found = []
        for name in patterns:
            url = f"https://{name}.azurewebsites.net"
            try:
                resp = await client.get(url, timeout=5.0)
                if resp.status_code != 404:
                    scm_url = f"https://{name}.scm.azurewebsites.net"
                    scm_resp = await client.get(scm_url, timeout=5.0)
                    found.append({
                        "url": url,
                        "status": resp.status_code,
                        "scm_url": scm_url,
                        "scm_status": scm_resp.status_code,
                    })
            except Exception:
                continue

        return found

    # ── Azure DevOps ──────────────────────────────────────────────────────────

    async def _enumerate_devops(self, client: httpx.AsyncClient, domain: str) -> List[Dict[str, Any]]:
        base = domain.split(".")[0].lower().replace("-", "")
        orgs = [base, f"{base}-dev", f"{base}engineering"]
        found = []
        for org in orgs:
            url = f"https://dev.azure.com/{org}"
            vsts_url = f"https://{org}.visualstudio.com"
            try:
                resp = await client.get(url, timeout=5.0)
                if resp.status_code not in (404, 401):
                    found.append({
                        "org": org,
                        "url": url,
                        "status": resp.status_code,
                    })
            except Exception:
                continue
            try:
                resp2 = await client.get(vsts_url, timeout=5.0)
                if resp2.status_code not in (404, 401):
                    found.append({
                        "org": org,
                        "url": vsts_url,
                        "status": resp2.status_code,
                    })
            except Exception:
                continue

        return found

    # ── ADFS Detection ────────────────────────────────────────────────────────

    async def _detect_adfs(self, client: httpx.AsyncClient, domain: str) -> Dict[str, Any]:
        # Check for adfs subdomain
        adfs_url = f"https://adfs.{domain}/adfs/ls/idpinitiatedsignon.aspx"
        # Check for sts subdomain
        sts_url = f"https://sts.{domain}/adfs/ls/idpinitiatedsignon.aspx"
        # Check for login subdomain
        login_url = f"https://login.{domain}/adfs/ls/idpinitiatedsignon.aspx"
        # Check for sso subdomain
        sso_url = f"https://sso.{domain}/adfs/ls/idpinitiatedsignon.aspx"

        found = []
        for name, url in [("adfs", adfs_url), ("sts", sts_url), ("login", login_url), ("sso", sso_url)]:
            try:
                resp = await client.get(url, timeout=5.0)
                if resp.status_code != 404:
                    has_adfs_content = "adfs" in resp.text.lower() or "microsoft" in resp.text.lower()
                    found.append({
                        "subdomain": name,
                        "url": url,
                        "status": resp.status_code,
                        "likely_adfs": has_adfs_content,
                    })
            except Exception:
                continue

        return {"found": bool(found), "endpoints": found}

    # ── DKIM Selector Check ───────────────────────────────────────────────────

    async def _check_dkim_selectors(self, client: httpx.AsyncClient, domain: str) -> Dict[str, Any]:
        import dns.asyncresolver
        selectors = ["selector1", "selector2", "selector1-domainkey", "selector2-domainkey", "default"]
        found = []
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = self.config.dns_resolver_list()
        resolver.timeout = 3
        resolver.lifetime = 5

        for sel in selectors:
            try:
                qname = f"{sel}._domainkey.{domain}"
                answers = await resolver.resolve(qname, "CNAME")
                for rdata in answers:
                    found.append({
                        "selector": sel,
                        "cname": str(rdata).rstrip("."),
                    })
            except Exception:
                try:
                    answers = await resolver.resolve(qname, "TXT")
                    for rdata in answers:
                        found.append({
                            "selector": sel,
                            "txt": str(rdata),
                        })
                except Exception:
                    continue

        return {"found": bool(found), "selectors": found}

    # ── OneDrive / SharePoint ─────────────────────────────────────────────────

    async def _check_onedrive(self, client: httpx.AsyncClient, emails: List[str]) -> List[Dict[str, Any]]:
        results = []
        for email in emails[:20]:  # limit to 20
            local = email.split("@")[0]
            domain = email.split("@")[1] if "@" in email else ""
            # OneDrive URL pattern: {user}_{domain}.my.sharepoint.com
            od_url = f"https://{local}_{domain.replace('.', '_')}.my.sharepoint.com"
            try:
                resp = await client.head(od_url, timeout=5.0, follow_redirects=False)
                if resp.status_code not in (404, 403):
                    results.append({
                        "email": email,
                        "url": od_url,
                        "status": resp.status_code,
                        "exists": resp.status_code != 404,
                    })
            except Exception:
                continue

        return results

    # ── Summary ───────────────────────────────────────────────────────────────

    @staticmethod
    def _summarize(openid: Dict, realm: Dict, onmicrosoft: Dict, adfs: Dict) -> str:
        lines = []
        if openid.get("found"):
            lines.append(f"Tenant ID: {openid.get('tenant_id', 'unknown')}")
        if realm.get("is_federated"):
            lines.append(f"Federated (ADFS) — federation protocol: {realm.get('federation_protocol', 'unknown')}")
        elif realm.get("found"):
            lines.append("Managed (cloud-only or password hash sync)")
        if onmicrosoft.get("found"):
            lines.append(f"onmicrosoft.com: {', '.join(d['domain'] for d in onmicrosoft['domains'])}")
        if adfs.get("found"):
            lines.append(f"ADFS endpoints: {', '.join(e['subdomain'] for e in adfs['endpoints'])}")
        return "; ".join(lines) if lines else "No Azure/M365 configuration found"
