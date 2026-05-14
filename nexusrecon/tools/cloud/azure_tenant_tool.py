"""Azure tenant enumeration — tenant ID, federation, and OAuth discovery."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx

from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool


@register_tool
class AzureTenantTool(OSINTTool):
    name = "azure_tenant_enum"
    tier = Tier.T0
    category = Category.CLOUD_AZURE
    requires_keys = []
    description = (
        "Azure tenant enumeration — discovers tenant ID, federation status, OAuth endpoints, "
        "and *.onmicrosoft.com / *.sharepoint.com domain presence"
    )
    target_types = ["domain"]

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        data: Dict[str, Any] = {"domain": target}

        try:
            async with httpx.AsyncClient(
                timeout=15.0,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"},
            ) as client:
                # 1. OpenID configuration → tenant ID
                oidc_resp = await client.get(
                    f"https://login.microsoftonline.com/{target}/.well-known/openid-configuration",
                    headers={"Accept": "application/json"},
                )
                if oidc_resp.status_code == 200:
                    oidc = oidc_resp.json()
                    issuer = oidc.get("issuer", "")
                    # issuer format: https://sts.windows.net/{tenant_id}/
                    tenant_id = issuer.split("/")[3] if issuer.count("/") >= 3 else None
                    data.update({
                        "tenant_id": tenant_id,
                        "issuer": issuer,
                        "token_endpoint": oidc.get("token_endpoint"),
                        "authorization_endpoint": oidc.get("authorization_endpoint"),
                        "userinfo_endpoint": oidc.get("userinfo_endpoint"),
                        "jwks_uri": oidc.get("jwks_uri"),
                        "tenant_region": oidc.get("tenant_region_scope"),
                    })

                # 2. User realm check → federation vs managed
                realm_resp = await client.get(
                    "https://login.microsoftonline.com/getuserrealm.srf",
                    params={"login": f"probe@{target}", "json": "1"},
                )
                if realm_resp.status_code == 200:
                    realm = realm_resp.json()
                    data.update({
                        "namespace_type": realm.get("NameSpaceType"),  # Managed | Federated
                        "is_federated": realm.get("NameSpaceType") == "Federated",
                        "federation_brand": realm.get("FederationBrandName"),
                        "cloud_instance": realm.get("CloudInstanceName"),
                        "desktop_sso_enabled": realm.get("DesktopSsoEnabled"),
                        "adfs_auth_url": realm.get("AuthURL"),
                    })

                # 3. Check for *.onmicrosoft.com tenant name
                stem = target.split(".")[0]
                onmicrosoft_domains: List[str] = []
                for candidate in [stem, stem.replace("-", ""), stem.replace(".", "")]:
                    ms_resp = await client.head(f"https://{candidate}.sharepoint.com")
                    if ms_resp.status_code in (200, 302, 403):
                        onmicrosoft_domains.append(f"{candidate}.onmicrosoft.com")
                        data["sharepoint_url"] = f"https://{candidate}.sharepoint.com"
                        break

                data["onmicrosoft_domains"] = onmicrosoft_domains

                # 4. Azure AD tenant lookup via common endpoint
                common_resp = await client.get(
                    "https://login.microsoftonline.com/common/discovery/instance",
                    params={"authorization_url": f"https://login.microsoftonline.com/{target}/oauth2/authorize", "api-version": "1.1"},
                    headers={"Accept": "application/json"},
                )
                if common_resp.status_code == 200:
                    discovery = common_resp.json()
                    data["tenant_discovery_endpoint"] = discovery.get("tenant_discovery_endpoint")

        except Exception as exc:
            return ToolResult(success=False, source=self.name, error=str(exc))

        # B26: tag attribution confidence — 1.0 only if tenant_id was resolved via openid-config
        openid_verified = bool(data.get("tenant_id"))
        data["attribution_confidence"] = 1.0 if openid_verified else 0.2
        data["attribution_signals"] = (
            ["openid_config_verified"]
            if openid_verified
            else ["no_openid_config", "stem_match_only"]
        )

        found = bool(data.get("tenant_id"))
        return ToolResult(success=True, source=self.name, data=data, result_count=1 if found else 0)
