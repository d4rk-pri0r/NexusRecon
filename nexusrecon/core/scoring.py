"""
Threat-scoring engine — correlates all gathered intel into a ranked "threads to pull" list.

Score formula per finding:
  base_score = cvss * epss_pct * kev_boost * exploit_boost * asset_exposure_boost
  breach_addend = 0.1 per breached employee (capped at 0.3)
  bucket_addend = 0.2 per public cloud bucket
  secret_addend = 0.3 per leaked credential set

Results are normalised to [0, 1] and ranked descending.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ── Dataclass for a ranked finding ────────────────────────────────────────────

@dataclass
class RankedFinding:
    title: str
    category: str               # "cve", "bucket", "breach", "secret", "pretext", "exposure"
    score: float                # 0.0 – 1.0 normalised
    severity: str               # critical / high / medium / low / info
    confidence: float
    description: str
    affected_assets: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    # CVE-specific
    cve_id: str | None = None
    cvss: float | None = None
    epss: float | None = None
    in_kev: bool = False
    has_exploit: bool = False
    has_metasploit: bool = False
    has_nuclei_template: bool = False
    # Breach/leak-specific
    breach_sources: list[str] = field(default_factory=list)
    # Cloud-specific
    cloud_provider: str | None = None
    # Evidence
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "category": self.category,
            "score": round(self.score, 4),
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "description": self.description,
            "affected_assets": self.affected_assets[:10],
            "next_steps": self.next_steps,
            "cve_id": self.cve_id,
            "cvss": self.cvss,
            "epss": self.epss,
            "in_kev": self.in_kev,
            "has_exploit": self.has_exploit,
            "has_metasploit": self.has_metasploit,
            "has_nuclei_template": self.has_nuclei_template,
            "breach_sources": self.breach_sources,
            "cloud_provider": self.cloud_provider,
            "sources": self.sources,
        }


# ── Main scoring function ──────────────────────────────────────────────────────

def score_findings(state: dict[str, Any]) -> list[RankedFinding]:
    """
    Consume campaign state and return a ranked list of RankedFinding objects.
    Called from Phase 8 — reads vuln_intel, cloud_intel, code_intel, email_intel.
    """
    candidates: list[RankedFinding] = []

    candidates.extend(_score_cves(state))
    candidates.extend(_score_cloud_buckets(state))
    candidates.extend(_score_secrets(state))
    candidates.extend(_score_breaches(state))
    candidates.extend(_score_nuclei_findings(state))
    candidates.extend(_score_open_exposures(state))
    candidates.extend(_score_agent_findings(state))

    # Normalise scores to [0,1]
    if candidates:
        max_score = max(c.score for c in candidates) or 1.0
        for c in candidates:
            c.score = min(1.0, c.score / max_score)

    candidates.sort(key=lambda x: (-x.score, x.severity))
    return candidates


# ── CVE scoring ────────────────────────────────────────────────────────────────

def _score_cves(state: dict[str, Any]) -> list[RankedFinding]:
    vuln_intel = state.get("vuln_intel", {})
    results: list[RankedFinding] = []

    # KEV CVE IDs (all exploited-in-wild by definition)
    kev_ids: set[str] = set()
    kev_data = vuln_intel.get("kev", {})
    for entry in kev_data.get("vulnerabilities", kev_data.get("entries", [])):
        cve = entry.get("cveID") or entry.get("cve")
        if cve:
            kev_ids.add(cve.upper())

    # Enriched CVE data from Phase 7
    enriched_cves: dict[str, Any] = vuln_intel.get("enriched_cves", {})

    for cve_id, data in enriched_cves.items():
        cvss = float(data.get("cvss", 0.0) or 0.0)
        epss = float(data.get("epss", 0.0) or 0.0)
        in_kev = cve_id.upper() in kev_ids or bool(data.get("in_kev"))
        has_exploit = bool(data.get("has_exploit"))
        has_msf = bool(data.get("has_metasploit"))
        has_template = bool(data.get("has_nuclei_template"))
        tech = data.get("tech", "")
        assets = data.get("affected_assets", [])

        # Base score: CVSS scaled to 0–1, multiplied by EPSS probability
        score = (cvss / 10.0) * max(epss, 0.05)

        # Multipliers
        if in_kev:
            score *= 3.0
        if has_msf:
            score *= 2.5
        elif has_exploit:
            score *= 2.0
        if has_template:
            score *= 1.3

        severity = _cvss_to_severity(cvss)
        next_steps = _cve_next_steps(cve_id, has_msf, has_template, tech)

        results.append(RankedFinding(
            title=f"{cve_id} in {tech}" if tech else cve_id,
            category="cve",
            score=score,
            severity=severity,
            confidence=0.9 if in_kev else 0.75,
            description=data.get("description", "")[:300],
            affected_assets=assets,
            next_steps=next_steps,
            cve_id=cve_id,
            cvss=cvss,
            epss=epss,
            in_kev=in_kev,
            has_exploit=has_exploit,
            has_metasploit=has_msf,
            has_nuclei_template=has_template,
            sources=data.get("sources", []),
        ))

    return results


def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def _cve_next_steps(cve_id: str, has_msf: bool, has_template: bool, tech: str) -> list[str]:
    steps = []
    if has_msf:
        steps.append(f"Load Metasploit: search {cve_id} in msfconsole, configure and run against target")
    elif has_template:
        steps.append(f"Run nuclei: nuclei -u <target> -id {cve_id.lower()}")
    steps.append(f"Verify {tech or 'service'} version on target before exploitation")
    steps.append(f"Check ExploitDB: https://www.exploit-db.com/search?cve={cve_id.replace('CVE-', '')}")
    return steps


# ── Cloud bucket scoring ───────────────────────────────────────────────────────

def _score_cloud_buckets(state: dict[str, Any]) -> list[RankedFinding]:
    results: list[RankedFinding] = []
    cloud_intel = state.get("cloud_intel", {})

    for key, data in cloud_intel.items():
        if not isinstance(data, dict):
            continue
        buckets = data.get("public_buckets", data.get("buckets", []))
        for b in buckets:
            if not isinstance(b, dict):
                continue
            is_public = b.get("public") or b.get("access") == "public"
            if not is_public:
                continue
            provider = b.get("provider", "cloud")
            name = b.get("name", b.get("bucket", "unknown"))
            url = b.get("url", "")

            results.append(RankedFinding(
                title=f"Public {provider.upper()} bucket: {name}",
                category="bucket",
                score=0.85,
                severity="high",
                confidence=0.95,
                description=f"Publicly accessible {provider} storage bucket at {url or name}",
                affected_assets=[url or name],
                next_steps=[
                    f"Enumerate contents: aws s3 ls s3://{name} --no-sign-request" if "s3" in provider.lower() else f"Browse {url or name}",
                    "Download and review all files for credentials, PII, configuration",
                    "Document evidence before reporting — buckets may be taken offline",
                ],
                cloud_provider=provider,
                sources=["bucket_enum"],
            ))

    return results


# ── Secret / credential scoring ───────────────────────────────────────────────

def _score_secrets(state: dict[str, Any]) -> list[RankedFinding]:
    results: list[RankedFinding] = []
    code_intel = state.get("code_intel", {})

    for key, data in code_intel.items():
        if not isinstance(data, dict):
            continue
        leaks = data.get("leaks", data.get("findings", []))
        if not leaks:
            continue

        # Group by type for a single finding per source
        types: dict[str, int] = {}
        for leak in leaks:
            t = leak.get("type", leak.get("rule", "secret")) if isinstance(leak, dict) else "secret"
            types[t] = types.get(t, 0) + 1

        score = min(1.0, 0.6 + len(leaks) * 0.05)
        type_summary = ", ".join(f"{t} ({n})" for t, n in sorted(types.items(), key=lambda x: -x[1])[:5])

        results.append(RankedFinding(
            title=f"Leaked credentials in {key}",
            category="secret",
            score=score,
            severity="critical" if any(k in type_summary.lower() for k in ["aws", "password", "private_key"]) else "high",
            confidence=0.85,
            description=f"{len(leaks)} secrets found: {type_summary}",
            affected_assets=[key],
            next_steps=[
                "Immediately rotate all exposed credentials",
                "Check CloudTrail / audit logs for unauthorized use of exposed keys",
                "Remove secrets from repository history (git filter-repo)",
                "File incident report if customer data may be affected",
            ],
            sources=[key.split("/")[0]],
        ))

    return results


# ── Breach / infostealer scoring ──────────────────────────────────────────────

def _score_breaches(state: dict[str, Any]) -> list[RankedFinding]:
    results: list[RankedFinding] = []
    email_intel = state.get("email_intel", {})
    emails = email_intel.get("emails", {})

    # Collect all breach hits
    breached: dict[str, list[str]] = {}  # email → [source, ...]
    infostealer: dict[str, list[str]] = {}

    for em, info in emails.items():
        if not isinstance(info, dict):
            continue
        if info.get("breaches"):
            breached[em] = [b.get("name", str(b)) for b in info["breaches"] if isinstance(b, dict)]
        if info.get("stealer_logs") or info.get("infostealer_hits"):
            sources = info.get("stealer_logs", info.get("infostealer_hits", []))
            infostealer[em] = sources if isinstance(sources, list) else [str(sources)]

    # Also check identity_intel / breach_intel
    breach_intel = state.get("breach_intel", {})
    for em, data in breach_intel.items():
        if isinstance(data, dict):
            hits = data.get("breaches", [])
            if hits:
                breached.setdefault(em, []).extend(hits if isinstance(hits, list) else [str(hits)])

    if infostealer:
        affected = list(infostealer.keys())[:20]
        results.append(RankedFinding(
            title=f"Infostealer logs: {len(infostealer)} employee credentials for sale",
            category="breach",
            score=0.95,
            severity="critical",
            confidence=0.9,
            description=(
                f"{len(infostealer)} employee accounts appear in infostealer log markets. "
                "Active session cookies and plaintext passwords are likely available."
            ),
            affected_assets=affected,
            next_steps=[
                "Force password reset + MFA enrollment for all affected accounts immediately",
                "Invalidate all active sessions for affected users",
                "Check for account takeover indicators in SSO/IdP logs",
                "Run targeted phishing simulation to test susceptibility",
            ],
            breach_sources=list({src for srcs in infostealer.values() for src in srcs}),
            sources=["hudsonrock", "leakcheck"],
        ))

    if breached:
        exec_keywords = ["ceo", "cfo", "cto", "ciso", "director", "vp", "founder"]
        exec_breached = [em for em in breached if any(kw in str(emails.get(em, {}).get("position", "")).lower() for kw in exec_keywords)]
        score = min(0.9, 0.5 + len(breached) * 0.02 + len(exec_breached) * 0.1)

        next_steps = [
            f"Cross-reference {len(breached)} breached emails with active SSO accounts",
            "Prioritize password spray targets using credential stuffing wordlists from breach data",
        ]
        if exec_breached:
            next_steps.insert(0, f"HIGH VALUE: {len(exec_breached)} executive accounts in breach data — attempt credential reuse")

        results.append(RankedFinding(
            title=f"Employee credentials in breach data ({len(breached)} accounts)",
            category="breach",
            score=score,
            severity="high" if not exec_breached else "critical",
            confidence=0.8,
            description=(
                f"{len(breached)} employee email addresses found in breach databases. "
                f"{len(exec_breached)} are executive/senior accounts."
            ),
            affected_assets=list(breached.keys())[:20],
            next_steps=next_steps,
            breach_sources=list({src for srcs in breached.values() for src in srcs}),
            sources=["haveibeenpwned", "hudsonrock", "leakcheck"],
        ))

    return results


# ── Nuclei findings scoring ────────────────────────────────────────────────────

def _score_nuclei_findings(state: dict[str, Any]) -> list[RankedFinding]:
    results: list[RankedFinding] = []
    vuln_intel = state.get("vuln_intel", {})

    nuclei_data = vuln_intel.get("nuclei_scan", {})
    findings = nuclei_data.get("findings", [])

    sev_score = {"critical": 0.95, "high": 0.75, "medium": 0.5}

    for f in findings:
        sev = f.get("severity", "medium")
        score = sev_score.get(sev, 0.4)
        cve_ids = f.get("cve_ids", [])
        template_id = f.get("template_id", "")
        cvss = float(f.get("cvss_score") or 0.0)

        if cvss >= 9.0:
            score = max(score, 0.9)

        next_steps = [f"Confirmed by nuclei template `{template_id}` — validate manually"]
        if cve_ids:
            next_steps.append(f"CVE reference: {', '.join(cve_ids)}")
        next_steps.append(f"Matched at: {f.get('matched_at', 'unknown')}")

        results.append(RankedFinding(
            title=f.get("name", template_id),
            category="cve" if cve_ids else "exposure",
            score=score,
            severity=sev,
            confidence=0.95,
            description=f.get("description", "")[:300],
            affected_assets=[f.get("matched_at", "")] if f.get("matched_at") else [],
            next_steps=next_steps,
            cve_id=cve_ids[0] if cve_ids else None,
            cvss=cvss if cvss else None,
            sources=["nuclei"],
        ))

    return results


# ── Open exposure scoring ─────────────────────────────────────────────────────

def _score_open_exposures(state: dict[str, Any]) -> list[RankedFinding]:
    """Score open admin panels, git configs, .env files discovered in Phase 6."""
    results: list[RankedFinding] = []
    infra_intel = state.get("infra_intel", {})

    high_value_paths = {
        "/.git/config": ("Git config exposed", "critical", 0.9),
        "/.env": (".env file exposed", "critical", 0.95),
        "/wp-admin": ("WordPress admin panel", "high", 0.8),
        "/administrator": ("Joomla admin panel", "high", 0.8),
        "/admin": ("Admin panel", "medium", 0.7),
        "/phpmyadmin": ("phpMyAdmin exposed", "critical", 0.9),
        "/actuator/health": ("Spring Boot actuator exposed", "medium", 0.8),
        "/jenkins": ("Jenkins exposed", "high", 0.85),
        "/console": ("Admin console exposed", "high", 0.8),
        "/swagger.json": ("API docs exposed (Swagger)", "medium", 0.75),
        "/openapi.json": ("API docs exposed (OpenAPI)", "medium", 0.75),
        "/api-docs": ("API docs exposed", "medium", 0.7),
        "/Dockerfile": ("Dockerfile exposed", "medium", 0.65),
    }

    for sub, data in infra_intel.items():
        if not isinstance(data, dict):
            continue
        paths = data.get("discovered_paths", [])
        for path_info in paths:
            if not isinstance(path_info, dict):
                continue
            path = path_info.get("path", "")
            status = path_info.get("status", 0)
            if status in (200, 301, 302) and path in high_value_paths:
                title, severity, confidence = high_value_paths[path]
                url = f"https://{sub}{path}"

                next_steps = []
                if path == "/.git/config":
                    next_steps = [
                        f"Dump full git repo: git-dumper {url.replace('/.git/config', '')} ./dumped_repo",
                        "Search dumped repo for credentials, API keys, internal hostnames",
                    ]
                elif path == "/.env":
                    next_steps = [
                        f"Fetch file: curl {url}",
                        "Extract database credentials, API keys, secret keys from file",
                    ]
                elif "admin" in path.lower() or path in ("/console", "/jenkins"):
                    next_steps = [
                        f"Attempt default credentials against {url}",
                        "Check for CVEs specific to detected version",
                        "Try credential stuffing with breach data if available",
                    ]
                else:
                    next_steps = [f"Review {url} for sensitive information disclosure"]

                results.append(RankedFinding(
                    title=f"{title} — {sub}",
                    category="exposure",
                    score=confidence * _severity_to_float(severity),
                    severity=severity,
                    confidence=confidence,
                    description=f"{title} at {url} (HTTP {status})",
                    affected_assets=[url],
                    next_steps=next_steps,
                    sources=["phase6_content_discovery"],
                ))

    return results


def _severity_to_float(severity: str) -> float:
    return {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4, "info": 0.2}.get(severity, 0.5)


# ── Agent-structured finding scoring ─────────────────────────────────────────

def _score_agent_findings(state: dict[str, Any]) -> list[RankedFinding]:
    """
    Score structured findings emitted by agents via the FINDINGS_JSON protocol.

    Agents in phases 1–7 append findings to state["findings"] with at least
    ``severity``, ``title``, ``description``, ``source``, and ``confidence`` keys.
    This function lifts those into RankedFinding objects so they can appear in
    ranked_threads even when no tool-level signals (CVEs, buckets, nuclei) were found.
    """
    results: list[RankedFinding] = []
    sev_base: dict[str, float] = {
        "critical": 0.85,
        "high": 0.65,
        "medium": 0.45,
        "low": 0.25,
        "info": 0.10,
    }

    for f in state.get("findings", []):
        if not isinstance(f, dict):
            continue
        severity = f.get("severity", "info")
        confidence = float(f.get("confidence", 0.5))
        score = sev_base.get(severity, 0.10) * confidence

        results.append(RankedFinding(
            title=f.get("title", "Agent finding"),
            category=f.get("category", "reconnaissance"),
            score=score,
            severity=severity,
            confidence=confidence,
            description=f.get("description", ""),
            sources=[f.get("source", "agent")],
        ))

    return results
