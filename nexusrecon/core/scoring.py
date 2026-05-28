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

import re
from dataclasses import dataclass, field
from typing import Any

#: Confidence below which a finding is treated as speculation, not attack
#: surface (Wave F-B3). The 2026-05-27 run minted six conf-0.2 "[POSSIBLE]"
#: cloud entries from probes that returned nothing; those belong in coverage,
#: not the ranked threads.
COVERAGE_CONFIDENCE_FLOOR = 0.30

#: Severity ordering for dedup merges (higher wins).
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

#: Severity -> impact (1-10), computed once here so every report renders the
#: same number (Wave F-B6). Previously attack_surface.md left Likelihood/Impact
#: blank while the LLM exec-summary invented its own integers.
_SEVERITY_IMPACT = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}


def _finding_get(finding: Any, key: str, default: Any = None) -> Any:
    """Read a field from either a RankedFinding or a plain finding dict."""
    if isinstance(finding, dict):
        return finding.get(key, default)
    return getattr(finding, key, default)


def impact_score(finding: Any) -> int:
    """Deterministic impact (1-10) from severity. Single source of truth."""
    return _SEVERITY_IMPACT.get(_finding_get(finding, "severity", "info"), 1)


def likelihood_score(finding: Any) -> int:
    """Deterministic likelihood (1-10): confidence scaled, boosted by
    weaponisation signals (KEV / Metasploit / public exploit / nuclei
    template). Computed once so reports agree."""
    conf = float(_finding_get(finding, "confidence", 0.5) or 0.0)
    base = max(1, round(conf * 8))
    if _finding_get(finding, "in_kev") or _finding_get(finding, "has_metasploit"):
        base += 2
    elif _finding_get(finding, "has_exploit") or _finding_get(finding, "has_nuclei_template"):
        base += 1
    return max(1, min(10, base))


def likelihood_impact(finding: Any) -> tuple[int, int]:
    """Return ``(likelihood, impact)``, both 1-10. Use this everywhere a
    report needs the numbers, instead of inventing them per-renderer."""
    return likelihood_score(finding), impact_score(finding)

#: Substrings (lowercased title) that mark an absence-of-evidence note rather
#: than attack surface (Wave F-B1). Kept tight so genuine informational
#: weaknesses (e.g. "DNSSEC Not Configured") are NOT swept into coverage.
_NON_FINDING_MARKERS = (
    "no mx record", "no code", "no secret", "no sensitive", "no confirmed",
    "no fingerprinted", "no malicious", "no data leak", "no leak detected",
    "clean reputation", "queried - no", "queried — no", "none detected",
    "no significant findings", "no sensitive data",
)

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
            # Deterministic risk dimensions, computed once (F-B6).
            "likelihood": likelihood_score(self),
            "impact": impact_score(self),
        }


# ── Main scoring function ──────────────────────────────────────────────────────

def unavailable_tools_from_preflight(preflight: dict[str, Any] | None) -> dict[str, str]:
    """Map tool name -> short reason for tools that cannot run this campaign,
    read from the F-A3 preflight report (Wave F-B7).

    Covers the missing-binary, missing-key, and policy-skipped buckets ── the
    "this can't run" set. Tools that ran but were unproductive are not here;
    they need run-health (post-run) and are out of scope for recommend-time.
    """
    if not isinstance(preflight, dict):
        return {}
    buckets = preflight.get("buckets") or {}
    reasons = {
        "missing_binary": "not installed",
        "missing_key": "missing an API key",
        "policy": "disabled by engagement policy",
        "over_tier": "above the engagement tier",
    }
    out: dict[str, str] = {}
    for bucket, label in reasons.items():
        for tool_name in (buckets.get(bucket) or {}):
            out[tool_name.lower()] = label
    return out


def annotate_next_steps(steps: list[str], unavailable: dict[str, str]) -> list[str]:
    """Flag any next-step that recommends a tool which can't run this campaign
    (Wave F-B7), so the report stops telling the operator to "run theHarvester"
    when it isn't installed or "query DeHashed" when it's policy-disabled.

    The step is kept (the underlying intent may still be valid by hand) but
    annotated, never silently dropped.
    """
    if not unavailable or not steps:
        return steps
    out: list[str] = []
    for step in steps:
        low = step.lower()
        hit = next(
            (t for t in unavailable if re.search(rf"\b{re.escape(t)}\b", low)),
            None,
        )
        if hit:
            out.append(f"{step}  [unavailable this run: {hit} is {unavailable[hit]}]")
        else:
            out.append(step)
    return out


def _collect_candidates(state: dict[str, Any]) -> list[RankedFinding]:
    candidates: list[RankedFinding] = []
    candidates.extend(_score_cves(state))
    candidates.extend(_score_cloud_buckets(state))
    candidates.extend(_score_secrets(state))
    candidates.extend(_score_breaches(state))
    candidates.extend(_score_nuclei_findings(state))
    candidates.extend(_score_open_exposures(state))
    candidates.extend(_score_agent_findings(state))
    return candidates


def score_findings(state: dict[str, Any]) -> list[RankedFinding]:
    """
    Consume campaign state and return a ranked list of RankedFinding objects.
    Called from Phase 8 — reads vuln_intel, cloud_intel, code_intel, email_intel.

    Findings are deduplicated (Wave F-B2) and absence-of-evidence /
    below-confidence-floor items are split off into coverage (F-B1/F-B3), so
    the returned list is the real, ranked attack surface. Use
    :func:`score_findings_with_coverage` when the coverage list is also needed.
    """
    kept, _coverage = score_findings_with_coverage(state)
    return kept


def score_findings_with_coverage(
    state: dict[str, Any],
) -> tuple[list[RankedFinding], list[RankedFinding]]:
    """Score, dedup, and partition findings into (ranked, coverage).

    - ``ranked``: real attack surface, normalised to [0,1] and sorted.
    - ``coverage``: absence-of-evidence notes (F-B1) and below-floor /
      ``[POSSIBLE]`` speculation (F-B3), kept for the "what we checked"
      appendix instead of competing for the operator's attention.

    Dedup (F-B2) runs first so a fact emitted three times across phases
    collapses to one entry carrying the union of sources and the highest
    confidence/severity seen.
    """
    candidates = _dedup_ranked(_collect_candidates(state))

    kept: list[RankedFinding] = []
    coverage: list[RankedFinding] = []
    for c in candidates:
        if _is_below_floor(c) or _is_non_finding(c):
            coverage.append(c)
        else:
            kept.append(c)

    if kept:
        max_score = max(c.score for c in kept) or 1.0
        for c in kept:
            c.score = min(1.0, c.score / max_score)

    kept.sort(key=lambda x: (-x.score, x.severity))
    coverage.sort(key=lambda x: (-x.score, x.severity))
    return kept, coverage


# ── Dedup + classification (Wave F-B1/B2/B3) ──────────────────────────────────

def _is_below_floor(rf: RankedFinding) -> bool:
    """F-B3: speculation ── explicitly ``[POSSIBLE]`` or below the floor."""
    if (rf.title or "").strip().lower().startswith("[possible]"):
        return True
    return rf.confidence < COVERAGE_CONFIDENCE_FLOOR


def _is_non_finding(rf: RankedFinding) -> bool:
    """F-B1: absence-of-evidence note ("we looked and found nothing"),
    not attack surface. Restricted to info severity so it never demotes a
    real (if low) weakness."""
    if rf.severity != "info":
        return False
    cat = (rf.category or "").replace("_", " ").lower()
    if "gap" in cat:  # "reconnaissance gap"
        return True
    title = (rf.title or "").strip().lower()
    if title.startswith("limited "):  # "Limited Email Intelligence", "...Footprint"
        return True
    return any(m in title for m in _NON_FINDING_MARKERS)


def _primary_asset(rf: RankedFinding) -> str:
    """First real affected asset (skipping ``dynamic/`` / ``graph_summary``
    pseudo-assets), lowercased. Used in the dedup key so two distinct
    subdomains never collapse together."""
    for a in rf.affected_assets or []:
        al = str(a).strip().lower()
        if not al or al.startswith("dynamic/") or al.startswith("graph_summary"):
            continue
        return al
    return ""


def _canonical_key(rf: RankedFinding) -> tuple[str, str, str]:
    """Merge key: normalised title stem + category + primary asset.

    The title stem drops a ``[POSSIBLE]`` prefix and any trailing
    `` - <qualifier>`` so the three reworded SPF/DMARC findings collapse,
    while the primary asset in the key keeps distinct subdomains apart.
    """
    title = (rf.title or "").strip().lower()
    if title.startswith("[possible]"):
        title = title[len("[possible]"):].strip()
    for sep in (" - ", " — ", " – "):
        idx = title.find(sep)
        if idx >= 12:  # only strip a suffix when a substantial stem remains
            title = title[:idx]
            break
    title = re.sub(r"[^a-z0-9]+", " ", title).strip()
    cat = re.sub(r"[^a-z0-9]+", " ", (rf.category or "").lower()).strip()
    return (title, cat, _primary_asset(rf))


def _union_lists(lists: list[list[str]]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for lst in lists:
        for item in lst or []:
            if item not in seen:
                seen.add(item)
                out.append(item)
    return out


def _dedup_ranked(findings: list[RankedFinding]) -> list[RankedFinding]:
    """F-B2: collapse findings sharing a canonical key into one, keeping the
    highest-confidence representative and unioning sources / next-steps /
    assets. Preserves first-seen order."""
    groups: dict[tuple[str, str, str], list[RankedFinding]] = {}
    order: list[tuple[str, str, str]] = []
    for rf in findings:
        k = _canonical_key(rf)
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(rf)

    out: list[RankedFinding] = []
    for k in order:
        grp = groups[k]
        if len(grp) == 1:
            out.append(grp[0])
            continue
        rep = max(grp, key=lambda r: (r.confidence, r.score))
        rep.score = max(r.score for r in grp)
        rep.confidence = max(r.confidence for r in grp)
        rep.severity = max(
            (r.severity for r in grp),
            key=lambda s: _SEVERITY_RANK.get(s, 0),
        )
        rep.sources = _union_lists([r.sources for r in grp])
        rep.next_steps = _union_lists([r.next_steps for r in grp])
        rep.affected_assets = _union_lists([r.affected_assets for r in grp])
        out.append(rep)
    return out


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
            # Carry affected_assets + next_steps through (previously dropped):
            # the dedup key needs the asset to keep distinct subdomains apart,
            # and the report needs the steps.
            affected_assets=f.get("affected_assets", []) or [],
            next_steps=f.get("next_steps", []) or [],
            sources=[f.get("source", "agent")],
        ))

    return results
