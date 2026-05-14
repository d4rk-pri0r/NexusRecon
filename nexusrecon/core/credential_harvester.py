"""Credential harvester — walks all intel sources and extracts concrete credentials."""
from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx
import structlog

log = structlog.get_logger(__name__)

CRED_PATTERNS: List[tuple[str, str]] = [
    ("aws_access_key", r"(AKIA[0-9A-Z]{16})"),
    ("aws_secret_key", r"(?i)aws.{0,20}?(?:secret|key).{0,20}?['\"]([0-9a-zA-Z/+]{40})['\"]"),
    ("github_token", r"(gh[pousr]_[A-Za-z0-9]{36,})"),
    ("github_oauth", r"(gho_[A-Za-z0-9]{36,})"),
    ("slack_token", r"(xox[baprs]-[A-Za-z0-9-]{10,})"),
    ("stripe_secret", r"(sk_live_[A-Za-z0-9]{24,})"),
    ("private_key", r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"),
    ("jwt", r"(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"),
    ("database_url", r"((?:postgres|mysql|mongodb)(?:\+\w+)?://[^:]+:[^@]+@[^/\s'\"]+)"),
    ("generic_password", r"(?i)password['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
    ("generic_api_key", r"(?i)(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]"),
]

_ENV_LINE_RE = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.+)$", re.MULTILINE)
_GIT_CRED_URL_RE = re.compile(r"https?://([^:]+):([^@]+)@")


def _redact(value: str) -> str:
    if len(value) <= 6:
        return "***"
    return value[:4] + "***" + value[-2:]


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _context_excerpt(text: str, match_start: int, window: int = 80) -> str:
    start = max(0, match_start - window)
    end = min(len(text), match_start + window)
    return text[start:end].replace("\n", " ")


def _classify_env_key(key: str, value: str) -> Optional[str]:
    key_upper = key.upper()
    if "AWS" in key_upper and ("KEY" in key_upper or "SECRET" in key_upper):
        return "aws_secret_key" if "SECRET" in key_upper else "aws_access_key"
    if "GITHUB" in key_upper or "GH_TOKEN" in key_upper:
        return "github_token"
    if "DATABASE_URL" in key_upper or "DB_URL" in key_upper:
        return "database_url"
    if "SECRET" in key_upper and len(value) >= 20:
        return "generic_api_key"
    if "API_KEY" in key_upper or "APIKEY" in key_upper:
        return "generic_api_key"
    if "PASSWORD" in key_upper or "PASSWD" in key_upper:
        return "generic_password"
    if "TOKEN" in key_upper:
        return "generic_api_key"
    return None


@dataclass
class HarvestedCredential:
    cred_type: str
    value_redacted: str
    value_hash: str
    source_url: str
    source_type: str
    context: str
    confidence: float
    validated: bool = False
    validation_method: Optional[str] = None
    validation_metadata: Dict[str, Any] = field(default_factory=dict)
    next_steps: List[str] = field(default_factory=list)


def _make_cred(
    cred_type: str,
    raw_value: str,
    source_url: str,
    source_type: str,
    context: str,
    confidence: float,
    next_steps: Optional[List[str]] = None,
) -> HarvestedCredential:
    return HarvestedCredential(
        cred_type=cred_type,
        value_redacted=_redact(raw_value),
        value_hash=_sha256(raw_value),
        source_url=source_url,
        source_type=source_type,
        context=context,
        confidence=confidence,
        next_steps=next_steps or [],
    )


def _scan_text_for_creds(
    text: str,
    source_url: str,
    source_type: str,
) -> List[HarvestedCredential]:
    creds = []
    for cred_type, pattern in CRED_PATTERNS:
        for m in re.finditer(pattern, text):
            val = m.group(1) if m.lastindex else m.group(0)
            ctx = _context_excerpt(text, m.start())
            creds.append(_make_cred(cred_type, val, source_url, source_type, ctx, 0.8))
    return creds


def _harvest_env_files(state: Dict[str, Any]) -> List[HarvestedCredential]:
    creds = []
    infra_intel = state.get("infra_intel", {})
    for sub, data in infra_intel.items():
        if not isinstance(data, dict):
            continue
        for path_entry in data.get("discovered_paths", []):
            if not isinstance(path_entry, dict):
                continue
            if path_entry.get("path") == "/.env" and path_entry.get("status") == 200:
                body = path_entry.get("body", "")
                if not body:
                    continue
                source_url = f"https://{sub}/.env"
                for m in _ENV_LINE_RE.finditer(body):
                    key, value = m.group(1), m.group(2).strip()
                    cred_type = _classify_env_key(key, value)
                    if cred_type:
                        creds.append(_make_cred(
                            cred_type, value, source_url, "exposed_env",
                            f"{key}={_redact(value)}", 0.9,
                            [f"Rotate {key} immediately and audit access logs"],
                        ))
    return creds


def _harvest_git_configs(state: Dict[str, Any]) -> List[HarvestedCredential]:
    creds = []
    infra_intel = state.get("infra_intel", {})
    for sub, data in infra_intel.items():
        if not isinstance(data, dict):
            continue
        for path_entry in data.get("discovered_paths", []):
            if not isinstance(path_entry, dict):
                continue
            if path_entry.get("path") == "/.git/config" and path_entry.get("status") == 200:
                body = path_entry.get("body", "")
                if not body:
                    continue
                source_url = f"https://{sub}/.git/config"
                for m in _GIT_CRED_URL_RE.finditer(body):
                    username, token = m.group(1), m.group(2)
                    creds.append(_make_cred(
                        "github_token", token, source_url, "exposed_git",
                        f"url = https://{username}:***@...", 0.85,
                        ["Revoke git credential immediately", f"Audit commits by {username}"],
                    ))
    return creds


def _harvest_github_actions(state: Dict[str, Any]) -> List[HarvestedCredential]:
    creds = []
    code_intel = state.get("code_intel", {})
    for key, data in code_intel.items():
        if not isinstance(data, dict):
            continue
        leaks = data.get("leaks", [])
        if not leaks and isinstance(data.get("data"), dict):
            leaks = data["data"].get("leaks", [])
        for leak in (leaks or []):
            if not isinstance(leak, dict):
                continue
            val = leak.get("secret") or leak.get("value", "")
            if not val:
                continue
            creds.append(_make_cred(
                leak.get("rule_id", "generic_api_key"), val,
                leak.get("file", f"github_actions/{key}"), "github_workflow",
                leak.get("line", ""), 0.9,
                [f"Rotate secret found in {leak.get('file', 'unknown')}"],
            ))
    return creds


def _harvest_gitleaks(state: Dict[str, Any]) -> List[HarvestedCredential]:
    creds = []
    code_intel = state.get("code_intel", {})
    for key, data in code_intel.items():
        if not isinstance(data, dict):
            continue
        findings = data.get("findings", [])
        if not findings and isinstance(data.get("data"), dict):
            findings = data["data"].get("findings", [])
        for finding in (findings or []):
            if not isinstance(finding, dict):
                continue
            val = finding.get("secret") or finding.get("match", "")
            if not val:
                continue
            creds.append(_make_cred(
                finding.get("rule_id", "generic_api_key"), val,
                finding.get("file", f"gitleaks/{key}"), "code_leak",
                finding.get("line", ""), 0.85,
            ))
    return creds


def _harvest_infostealer(state: Dict[str, Any]) -> List[HarvestedCredential]:
    creds = []
    email_intel = state.get("email_intel", {})
    for em, data in email_intel.get("emails", {}).items():
        if not isinstance(data, dict):
            continue
        for log_entry in data.get("stealer_logs", []):
            if not isinstance(log_entry, dict):
                continue
            pwd = log_entry.get("password", "")
            if pwd:
                creds.append(_make_cred(
                    "password", pwd, log_entry.get("url", em), "infostealer",
                    f"email={em} site={log_entry.get('url', '?')}", 0.95,
                    ["Reset password immediately", "Enable MFA if not already set"],
                ))

    breach_intel = state.get("breach_intel", {})
    for em, data in breach_intel.items():
        if not isinstance(data, dict):
            continue
        for entry in data.get("entries", []):
            if not isinstance(entry, dict):
                continue
            pwd = entry.get("password", "")
            if pwd:
                creds.append(_make_cred(
                    "password", pwd, entry.get("database_name", em), "infostealer",
                    f"email={em} db={entry.get('database_name', '?')}", 0.75,
                ))
    return creds


def _harvest_pastebin(state: Dict[str, Any]) -> List[HarvestedCredential]:
    creds = []
    dark_intel = state.get("dark_intel", {})
    for key, data in dark_intel.items():
        if not isinstance(data, dict):
            continue
        for paste in data.get("pastes", []):
            if not isinstance(paste, dict):
                continue
            for leaked in paste.get("leaked_secrets", []):
                if not isinstance(leaked, dict):
                    continue
                cred_type = leaked.get("type", "generic_api_key")
                creds.append(_make_cred(
                    cred_type, leaked.get("pattern", "?")[:40],
                    paste.get("url", "pastebin"), "code_leak",
                    paste.get("context_excerpt", "")[:100], 0.6,
                ))
    return creds


async def _validate_aws(cred: HarvestedCredential, raw_value: str) -> None:
    try:
        import boto3
        client = boto3.client("sts")
        result = await asyncio.to_thread(client.get_caller_identity)
        cred.validated = True
        cred.validation_method = "aws sts get-caller-identity"
        cred.validation_metadata = {
            "account_id": result.get("Account", ""),
            "user_arn": result.get("Arn", ""),
        }
    except Exception as exc:
        cred.next_steps.append(f"Manual validation: aws sts get-caller-identity (error: {exc})")


async def _validate_github(cred: HarvestedCredential, raw_value: str) -> None:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {raw_value}"},
            )
            if resp.status_code == 200:
                data = resp.json()
                cred.validated = True
                cred.validation_method = "GET https://api.github.com/user"
                cred.validation_metadata = {"login": data.get("login", ""), "email": data.get("email", "")}
    except Exception as exc:
        cred.next_steps.append(f"Manual: curl -H 'Authorization: token <token>' https://api.github.com/user")


async def _validate_slack(cred: HarvestedCredential, raw_value: str) -> None:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "https://slack.com/api/auth.test",
                data={"token": raw_value},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("ok"):
                    cred.validated = True
                    cred.validation_method = "POST https://slack.com/api/auth.test"
                    cred.validation_metadata = {"team": data.get("team", ""), "user": data.get("user", "")}
    except Exception:
        pass


async def _validate_jwt(cred: HarvestedCredential, raw_value: str) -> None:
    try:
        import json as _json
        import base64
        parts = raw_value.split(".")
        if len(parts) >= 2:
            padded = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = _json.loads(base64.urlsafe_b64decode(padded))
            cred.validated = True
            cred.validation_method = "JWT decode (signature not verified)"
            cred.validation_metadata = payload
    except Exception:
        pass


async def harvest_credentials(
    state: Dict[str, Any],
    validate: bool = False,
) -> List[HarvestedCredential]:
    """Walk all intel sources, extract concrete credentials, optionally validate (read-only)."""
    all_creds: List[HarvestedCredential] = []

    all_creds.extend(_harvest_env_files(state))
    all_creds.extend(_harvest_git_configs(state))
    all_creds.extend(_harvest_github_actions(state))
    all_creds.extend(_harvest_gitleaks(state))
    all_creds.extend(_harvest_infostealer(state))
    all_creds.extend(_harvest_pastebin(state))

    # Deduplicate by value_hash
    seen_hashes: set[str] = set()
    unique_creds: List[HarvestedCredential] = []
    for cred in all_creds:
        if cred.value_hash not in seen_hashes:
            seen_hashes.add(cred.value_hash)
            unique_creds.append(cred)

    if validate:
        # Build a map from hash → raw value for validation
        # Re-extract raw values for validation only — we never log them
        raw_map = _build_raw_map(state)

        async def _validate_one(cred: HarvestedCredential) -> None:
            raw = raw_map.get(cred.value_hash, "")
            if not raw:
                return
            if cred.cred_type in ("aws_access_key",):
                await _validate_aws(cred, raw)
            elif cred.cred_type in ("github_token", "github_oauth"):
                await _validate_github(cred, raw)
            elif cred.cred_type == "slack_token":
                await _validate_slack(cred, raw)
            elif cred.cred_type == "jwt":
                await _validate_jwt(cred, raw)
            else:
                cred.next_steps.append(f"Manual validation required for {cred.cred_type}")

        await asyncio.gather(*(_validate_one(c) for c in unique_creds), return_exceptions=True)

    log.info("Credential harvest complete", total=len(unique_creds), validated=sum(1 for c in unique_creds if c.validated))
    return unique_creds


def _build_raw_map(state: Dict[str, Any]) -> Dict[str, str]:
    """Build hash→raw_value map for validation. Values are never logged."""
    raw_map: Dict[str, str] = {}

    infra_intel = state.get("infra_intel", {})
    for sub, data in infra_intel.items():
        if not isinstance(data, dict):
            continue
        for path_entry in data.get("discovered_paths", []):
            if path_entry.get("path") == "/.env" and path_entry.get("status") == 200:
                body = path_entry.get("body", "")
                for m in _ENV_LINE_RE.finditer(body):
                    key, value = m.group(1), m.group(2).strip()
                    raw_map[_sha256(value)] = value

    code_intel = state.get("code_intel", {})
    for key, data in code_intel.items():
        if not isinstance(data, dict):
            continue
        for src_key in ("leaks", "findings"):
            items = data.get(src_key) or (data.get("data") or {}).get(src_key, [])
            for item in (items or []):
                val = (item or {}).get("secret") or (item or {}).get("match", "")
                if val:
                    raw_map[_sha256(val)] = val

    return raw_map
