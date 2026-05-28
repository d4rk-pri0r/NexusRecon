"""
Scope enforcement — the most important module in NexusRecon.

The ScopeGuard is called before EVERY tool invocation.  It is not a
suggestion.  Out-of-scope targets are dropped with an audit log entry
and an OutOfScopeError is raised.  The tool never executes.

Also enforces tier limits.  A T2 tool cannot run if max_tier is T1.
"""

from __future__ import annotations

import re
from ipaddress import AddressValueError, IPv4Address, IPv4Network, IPv6Address, IPv6Network

import structlog

from nexusrecon.models.scope import ScopeModel

log = structlog.get_logger(__name__)


class OutOfScopeError(Exception):
    """Raised when a tool target is not within the authorized scope."""

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"OUT OF SCOPE: {target!r} — {reason}")


class TierViolationError(Exception):
    """Raised when a tool's tier exceeds the max authorized tier."""

    def __init__(self, tool_name: str, tool_tier: str, max_tier: str) -> None:
        self.tool_name = tool_name
        self.tool_tier = tool_tier
        self.max_tier = max_tier
        super().__init__(
            f"TIER VIOLATION: Tool '{tool_name}' is {tool_tier} but "
            f"engagement max tier is {max_tier}"
        )


class ConstraintViolationError(Exception):
    """Raised when a tool is disallowed by an engagement constraint.

    Distinct from scope/tier violations: the target is in scope and the
    tier is permitted, but the engagement turned off a capability the
    tool depends on (paid APIs, breach-DB lookups). The tool is skipped,
    not blocked for legal reasons ── audited as ``policy_skipped`` rather
    than ``scope_violation``.
    """

    def __init__(self, tool_name: str, constraint: str, reason: str) -> None:
        self.tool_name = tool_name
        self.constraint = constraint
        self.reason = reason
        super().__init__(f"POLICY SKIP: {tool_name} - {reason}")


class ScopeGuard:
    """
    Validates tool targets and tier levels against the engagement scope.

    Usage:
        guard = ScopeGuard(scope)
        guard.check_domain("dev.acme.com")          # raises if out of scope
        guard.check_tier("T1", "subfinder")         # raises if tier too high
    """

    def __init__(self, scope: ScopeModel) -> None:
        self.scope = scope
        self._build_lookups()

    def _build_lookups(self) -> None:
        """Pre-compute lookup structures for fast validation."""
        s = self.scope.scope
        ins = s.in_scope
        outs = s.out_of_scope

        self._allowed_domains: list[str] = [d.lower() for d in (ins.domains or [])]
        self._blocked_domains: list[str] = [d.lower() for d in (outs.domains or [])]
        self._allowed_emails: list[str] = [e.lower() for e in (ins.email_domains or [])]

        self._allowed_networks: list[IPv4Network | IPv6Network] = []
        for cidr in (ins.ip_ranges or []):
            try:
                self._allowed_networks.append(IPv4Network(cidr, strict=False))
            except ValueError:
                try:
                    self._allowed_networks.append(IPv6Network(cidr, strict=False))
                except ValueError:
                    log.warning("Invalid IP range in scope", cidr=cidr)

        self._blocked_networks: list[IPv4Network | IPv6Network] = []
        for cidr in (outs.ip_ranges or []):
            try:
                self._blocked_networks.append(IPv4Network(cidr, strict=False))
            except ValueError:
                try:
                    self._blocked_networks.append(IPv6Network(cidr, strict=False))
                except ValueError:
                    pass

        self._allowed_asns: list[str] = [a.upper() for a in (ins.asns or [])]

    # ── Domain checks ─────────────────────────────────────────────────────────

    def check_domain(self, domain: str) -> None:
        """
        Validate that a domain is in scope.

        Raises OutOfScopeError if:
        - The domain matches an out-of-scope pattern (wildcard or exact)
        - The domain does not match any in-scope domain (exact or subdomain)
        """
        domain = domain.lower().strip(".")

        # Check blocked first (highest priority)
        for blocked in self._blocked_domains:
            if self._domain_matches(domain, blocked):
                raise OutOfScopeError(
                    domain,
                    f"Matches out-of-scope pattern: {blocked!r}",
                )

        # Check allowed
        for allowed in self._allowed_domains:
            if self._domain_matches(domain, allowed):
                return

        # Also check email domains as in-scope
        for ed in self._allowed_emails:
            if self._domain_matches(domain, ed):
                return

        raise OutOfScopeError(
            domain,
            "Not in any in-scope domain or email domain",
        )

    def _domain_matches(self, domain: str, pattern: str) -> bool:
        """
        Match a domain against a scope pattern.

        Patterns:
        - exact match: "acme.com"
        - wildcard prefix: "*.acme.com" matches all subdomains
        - raw subdomain: "acme.com" matches "sub.acme.com" and "acme.com"
        """
        if pattern.startswith("*."):
            suffix = pattern[2:]  # strip "*."
            return domain == suffix or domain.endswith("." + suffix)
        else:
            return domain == pattern or domain.endswith("." + pattern)

    def is_domain_in_scope(self, domain: str) -> bool:
        """Non-raising version of check_domain."""
        try:
            self.check_domain(domain)
            return True
        except OutOfScopeError:
            return False

    # ── IP checks ─────────────────────────────────────────────────────────────

    def check_ip(self, ip_str: str) -> None:
        """Validate that an IP address is within an authorized range."""
        try:
            addr: IPv4Address | IPv6Address
            try:
                addr = IPv4Address(ip_str)
                networks = [n for n in self._blocked_networks if isinstance(n, IPv4Network)]
                allowed_nets = [n for n in self._allowed_networks if isinstance(n, IPv4Network)]
            except AddressValueError:
                addr = IPv6Address(ip_str)
                networks = [n for n in self._blocked_networks if isinstance(n, IPv6Network)]
                allowed_nets = [n for n in self._allowed_networks if isinstance(n, IPv6Network)]
        except (AddressValueError, ValueError) as e:
            raise OutOfScopeError(ip_str, f"Not a valid IP address: {e}")

        for blocked_net in networks:
            if addr in blocked_net:
                raise OutOfScopeError(ip_str, f"In blocked IP range: {blocked_net}")

        if not allowed_nets:
            # No IP ranges defined — IP-only checks not enforced
            return

        for allowed_net in allowed_nets:
            if addr in allowed_net:
                return

        raise OutOfScopeError(ip_str, "Not in any authorized IP range")

    def is_ip_in_scope(self, ip_str: str) -> bool:
        try:
            self.check_ip(ip_str)
            return True
        except OutOfScopeError:
            return False

    # ── ASN checks ────────────────────────────────────────────────────────────

    def check_asn(self, asn: str) -> None:
        asn_upper = asn.upper()
        if self._allowed_asns and asn_upper not in self._allowed_asns:
            raise OutOfScopeError(asn, f"ASN not in scope. Authorized: {self._allowed_asns}")

    # ── Tier checks ───────────────────────────────────────────────────────────

    def check_tier(self, tool_tier: str, tool_name: str) -> None:
        """Raise TierViolationError if tool tier exceeds max authorized tier."""
        max_tier_val = self.scope.tier_value()
        try:
            tool_tier_val = int(tool_tier[1])  # "T0" -> 0, "T1" -> 1, etc.
        except (IndexError, ValueError):
            raise ValueError(f"Invalid tier format: {tool_tier!r}")

        if tool_tier_val > max_tier_val:
            raise TierViolationError(
                tool_name, tool_tier, self.scope.constraints.max_tier
            )

    def is_tier_allowed(self, tool_tier: str) -> bool:
        try:
            self.check_tier(tool_tier, "check")
            return True
        except TierViolationError:
            return False

    # ── Engagement-constraint checks (Wave F-A2) ──────────────────────────────

    def check_constraints(
        self,
        tool_name: str,
        category: str,
        paid_api: bool,
    ) -> None:
        """Raise ConstraintViolationError if an engagement constraint
        forbids this tool, independent of scope and tier.

        Two gates today, both driven by ``scope.constraints``:

        - ``allow_breach_db_lookup: false`` blocks any breach-category
          tool (DeHashed, LeakCheck, Hudson Rock, etc.). The operator
          said no breach-DB lookups; that includes free-tier ones.
        - ``allow_paid_apis: false`` blocks tools flagged ``paid_api``
          (Shodan and friends) even when a key is configured globally.

        Primitives, not the tool object, keep this legal-critical module
        free of any dependency on ``tools.base``.
        """
        c = self.scope.constraints
        if category == "breach" and not c.allow_breach_db_lookup:
            raise ConstraintViolationError(
                tool_name,
                "allow_breach_db_lookup",
                "breach-database lookups are disabled for this engagement "
                "(allow_breach_db_lookup: false)",
            )
        if paid_api and not c.allow_paid_apis:
            raise ConstraintViolationError(
                tool_name,
                "allow_paid_apis",
                "paid-API tools are disabled for this engagement "
                "(allow_paid_apis: false)",
            )

    def is_tool_allowed_by_constraints(self, category: str, paid_api: bool) -> bool:
        """Non-raising version of check_constraints (for preflight surfaces)."""
        try:
            self.check_constraints("check", category, paid_api)
            return True
        except ConstraintViolationError:
            return False

    # ── Cloud tenant checks ───────────────────────────────────────────────────

    def check_m365_tenant(self, tenant: str) -> None:
        """Validate that an M365 tenant is in scope."""
        allowed = self.scope.scope.in_scope.cloud_tenants.m365
        if not allowed:
            return  # No M365 restriction defined
        tenant_lower = tenant.lower()
        for a in allowed:
            if tenant_lower == a.lower() or tenant_lower.startswith(a.lower()):
                return
        raise OutOfScopeError(tenant, f"M365 tenant not in scope. Authorized: {allowed}")

    def check_aws_account(self, account_id: str) -> None:
        """Validate that an AWS account ID is in scope."""
        allowed = self.scope.scope.in_scope.cloud_tenants.aws_accounts
        if not allowed:
            return
        if account_id not in allowed:
            raise OutOfScopeError(
                account_id, f"AWS account not in scope. Authorized: {allowed}"
            )

    def check_github_org(self, org: str) -> None:
        """Validate that a GitHub org is in scope (by domain or explicit list)."""
        allowed_orgs = self.scope.scope.in_scope.github_orgs or []
        if not allowed_orgs:
            return  # No explicit GitHub restriction — rely on domain check
        if org.lower() not in [o.lower() for o in allowed_orgs]:
            raise OutOfScopeError(org, f"GitHub org not in scope. Authorized: {allowed_orgs}")

    # ── Combined target check ─────────────────────────────────────────────────

    def validate_target(self, target: str, target_type: str, tool_name: str, tier: str) -> None:
        """
        Full pre-flight check for a tool invocation.
        Checks tier first (cheaper), then target scope.
        """
        self.check_tier(tier, tool_name)

        if target_type == "domain":
            self.check_domain(target)
        elif target_type == "ip":
            self.check_ip(target)
        elif target_type == "asn":
            self.check_asn(target)
        elif target_type == "m365_tenant":
            self.check_m365_tenant(target)
        elif target_type == "aws_account":
            self.check_aws_account(target)
        elif target_type == "github_org":
            self.check_github_org(target)
        # email: domain part is checked
        elif target_type == "email":
            domain = target.split("@")[-1] if "@" in target else target
            self.check_domain(domain)


# ── Pre-flight infrastructure checks ─────────────────────────────────────────

SHARED_INFRASTRUCTURE_PATTERNS = [
    # CDN providers (shared infrastructure)
    r"cloudflare\.com$",
    r"fastly\.net$",
    r"akamaiedge\.net$",
    r"cloudfront\.net$",
    r"azureedge\.net$",
    r"googleusercontent\.com$",
    # Shared SaaS
    r"salesforce\.com$",
    r"zendesk\.com$",
    r"hubspot\.com$",
    r"freshdesk\.com$",
    r"intercom\.io$",
    r"twilio\.com$",
    r"sendgrid\.net$",
]


def check_shared_infrastructure(domain: str) -> str | None:
    """
    Return a warning message if domain appears to be shared infrastructure
    that is not client-owned.  Operator must explicitly acknowledge before
    scanning these targets.
    """
    domain_lower = domain.lower()
    for pattern in SHARED_INFRASTRUCTURE_PATTERNS:
        if re.search(pattern, domain_lower):
            return (
                f"Domain '{domain}' appears to match shared infrastructure "
                f"pattern '{pattern}'.  Verify this is client-owned before scanning."
            )
    return None


def preflight_check(scope: ScopeModel) -> list[tuple[str, str]]:
    """
    Run pre-flight validation on the entire scope.

    Returns list of (warning_level, message) tuples.
    warning_level is "ERROR" or "WARN".
    """
    warnings = []

    ins = scope.scope.in_scope

    # Check for potential shared infra in in-scope domains
    for domain in (ins.domains or []):
        msg = check_shared_infrastructure(domain)
        if msg:
            warnings.append(("WARN", msg))

    # Verify SOW hash format
    sow_hash = scope.engagement.signed_sow_hash
    if not sow_hash or not sow_hash.startswith("sha256:"):
        warnings.append(("ERROR", "signed_sow_hash must be a sha256: hash of the signed SOW document"))

    # Verify date range
    try:
        from datetime import date
        start = date.fromisoformat(scope.engagement.start_date)
        end = date.fromisoformat(scope.engagement.end_date)
        today = date.today()
        if today < start:
            warnings.append(("WARN", f"Engagement starts {scope.engagement.start_date} — not yet active"))
        if today > end:
            warnings.append(("ERROR", f"Engagement ended {scope.engagement.end_date} — scope is expired"))
    except ValueError as e:
        warnings.append(("ERROR", f"Invalid date format in engagement: {e}"))

    # Warn if no domains defined
    if not ins.domains and not ins.ip_ranges and not ins.asns:
        warnings.append(("WARN", "No domains, IP ranges, or ASNs defined in scope"))

    return warnings
