"""
Entity models for the NexusRecon entity graph.

Every piece of intelligence resolves to one of these entity types.
Entities are nodes; relationships are edges.  All entities require
a source citation — entities without provenance are rejected at
the evidence auditor stage.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── Entity and Relationship Enumerations ─────────────────────────────────────

class EntityType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    ASN = "asn"
    CERTIFICATE = "certificate"
    EMAIL = "email"
    PERSON = "person"
    ORGANIZATION = "organization"
    CLOUD_ASSET = "cloud_asset"
    REPOSITORY = "repository"
    SECRET = "secret"
    TECHNOLOGY = "technology"
    CVE = "cve"
    SOCIAL_ACCOUNT = "social_account"
    USERNAME = "username"
    URL = "url"
    FILE_ARTIFACT = "file_artifact"
    # Step 0.0 (METASPLOIT_PLAN): reasoning artifacts become
    # first-class graph nodes. Previously these lived as bare
    # ``list[str]`` on ``CampaignGraphState`` (hypotheses /
    # confirmed_leads / open_questions) — flat text the agents
    # couldn't reason over. Promoting them to nodes lets the
    # correlation agent query "which hypothesis cites which
    # entity" and the risk analyst surface "what
    # open-questions block the top thread".
    HYPOTHESIS = "hypothesis"
    LEAD = "lead"
    OPEN_QUESTION = "open_question"


class RelationshipType(StrEnum):
    RESOLVES_TO = "resolves_to"
    HAS_SUBDOMAIN = "has_subdomain"
    BELONGS_TO = "belongs_to"
    HAS_CERT = "has_cert"
    HOSTS = "hosts"
    OWNS = "owns"
    WORKS_AT = "works_at"
    HAS_ACCOUNT = "has_account"
    CONTAINS_SECRET = "contains_secret"
    HAS_TECH = "has_tech"
    HAS_CVE = "has_cve"
    LINKED_TO = "linked_to"
    TYPOSQUAT_OF = "typosquat_of"
    PART_OF = "part_of"
    ROUTES_THROUGH = "routes_through"
    REGISTERED_BY = "registered_by"
    HOSTED_ON = "hosted_on"
    EXPOSES = "exposes"
    # Step 0.0: edges from reasoning artifacts back to the
    # entities that justify them. A HypothesisEntity CITES the
    # email-list it was generated from; a LeadEntity CITES the
    # cloud-asset it implicates. Makes "explain this finding"
    # a graph traversal instead of a prompt-engineering exercise.
    CITES = "cites"
    BLOCKS = "blocks"  # an open_question BLOCKS a downstream lead


# ── Provenance (Phase 0.1) ───────────────────────────────────────────────────


class ProvenanceRecord(BaseModel):
    """One observation tying an entity to the tool that surfaced it.

    Phase 0.1 of ``IMPLEMENTATION_PLAN_METASPLOIT_OSINT.md``:
    the bare ``sources: list[str]`` was sufficient for the
    Step 0.0 wire-up but loses the audit trail. With a typed
    provenance record we can answer:

      - "Which exact tool invocation surfaced this entity?"
        (``tool_name`` + ``timestamp``)
      - "What audit-log entry hashed the raw response?"
        (``evidence_hash`` — links back to the hash-chained
        audit log produced by ``audit.log_tool_result``)
      - "How many independent sources corroborate this
        entity?" (``len(provenance)`` with distinct
        ``source`` values)

    All fields except ``source`` are optional so legacy
    code paths that only knew the tool name can still
    record provenance without back-filling history.
    """

    source: str
    """Short tool name / phase identifier — e.g. ``shodan``,
    ``crtsh``, ``phase4_correlation``. Matches the
    ``BaseEntity.sources`` legacy strings so the two surfaces
    stay convertible."""

    timestamp: datetime = Field(default_factory=datetime.utcnow)
    """When this source observed the entity. Distinct from
    ``BaseEntity.first_seen`` (earliest across all sources)
    and ``last_seen`` (most recent across all sources)."""

    evidence_hash: str | None = None
    """sha256 of the source's raw response — links back to the
    audit log entry that hashed the same response. Used by
    the verification engine in Phase 2 to detect when two
    sources actually agreed on identical raw evidence vs.
    independently arriving at the same conclusion."""

    tool_name: str | None = None
    """Tool class name when the source IS a tool (vs. an agent
    or phase). For ``shodan`` source, ``tool_name`` would be
    ``"ShodanTool"``. Phase / agent sources leave this
    None."""


# ── Base Entity ──────────────────────────────────────────────────────────────

class BaseEntity(BaseModel):
    """Base class for all NexusRecon entities."""

    entity_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: EntityType
    value: str  # primary identifier (domain name, IP, email, etc.)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    # Phase 0.1: rich provenance ── one record per observation. The
    # bare ``sources: list[str]`` survives as a derived view for the
    # parts of the codebase that haven't migrated yet (most of it,
    # at the time of this PR). Writers should prefer
    # ``add_provenance(...)``; readers that only need source names
    # can keep using ``sources``.
    provenance: list[ProvenanceRecord] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    engagement_id: str | None = None

    # Phase 0.1: marker for entities the system INFERRED rather than
    # observed directly. A ``possible_persona`` hypothesised by the
    # personal-pivot tool is virtual; the real corp email it was
    # derived from is not. Lets the verification engine treat them
    # differently when computing corroboration scores.
    is_virtual: bool = False

    def touch(self) -> None:
        """Update last_seen timestamp."""
        self.last_seen = datetime.utcnow()

    def add_source(self, source: str) -> None:
        if source not in self.sources:
            self.sources.append(source)
        self.touch()

    def add_provenance(
        self,
        source: str,
        *,
        timestamp: datetime | None = None,
        evidence_hash: str | None = None,
        tool_name: str | None = None,
    ) -> None:
        """Phase 0.1: add a typed provenance record.

        Also mirrors ``source`` into the legacy ``sources``
        list so old code paths that read ``sources`` see the
        update — the two surfaces stay in sync without a full
        migration of every reader.
        """
        record = ProvenanceRecord(
            source=source,
            timestamp=timestamp or datetime.utcnow(),
            evidence_hash=evidence_hash,
            tool_name=tool_name,
        )
        self.provenance.append(record)
        if source not in self.sources:
            self.sources.append(source)
        self.touch()


# ── Specific Entity Types ─────────────────────────────────────────────────────

class DomainEntity(BaseEntity):
    entity_type: EntityType = EntityType.DOMAIN
    registrar: str | None = None
    registration_date: datetime | None = None
    expiration_date: datetime | None = None
    registrant: str | None = None
    registrant_email: str | None = None
    registrant_org: str | None = None
    nameservers: list[str] = Field(default_factory=list)
    status: list[str] = Field(default_factory=list)
    dnssec: bool = False
    spf_record: str | None = None
    dmarc_policy: str | None = None
    mx_records: list[str] = Field(default_factory=list)
    a_records: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)


class SubdomainEntity(BaseEntity):
    entity_type: EntityType = EntityType.SUBDOMAIN
    parent_domain: str = ""
    cnames: list[str] = Field(default_factory=list)
    a_records: list[str] = Field(default_factory=list)
    is_alive: bool | None = None
    http_status: int | None = None
    technologies: list[str] = Field(default_factory=list)


class IPAddressEntity(BaseEntity):
    entity_type: EntityType = EntityType.IP_ADDRESS
    version: int = 4
    asn: str | None = None
    asn_name: str | None = None
    country: str | None = None
    city: str | None = None
    isp: str | None = None
    open_ports: list[int] = Field(default_factory=list)
    services: dict[str, str] = Field(default_factory=dict)  # port -> banner
    is_cloud: bool = False
    cloud_provider: str | None = None
    is_cdn: bool = False
    cdn_name: str | None = None
    abuse_score: int | None = None
    is_tor_exit: bool = False
    is_vpn: bool = False
    greynoise_classification: str | None = None


class ASNEntity(BaseEntity):
    entity_type: EntityType = EntityType.ASN
    asn_number: str = ""
    name: str | None = None
    country: str | None = None
    prefixes_v4: list[str] = Field(default_factory=list)
    prefixes_v6: list[str] = Field(default_factory=list)
    rir: str | None = None  # ARIN, RIPE, APNIC, etc.


class CertificateEntity(BaseEntity):
    entity_type: EntityType = EntityType.CERTIFICATE
    subject_cn: str = ""
    subject_org: str | None = None
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    san_domains: list[str] = Field(default_factory=list)
    serial_number: str | None = None
    fingerprint_sha256: str | None = None
    is_wildcard: bool = False
    is_expired: bool = False
    ct_log_url: str | None = None


class EmailEntity(BaseEntity):
    entity_type: EntityType = EntityType.EMAIL
    local_part: str = ""
    domain: str = ""
    person_name: str | None = None
    role: str | None = None
    department: str | None = None
    is_valid: bool | None = None
    is_deliverable: bool | None = None
    is_breached: bool = False
    breach_count: int = 0
    breach_names: list[str] = Field(default_factory=list)
    format_pattern: str | None = None  # e.g. "firstname.lastname"
    is_executive: bool = False


class PersonEntity(BaseEntity):
    entity_type: EntityType = EntityType.PERSON
    full_name: str = ""
    first_name: str | None = None
    last_name: str | None = None
    title: str | None = None
    department: str | None = None
    company: str | None = None
    email_addresses: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    social_profiles: dict[str, str] = Field(default_factory=dict)
    is_executive: bool = False
    is_technical: bool = False
    recent_activity: list[str] = Field(default_factory=list)
    profile_image_url: str | None = None
    location: str | None = None


class OrganizationEntity(BaseEntity):
    entity_type: EntityType = EntityType.ORGANIZATION
    legal_name: str = ""
    trade_name: str | None = None
    ticker: str | None = None
    exchange: str | None = None
    industry: str | None = None
    employee_count: int | None = None
    revenue: str | None = None
    founded: int | None = None
    headquarters: str | None = None
    description: str | None = None
    linkedin_url: str | None = None
    website: str | None = None
    crunchbase_url: str | None = None


class CloudAssetEntity(BaseEntity):
    entity_type: EntityType = EntityType.CLOUD_ASSET
    provider: str = ""          # aws, azure, gcp
    service_type: str = ""      # s3, blob, lambda, function, etc.
    resource_name: str = ""
    region: str | None = None
    is_public: bool = False
    is_authenticated: bool = True
    permissions: str | None = None  # read, write, list, etc.
    url: str | None = None
    account_id: str | None = None
    tenant_id: str | None = None


class RepositoryEntity(BaseEntity):
    entity_type: EntityType = EntityType.REPOSITORY
    platform: str = ""          # github, gitlab, bitbucket, etc.
    org: str | None = None
    repo_name: str = ""
    full_name: str = ""         # org/repo_name
    url: str = ""
    is_public: bool = True
    has_secrets: bool = False
    secret_count: int = 0
    languages: list[str] = Field(default_factory=list)
    stars: int | None = None
    last_commit: datetime | None = None
    description: str | None = None


class SecretEntity(BaseEntity):
    entity_type: EntityType = EntityType.SECRET
    secret_type: str = ""       # api_key, password, private_key, token, etc.
    service: str | None = None  # AWS, GitHub, Slack, Stripe, etc.
    source_file: str | None = None
    source_url: str | None = None
    raw_value: str | None = None  # store only partial/masked for safety
    is_active: bool | None = None
    commit_hash: str | None = None
    line_number: int | None = None
    detector: str | None = None  # gitleaks, trufflehog, etc.


class TechnologyEntity(BaseEntity):
    entity_type: EntityType = EntityType.TECHNOLOGY
    product: str = ""
    vendor: str | None = None
    version: str | None = None
    cpe: str | None = None
    category: str | None = None  # cms, framework, server, etc.
    is_eol: bool = False
    eol_date: datetime | None = None
    cve_count: int = 0


class CVEEntity(BaseEntity):
    entity_type: EntityType = EntityType.CVE
    cve_id: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    is_kev: bool = False            # CISA Known Exploited Vulnerabilities
    has_public_exploit: bool = False
    exploit_urls: list[str] = Field(default_factory=list)
    description: str | None = None
    affected_products: list[str] = Field(default_factory=list)
    published_date: datetime | None = None


class SocialAccountEntity(BaseEntity):
    entity_type: EntityType = EntityType.SOCIAL_ACCOUNT
    platform: str = ""
    username: str = ""
    display_name: str | None = None
    url: str | None = None
    bio: str | None = None
    follower_count: int | None = None
    following_count: int | None = None
    post_count: int | None = None
    is_verified: bool = False
    profile_image_url: str | None = None


class UsernameEntity(BaseEntity):
    entity_type: EntityType = EntityType.USERNAME
    username: str = ""
    platforms_found: list[str] = Field(default_factory=list)
    platform_urls: dict[str, str] = Field(default_factory=dict)


class URLEntity(BaseEntity):
    entity_type: EntityType = EntityType.URL
    url: str = ""
    domain: str | None = None
    path: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    title: str | None = None
    technologies: list[str] = Field(default_factory=list)
    interesting: bool = False
    interesting_reason: str | None = None


class FileArtifactEntity(BaseEntity):
    entity_type: EntityType = EntityType.FILE_ARTIFACT
    filename: str = ""
    url: str | None = None
    file_type: str | None = None
    file_hash: str | None = None
    creator: str | None = None
    created_date: datetime | None = None
    modified_date: datetime | None = None
    internal_paths: list[str] = Field(default_factory=list)
    software_info: list[str] = Field(default_factory=list)
    username_leaks: list[str] = Field(default_factory=list)


# ── Reasoning artifacts (Step 0.0) ────────────────────────────────────────────
#
# Previously held as ``list[str]`` on the LangGraph state. Promoting
# to first-class entities means agents can reason over them: which
# hypothesis cites which entity (CITES edge), which open question
# blocks which lead (BLOCKS edge), how confidence in a derived lead
# tracks confidence in its cited evidence.


class HypothesisEntity(BaseEntity):
    """A working hypothesis surfaced by the correlation phase.

    The ``value`` is the human-readable hypothesis text; the
    ``cites`` field carries entity_ids the hypothesis is based
    on (mirrored as CITES edges in the graph for traversal)."""
    entity_type: EntityType = EntityType.HYPOTHESIS
    statement: str = ""
    cites: list[str] = Field(default_factory=list)
    status: str = "open"  # open | corroborated | rejected
    generated_by: str | None = None  # phase or agent name


class LeadEntity(BaseEntity):
    """A confirmed lead — a finding the operator can act on.

    Stronger than a hypothesis: the cited evidence has cleared a
    confidence floor (per the correlation agent's logic). Carries
    severity + recommended-next-step so the TUI can surface it
    in the top threads pane."""
    entity_type: EntityType = EntityType.LEAD
    statement: str = ""
    cites: list[str] = Field(default_factory=list)
    severity: str = "medium"  # critical | high | medium | low | info
    recommended_action: str | None = None


class OpenQuestionEntity(BaseEntity):
    """A gap the operator (or the dispatcher) should chase.

    ``blocks`` lists entity_ids of downstream leads/hypotheses
    that depend on the question being answered. Useful for the
    strategic-reasoning engine in Phase 1 — "what's the next
    most-blocking question to dispatch tools against?" """
    entity_type: EntityType = EntityType.OPEN_QUESTION
    question: str = ""
    blocks: list[str] = Field(default_factory=list)
    suggested_tools: list[str] = Field(default_factory=list)


# ── Relationship Model ────────────────────────────────────────────────────────

class EntityRelationship(BaseModel):
    """A directed edge in the entity graph with full provenance."""

    rel_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str
    target_id: str
    rel_type: RelationshipType
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: str | None = None
    source_tool: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)
