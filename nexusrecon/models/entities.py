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
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Entity and Relationship Enumerations ─────────────────────────────────────

class EntityType(str, Enum):
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


class RelationshipType(str, Enum):
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


# ── Base Entity ──────────────────────────────────────────────────────────────

class BaseEntity(BaseModel):
    """Base class for all NexusRecon entities."""

    entity_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: EntityType
    value: str  # primary identifier (domain name, IP, email, etc.)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    sources: List[str] = Field(default_factory=list)
    engagement_id: Optional[str] = None

    def touch(self) -> None:
        """Update last_seen timestamp."""
        self.last_seen = datetime.utcnow()

    def add_source(self, source: str) -> None:
        if source not in self.sources:
            self.sources.append(source)
        self.touch()


# ── Specific Entity Types ─────────────────────────────────────────────────────

class DomainEntity(BaseEntity):
    entity_type: EntityType = EntityType.DOMAIN
    registrar: Optional[str] = None
    registration_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    registrant: Optional[str] = None
    registrant_email: Optional[str] = None
    registrant_org: Optional[str] = None
    nameservers: List[str] = Field(default_factory=list)
    status: List[str] = Field(default_factory=list)
    dnssec: bool = False
    spf_record: Optional[str] = None
    dmarc_policy: Optional[str] = None
    mx_records: List[str] = Field(default_factory=list)
    a_records: List[str] = Field(default_factory=list)
    txt_records: List[str] = Field(default_factory=list)


class SubdomainEntity(BaseEntity):
    entity_type: EntityType = EntityType.SUBDOMAIN
    parent_domain: str = ""
    cnames: List[str] = Field(default_factory=list)
    a_records: List[str] = Field(default_factory=list)
    is_alive: Optional[bool] = None
    http_status: Optional[int] = None
    technologies: List[str] = Field(default_factory=list)


class IPAddressEntity(BaseEntity):
    entity_type: EntityType = EntityType.IP_ADDRESS
    version: int = 4
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    services: Dict[str, str] = Field(default_factory=dict)  # port -> banner
    is_cloud: bool = False
    cloud_provider: Optional[str] = None
    is_cdn: bool = False
    cdn_name: Optional[str] = None
    abuse_score: Optional[int] = None
    is_tor_exit: bool = False
    is_vpn: bool = False
    greynoise_classification: Optional[str] = None


class ASNEntity(BaseEntity):
    entity_type: EntityType = EntityType.ASN
    asn_number: str = ""
    name: Optional[str] = None
    country: Optional[str] = None
    prefixes_v4: List[str] = Field(default_factory=list)
    prefixes_v6: List[str] = Field(default_factory=list)
    rir: Optional[str] = None  # ARIN, RIPE, APNIC, etc.


class CertificateEntity(BaseEntity):
    entity_type: EntityType = EntityType.CERTIFICATE
    subject_cn: str = ""
    subject_org: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    san_domains: List[str] = Field(default_factory=list)
    serial_number: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    is_wildcard: bool = False
    is_expired: bool = False
    ct_log_url: Optional[str] = None


class EmailEntity(BaseEntity):
    entity_type: EntityType = EntityType.EMAIL
    local_part: str = ""
    domain: str = ""
    person_name: Optional[str] = None
    role: Optional[str] = None
    department: Optional[str] = None
    is_valid: Optional[bool] = None
    is_deliverable: Optional[bool] = None
    is_breached: bool = False
    breach_count: int = 0
    breach_names: List[str] = Field(default_factory=list)
    format_pattern: Optional[str] = None  # e.g. "firstname.lastname"
    is_executive: bool = False


class PersonEntity(BaseEntity):
    entity_type: EntityType = EntityType.PERSON
    full_name: str = ""
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    title: Optional[str] = None
    department: Optional[str] = None
    company: Optional[str] = None
    email_addresses: List[str] = Field(default_factory=list)
    phone_numbers: List[str] = Field(default_factory=list)
    social_profiles: Dict[str, str] = Field(default_factory=dict)
    is_executive: bool = False
    is_technical: bool = False
    recent_activity: List[str] = Field(default_factory=list)
    profile_image_url: Optional[str] = None
    location: Optional[str] = None


class OrganizationEntity(BaseEntity):
    entity_type: EntityType = EntityType.ORGANIZATION
    legal_name: str = ""
    trade_name: Optional[str] = None
    ticker: Optional[str] = None
    exchange: Optional[str] = None
    industry: Optional[str] = None
    employee_count: Optional[int] = None
    revenue: Optional[str] = None
    founded: Optional[int] = None
    headquarters: Optional[str] = None
    description: Optional[str] = None
    linkedin_url: Optional[str] = None
    website: Optional[str] = None
    crunchbase_url: Optional[str] = None


class CloudAssetEntity(BaseEntity):
    entity_type: EntityType = EntityType.CLOUD_ASSET
    provider: str = ""          # aws, azure, gcp
    service_type: str = ""      # s3, blob, lambda, function, etc.
    resource_name: str = ""
    region: Optional[str] = None
    is_public: bool = False
    is_authenticated: bool = True
    permissions: Optional[str] = None  # read, write, list, etc.
    url: Optional[str] = None
    account_id: Optional[str] = None
    tenant_id: Optional[str] = None


class RepositoryEntity(BaseEntity):
    entity_type: EntityType = EntityType.REPOSITORY
    platform: str = ""          # github, gitlab, bitbucket, etc.
    org: Optional[str] = None
    repo_name: str = ""
    full_name: str = ""         # org/repo_name
    url: str = ""
    is_public: bool = True
    has_secrets: bool = False
    secret_count: int = 0
    languages: List[str] = Field(default_factory=list)
    stars: Optional[int] = None
    last_commit: Optional[datetime] = None
    description: Optional[str] = None


class SecretEntity(BaseEntity):
    entity_type: EntityType = EntityType.SECRET
    secret_type: str = ""       # api_key, password, private_key, token, etc.
    service: Optional[str] = None  # AWS, GitHub, Slack, Stripe, etc.
    source_file: Optional[str] = None
    source_url: Optional[str] = None
    raw_value: Optional[str] = None  # store only partial/masked for safety
    is_active: Optional[bool] = None
    commit_hash: Optional[str] = None
    line_number: Optional[int] = None
    detector: Optional[str] = None  # gitleaks, trufflehog, etc.


class TechnologyEntity(BaseEntity):
    entity_type: EntityType = EntityType.TECHNOLOGY
    product: str = ""
    vendor: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    category: Optional[str] = None  # cms, framework, server, etc.
    is_eol: bool = False
    eol_date: Optional[datetime] = None
    cve_count: int = 0


class CVEEntity(BaseEntity):
    entity_type: EntityType = EntityType.CVE
    cve_id: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_version: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    is_kev: bool = False            # CISA Known Exploited Vulnerabilities
    has_public_exploit: bool = False
    exploit_urls: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    affected_products: List[str] = Field(default_factory=list)
    published_date: Optional[datetime] = None


class SocialAccountEntity(BaseEntity):
    entity_type: EntityType = EntityType.SOCIAL_ACCOUNT
    platform: str = ""
    username: str = ""
    display_name: Optional[str] = None
    url: Optional[str] = None
    bio: Optional[str] = None
    follower_count: Optional[int] = None
    following_count: Optional[int] = None
    post_count: Optional[int] = None
    is_verified: bool = False
    profile_image_url: Optional[str] = None


class UsernameEntity(BaseEntity):
    entity_type: EntityType = EntityType.USERNAME
    username: str = ""
    platforms_found: List[str] = Field(default_factory=list)
    platform_urls: Dict[str, str] = Field(default_factory=dict)


class URLEntity(BaseEntity):
    entity_type: EntityType = EntityType.URL
    url: str = ""
    domain: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    title: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)
    interesting: bool = False
    interesting_reason: Optional[str] = None


class FileArtifactEntity(BaseEntity):
    entity_type: EntityType = EntityType.FILE_ARTIFACT
    filename: str = ""
    url: Optional[str] = None
    file_type: Optional[str] = None
    file_hash: Optional[str] = None
    creator: Optional[str] = None
    created_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    internal_paths: List[str] = Field(default_factory=list)
    software_info: List[str] = Field(default_factory=list)
    username_leaks: List[str] = Field(default_factory=list)


# ── Relationship Model ────────────────────────────────────────────────────────

class EntityRelationship(BaseModel):
    """A directed edge in the entity graph with full provenance."""

    rel_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str
    target_id: str
    rel_type: RelationshipType
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: Optional[str] = None
    source_tool: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)
