"""Intel Package export — Phase 4 PR B.

Phase 4's structured-export goal: emit campaign findings in
formats downstream tools (vulnerability scanners, C2
frameworks, SOAR / ticketing systems) can consume directly,
without bespoke parsers per integration.

The export format chosen by the architecture decisions is
**STIX 2.1** — the OASIS standard for threat intel exchange.
Every NexusRecon entity maps to a STIX SDO/SCO; every
relationship maps to a STIX Relationship SRO. The output is
a STIX Bundle, the canonical container format.

What ships in PR B
- :func:`build_stix_bundle(graph, scope_hash, ...)` — turns
  an :class:`EntityGraph` into a STIX 2.1 bundle dict.
- :func:`write_stix_bundle(graph, path, ...)` — convenience
  wrapper that serialises to a file.
- ``nexusrecon export --format stix2`` CLI command.
- Stdlib-only implementation (no ``stix2`` library dep).
  Schema correctness verified by structural tests; strict
  validation can layer on later with the official library.

What downstream consumers get
- Vulnerability scanners read the ``vulnerability`` SDOs +
  ``infrastructure`` SDOs to know what to test.
- C2 frameworks read the ``identity`` SDOs + ``email-addr``
  + ``url`` SCOs to seed pretext + listener config.
- SOAR / ticketing systems read the ``note`` SDOs (which
  carry hypotheses + leads + open questions) and the
  ``indicator`` SDOs (high-confidence findings).
- Generic JSON consumers can read the same bundle — STIX
  is JSON underneath.

Mapping reference
- ``domain`` / ``subdomain`` → ``domain-name`` SCO
- ``ip_address`` → ``ipv4-addr`` or ``ipv6-addr`` SCO
- ``email`` → ``email-addr`` SCO
- ``url`` → ``url`` SCO
- ``person`` / ``organization`` → ``identity`` SDO
- ``technology`` → ``software`` SCO
- ``cve`` → ``vulnerability`` SDO with CVE external_reference
- ``cloud_asset`` / ``repository`` → ``infrastructure`` SDO
- ``hypothesis`` / ``lead`` / ``open_question`` → ``note`` SDO
- ``secret`` → ``note`` SDO (we record the EXISTENCE +
  location, never the secret value itself)
- Relationships → ``relationship`` SROs with NexusRecon
  rel_type carried through as the ``relationship_type``
"""
from nexusrecon.export.stix import (
    STIXBundle,
    build_stix_bundle,
    write_stix_bundle,
)

__all__ = [
    "STIXBundle",
    "build_stix_bundle",
    "write_stix_bundle",
]
