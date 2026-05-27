"""Downstream-consumer integrations — Phase 4 PR D.

PR B shipped the generic STIX 2.1 export; PR D adds three
purpose-built emitters for the workflows operators actually
plug NexusRecon into:

  - :class:`JiraTicketEmitter` — turns Findings into JSON
    bodies the Jira REST API expects
    (``POST /rest/api/2/issue``). Operators paste-and-go via
    ``curl`` or feed into their SOAR.
  - :func:`emit_nuclei_targets` — extracts in-scope URLs +
    hosts from the campaign graph as a plain text list that
    Nuclei consumes via ``-list``. Closes the recon → vuln
    handoff loop.
  - :func:`emit_cobaltstrike_profile_stub` — generates a
    malleable C2 profile starter populated with the
    campaign's pretext targets + extracted technology
    fingerprints. NOT a finished profile (operators tune the
    tradecraft fields); the stub gets them past the boring
    boilerplate.

What's NOT here
- Live API calls. Each emitter writes a FILE the operator
  posts/feeds; we never call third-party APIs from this
  module. Auditability First — every outbound integration
  should be operator-visible at the seam.
- Sliver / Mythic / Splunk SOAR specific helpers. Same
  pattern as the bundled three; community packs can add
  more.
"""
from nexusrecon.export.downstream.cobaltstrike import (
    emit_cobaltstrike_profile_stub,
)
from nexusrecon.export.downstream.jira import (
    JiraIssue,
    JiraTicketEmitter,
)
from nexusrecon.export.downstream.nuclei import (
    emit_nuclei_targets,
)

__all__ = [
    "JiraIssue",
    "JiraTicketEmitter",
    "emit_cobaltstrike_profile_stub",
    "emit_nuclei_targets",
]
