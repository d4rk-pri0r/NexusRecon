"""Contribution SDK — Phase 3 PR B.

The Pack format (PR A) made it possible to ship contributions
*without forking*. PR B makes it actually pleasant to write
them. The SDK exposes three concerns a community contributor
will hit immediately:

  1. **Prompt versioning** — every agent prompt is registered
     with a version + content hash so the audit trail can
     show which exact prompt produced which finding. Without
     this, a hot-patched prompt invalidates the historical
     audit chain; with it, prompt changes are first-class
     citizens.

  2. **Citation guardrails** — agents that don't cite the
     graph entities they reference are the #1 source of
     hallucinated findings in production. The SDK provides a
     drop-in validator that parses an agent response,
     extracts claimed citations, and verifies each one
     against the live graph. Bad citations land in the
     verification log; the operator decides whether to gate
     or just flag.

  3. **Agent scaffolder** (``nexusrecon agent new``) — an
     interactive Rich-prompted generator that produces a
     ready-to-edit agent file with prompt versioning +
     citation hooks already wired in. Lower the "new
     contributor's first PR" barrier from "read 3000 lines
     of base classes" to "run one command, edit one file".

Sequencing within PR B
- ``prompt_versioning`` is the foundation — both other pieces
  reference it. Stateless module, ~150 lines.
- ``citation_guard`` is independent — pure validation, can
  be used by core agents too (not just contributed ones).
- ``agent_scaffolder`` ties them together: every generated
  template uses both modules.

What's NOT here (future PRs)
- Cookiecutter dependency. Templates are inlined Python
  strings to keep deps lean; can be migrated later.
- Tool / policy / report scaffolders. Same pattern is
  cheap to add once the agent path proves out.
- Live prompt diff viewer. PR D may add a TUI surface; PR
  B just records the data.
"""
from nexusrecon.sdk.citation_guard import (
    CitationReport,
    CitationViolation,
    validate_citations,
)
from nexusrecon.sdk.prompt_versioning import (
    PromptRecord,
    PromptVersionMismatch,
    compute_prompt_hash,
    get_prompt_record,
    list_registered_prompts,
    register_prompt,
)

__all__ = [
    "CitationReport",
    "CitationViolation",
    "PromptRecord",
    "PromptVersionMismatch",
    "compute_prompt_hash",
    "get_prompt_record",
    "list_registered_prompts",
    "register_prompt",
    "validate_citations",
]
