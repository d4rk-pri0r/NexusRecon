"""Bidirectional import — Phase 4 PR C.

Complement to the STIX 2.1 export (PR B). Operators routinely
have third-party tool output they want to fold INTO the
Living Graph: a Nessus vulnerability scan from last week, a
Nuclei output JSON from the security team, a CSV asset
inventory exported from the CMDB, or a STIX bundle handed
over by a partner.

Each importer takes a file path + the live :class:`EntityGraph`
and emits entities + relationships into the graph, tagged
with a distinguishing source identifier so the corroboration
engine can grade the resulting cross-source agreement
correctly.

What ships
- :class:`STIXBundleImporter` — round-trips PR B's own output
  back into a graph (so the export + import contract is
  testable end-to-end).
- :class:`NessusImporter` — parses Nessus XML reports
  (``.nessus`` files); emits host + vulnerability entities
  with the CVE references attached.
- :class:`NucleiImporter` — parses Nuclei's JSON-lines output
  format; emits the matched URL / host / vulnerability +
  the Nuclei template ID as evidence.
- :class:`CSVImporter` — generic CSV ingester with a
  declarative ``column_mapping`` so operators handle CMDB
  exports + spreadsheets without writing code.

Design tenets
- **Provenance first.** Every imported entity gets sources
  like ``imported_from:nessus`` or ``imported_from:csv``
  so downstream verifiers can grade the corroboration
  contribution correctly.
- **Skip + warn, never raise.** A malformed row / item /
  bundle entry produces a warning in the
  :class:`ImportReport`; the rest of the file continues.
  Same posture as the pack loader.
- **No schema mutation.** Importers do NOT register custom
  entity / relationship types. The Pack format (Phase 3 PR
  A) is the supported extension surface.
"""
from nexusrecon.ingest.csv_ import CSVImporter
from nexusrecon.ingest.nessus import NessusImporter
from nexusrecon.ingest.nuclei import NucleiImporter
from nexusrecon.ingest.stix_in import STIXBundleImporter
from nexusrecon.ingest.types import ImportReport, ImportResult

__all__ = [
    "CSVImporter",
    "ImportReport",
    "ImportResult",
    "NessusImporter",
    "NucleiImporter",
    "STIXBundleImporter",
]
