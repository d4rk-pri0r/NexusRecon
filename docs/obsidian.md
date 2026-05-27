# Obsidian workflow

NexusRecon's master report renders cleanly in
[Obsidian](https://obsidian.md) when emitted with the
`--obsidian` flag. The campaign output directory becomes a
vault subfolder; the master report becomes a note with YAML
frontmatter, wiki-style cross-references between deliverables,
and severity-tagged callouts.

The standard `master_report.md` stays unchanged so
GitHub-rendered links and external markdown viewers keep
working — `master_report.obsidian.md` is a parallel file, not
a replacement.

## Usage

```sh
nexusrecon run --scope scope.yaml --obsidian
```

After the run, the campaign output directory holds both files
side-by-side:

```
campaigns/eng-2026-01/acme.com/2026-01-15T14-30-00/
├── master_report.md                    # standard, GitHub-flavored
├── master_report.obsidian.md           # parallel, Obsidian-flavored
├── asset_inventory.md
├── findings.json
├── ...
```

## Open the directory as a vault

1. Launch Obsidian → **Open folder as vault**.
2. Pick the
   `campaigns/<engagement>/<target>/<timestamp>/` directory.
3. Accept Obsidian's "this folder is a vault" prompt.
4. Open `master_report.obsidian.md`. The Properties panel on
   the right surfaces the campaign metadata via the YAML
   frontmatter.

## What differs from the standard report

| Feature                | `master_report.md`               | `master_report.obsidian.md`                     |
|------------------------|----------------------------------|-------------------------------------------------|
| Frontmatter            | none                             | YAML block — campaign / target / scope_hash / version / tags |
| Cross-references       | `[label](file.md)`               | `[[file\|label]]` wikilinks for Graph View      |
| Severity blockquotes   | `> **CRITICAL**: …`              | `> [!danger] CRITICAL\n> …` Obsidian callouts   |
| External URLs          | unchanged                        | unchanged                                       |
| GitHub-preview render  | works                            | wikilinks appear as plain text                  |

The Obsidian variant uses Obsidian's **built-in** callout types
(`note`, `info`, `warning`, `danger`) — no community plugin
required.

## Properties surfaced

The YAML frontmatter exposes these properties (queryable via
Dataview + visible in the Properties panel):

```yaml
campaign_id: c-2026-01-15
engagement_id: ENG-2026-001
target: acme.com
generated: 2026-01-15T14:30:00
scope_hash: sha256:5a8f...
nexusrecon_version: 0.6.0
tags:
  - nexusrecon
  - recon
  - redteam
```

`scope_hash` and `nexusrecon_version` pair the way they do in
the standard report footer — links a given vault note back to a
specific signed engagement authorization + the framework
version that produced it.

## Graph View

Once you have multiple campaigns ingested into the same vault,
Obsidian's **Graph View** draws every campaign's deliverables
as a cluster of connected notes (because the wikilinks point
between them). Filter the graph by `tag:#redteam` to see only
NexusRecon notes, or by `tag:#nexusrecon AND tag:#recon` to
narrow further.

## What NOT to do

- **Don't commit a populated vault to a public repo.** The
  Obsidian variant carries the same sensitive findings the
  standard report does (and arguably highlights them more
  legibly). Per-engagement findings stay in the unpublished
  campaign directory.
- **Don't edit `master_report.obsidian.md` in the vault and
  expect changes to round-trip.** The file is regenerated on
  every campaign run; manual edits are overwritten. Add
  campaign notes to separate vault notes that link to the
  generated file.

## Tested with

- Obsidian 1.5+ (built-in callout syntax shipped in 1.0).
- Standard markdown viewers (the standard `master_report.md`
  remains GitHub-renderable and is unchanged).
