# NexusRecon v2 — "Gold Standard" Execution Plan

> **Audience:** Sonnet 4.6 with extended thinking, working autonomously.
> **Goal:** Implement the 5 highest-leverage moves to take NexusRecon from
> "comprehensive aggregator" to "the platform people demo on Twitter."
> **Working directory:** `/Users/waifumachine/agentic-osint`
> **Status going in:** 79 tools registered (46 keyless, 33 key/binary-gated). Scoring engine, top-threads
> report, and per-employee phishing pretext bundles already exist.

---

## 0. Codebase Conventions (READ FIRST)

These are *load-bearing* conventions. Follow them; don't invent new patterns.

### 0.1 Tool architecture

Every tool lives at `nexusrecon/tools/{category}/{name}_tool.py`, subclasses `OSINTTool`, uses `@register_tool`:

```python
from nexusrecon.tools.base import Category, OSINTTool, Tier, ToolResult
from nexusrecon.tools.registry import register_tool

@register_tool
class ExampleTool(OSINTTool):
    name = "example"
    tier = Tier.T0           # T0=passive, T1=active DNS/HTTP fingerprint, T2=active scan, T3=intrusive
    category = Category.WEB
    requires_keys = []        # list env-var names; empty = no key required
    binary_required = None    # "binary_name" if external CLI; None for pure-Python
    description = "One-line operator-facing summary"
    target_types = ["domain"]  # "domain" | "ip" | "email" | "cve" | "url"

    async def run(self, target: str, **kwargs) -> ToolResult:
        # ... return ToolResult(success=bool, source=self.name, data={...}, result_count=N)
```

Then add `from . import example_tool` to the matching `nexusrecon/tools/{category}/__init__.py`. Tools auto-register at import.

### 0.2 HTTP idioms

```python
import httpx

headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "application/json",
}

async with httpx.AsyncClient(headers=headers, timeout=15.0, follow_redirects=True) as client:
    resp = await client.get(url)
    ...
```

- **Always** `async with` (resource cleanup)
- **Never** `verify=False`
- **Never** hardcode `"NexusRecon/1.0"` UA — use the Firefox UA above
- Use `asyncio.Semaphore(N)` when fan-out > 20 concurrent requests
- For optional API keys: read via `self.config.get_secret("KEY_NAME")` and gracefully degrade if absent

### 0.3 ToolResult shape

`ToolResult` lives in `nexusrecon.tools.base`. Always pass:
- `success: bool`
- `source: str` (always `self.name`)
- `data: dict` — structured findings
- `result_count: int` — meaningful count (subdomains found, CVEs, etc.) — **not** just `1`
- `error: Optional[str]` on failure

### 0.4 State shape

State is `CampaignGraphState` (TypedDict, `nexusrecon/graph/state.py`). Existing keys:
`seeds`, `subdomain_intel`, `domain_intel`, `email_intel`, `cloud_intel`, `code_intel`, `infra_intel`,
`vuln_intel`, `pretext_intel`, `findings`, `confirmed_leads`, `hypotheses`, `agent_messages`,
`completed_phases`, `report_paths`, `ranked_threads` (added in Phase 8).

When you add new state keys, also add them to the TypedDict in `state.py`.

### 0.5 Phase pipeline

Phases live in `nexusrecon/graph/nodes.py`. Routing in `route_to_next_phase()`. Order:
phase1 → phase2 → phase3 → phase4 → phase5 → phase6 → phase7 → phase8 → phase9 → __end__

The graph is wired in `nexusrecon/graph/builder.py` (read this before adding new phases).

### 0.6 LLM access

```python
from nexusrecon.graph.agent_executor import AgentExecutor
executor = AgentExecutor(get_config())
result = await executor.run_agent(role="some_agent", task_data={...}, task_prompt="...")
# returns dict; result["output"] is the text
```

Available agent roles are in `nexusrecon/graph/agents.py`. New roles need to be registered there.

### 0.7 Reporting

`nexusrecon/reports/engine.py` — `ReportEngine.generate_all(state)` calls a series of `_method(state)`
methods that each write one file and return its path. To add a report: add a method, append to
`generate_all()`. Do **not** create separate orchestration classes.

### 0.8 What NOT to do

- Don't add `verify=False` or hardcoded UAs.
- Don't create new abstraction layers (no `BaseHTTPTool`, no factories). Each tool is a flat subclass.
- Don't write multi-paragraph docstrings or comment-block headers.
- Don't add backwards-compat shims; this codebase is pre-1.0 — break things if needed.
- Don't create `__init__.py` re-exports beyond `from . import name_tool` lines.
- Don't write CLI commands unless the move explicitly requires them.

### 0.9 Verification (run after every move)

```bash
cd /Users/waifumachine/agentic-osint
python3 -c "
from nexusrecon.tools.registry import get_registry
import nexusrecon.tools.domain, nexusrecon.tools.pretext, nexusrecon.tools.cloud
import nexusrecon.tools.intel, nexusrecon.tools.web, nexusrecon.tools.vuln
import nexusrecon.tools.identity
# add new categories here as you create them
print(f'Registered: {len(list(get_registry()._tools.values()))}')
print(f'Available:  {len(get_registry().available_tools())}')
"
```

Then run `python3 -m py_compile $(find nexusrecon -name '*.py')` to confirm everything compiles.

---

## Move 1 — Coverage Gaps (Dark Web, Pastebin, Holehe, Ransomwatch, Ahmia)

### Why it matters
These are table-stakes for a "comprehensive" platform; absence is conspicuous to any reviewer. All
are passive (T0) and key-free or freemium.

### Tools to create

#### 1.1 `nexusrecon/tools/identity/holehe_tool.py`

- **Source:** the `holehe` Python library (already on PyPI, MIT). `pip install holehe`.
- **target_types:** `["email"]`
- **Category:** `Category.IDENTITY`
- **What it does:** given an email, returns ~120 sites where it's registered (Spotify, Adobe, Twitter, etc.).
- **Implementation:** import `holehe.core`, iterate the registered modules, run them concurrently with `asyncio.gather`. Holehe modules are async coroutines — they take `(email, client, out)` where `out` is a list it appends to.
- **Pattern:**
  ```python
  from holehe.core import import_submodules, get_functions
  modules = import_submodules("holehe.modules")
  funcs = get_functions(modules)
  out = []
  async with httpx.AsyncClient(timeout=10) as client:
      tasks = [func(email, client, out) for func in funcs]
      await asyncio.gather(*tasks, return_exceptions=True)
  # out items have shape: {"name": "spotify", "rateLimit": False, "exists": True, "emailrecovery": "...", "phoneNumber": "...", "others": {...}}
  ```
- **Output shape:** `{"email": str, "registered_count": int, "registered_services": [{"service": str, "details": {...}}]}`
- **Pitfall:** holehe spins up its own httpx client by default; we pass ours so the OPSEC proxy/UA settings apply. Some modules error out — `return_exceptions=True` is mandatory.

#### 1.2 `nexusrecon/tools/intel/pastebin_tool.py`

- **Sources:** psbdmp.ws (`https://psbdmp.ws/api/search/{query}` returns JSON of paste IDs), GitHub gists (`https://api.github.com/search/code?q={query}` requires `GITHUB_TOKEN` for higher rate limits).
- **Category:** `Category.INFRASTRUCTURE` (closest fit; could be `Category.SECRET` if you prefer)
- **target_types:** `["domain", "email"]`
- **requires_keys:** `[]` (GitHub token *optional* — improves results but not required)
- **What it does:** searches both sources for the target string, fetches paste content for top N matches, regex-scans for credential patterns (reuse the patterns from `cloud/github_actions_tool.py`).
- **Output shape:** `{"target": str, "paste_count": int, "pastes": [{"source": "psbdmp"|"github_gist", "id": str, "url": str, "leaked_secrets": [...], "context_excerpt": str (200 chars)}]}`
- **Pitfall:** psbdmp returns IDs only; you must fetch the paste body separately at `https://psbdmp.ws/api/dump/get/{id}`. Limit to top 20 pastes by default — these can be huge.

#### 1.3 `nexusrecon/tools/intel/ransomwatch_tool.py`

- **Source:** `https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json` (single ~5MB JSON file, updated every few hours).
- **Category:** `Category.INFRASTRUCTURE`
- **target_types:** `["domain"]`
- **requires_keys:** `[]`
- **What it does:** downloads posts.json, filters where `post_title` or `post_url` substring-matches the target domain or its derived org name. **Critical**: also derive a list of "company name" variants from the seed (e.g., `acme.com` → `acme`) and check those.
- **Output shape:** `{"target": str, "is_listed": bool, "listings": [{"group_name": str, "post_title": str, "discovered": str (ISO date), "url": str}], "list_check_date": str}`
- **Pitfall:** posts.json contains text like `"acme corp - leaked 50GB"`; case-insensitive substring match on the *org name* part of the domain catches more than just exact-domain match. Don't match on TLD-stripped name only — needs at least 4 chars to avoid false positives.

#### 1.4 `nexusrecon/tools/intel/ahmia_tool.py`

- **Source:** `https://ahmia.fi/search/?q={query}` — clearnet endpoint, returns HTML with `.onion` results.
- **Category:** `Category.INFRASTRUCTURE`
- **target_types:** `["domain"]`
- **requires_keys:** `[]`
- **What it does:** queries Ahmia for the target domain, parses the HTML for `.onion` URLs and snippet text. Use BeautifulSoup (already a project dependency).
- **Output shape:** `{"target": str, "result_count": int, "onion_results": [{"title": str, "onion_url": str, "snippet": str (300 chars)}]}`
- **Pitfall:** Ahmia results selector is `<li class="result">` containing `<h4><a>` for title and `<p>` for snippet. **Do not actually fetch the .onion URLs** — we're just *indexing* dark-web mentions, not crawling them. That's a separate ethical/legal question.

#### 1.5 `nexusrecon/tools/intel/certstream_tool.py`

- **Source:** `https://crt.sh/?q=%25.{domain}&output=json` — already used by crtsh_tool, but this variant **filters to certs issued in the last 7 days only**. The point is *recently issued* certs, which often signal new infrastructure or imminent phishing infrastructure.
- **Category:** `Category.CERTIFICATE`
- **What it does:** filters crt.sh results by `entry_timestamp > now - 7 days`. Adds typosquatting check: for each new cert, compute Levenshtein distance to seed domain and flag if `1 <= distance <= 3` (likely phishing infrastructure being prepared).
- **Output shape:** `{"target": str, "recent_certs": [...], "potential_phishing_infra": [{"domain": str, "edit_distance": int, "issued": str, "ca": str}]}`
- **Pitfall:** crt.sh's date format is awkward — use `python-dateutil`. The Levenshtein check needs `pip install python-Levenshtein` or implement directly (it's <30 lines).

### Wiring

```python
# nexusrecon/tools/identity/__init__.py
from . import holehe_tool

# nexusrecon/tools/intel/__init__.py
from . import pastebin_tool, ransomwatch_tool, ahmia_tool, certstream_tool
```

### Integration into pipeline

In `phase2_identity_cloud` of `nodes.py`: for each harvested email (after Hunter/theHarvester), call holehe and store under `email_intel["emails"][email]["registered_services"]`.

In `phase1_passive_footprinting`: after the existing subdomain block, call `ransomwatch`, `ahmia`, `pastebin`, `certstream` for each seed in parallel. Store results under `state["dark_intel"]` (new key — add to TypedDict).

### Acceptance criteria

- `nexusrecon tools` shows the 5 new tools.
- Running a campaign against a known-listed ransomware victim domain returns `is_listed: true`.
- holehe finds at least one match for a personal email known to be registered with major services.

---

## Move 2 — Credential Harvester

### Why it matters
This is the headline "credentials ready for you when you come back" feature. Right now we *discover*
exposed credential surfaces but never extract the actual credentials into a single deliverable.

### Architecture

Add a **new core module** `nexusrecon/core/credential_harvester.py` and a **new phase** `phase7_5_harvest`
between phases 7 and 8 (so scoring in phase 8 can include validated credentials).

### Files to create

#### 2.1 `nexusrecon/core/credential_harvester.py`

```python
@dataclass
class HarvestedCredential:
    cred_type: str  # "aws_access_key", "github_token", "database_url", "api_key", "password", "private_key"
    value_redacted: str  # first 4 chars + "***" + last 2 chars
    value_hash: str  # sha256 of full value (for evidence chain)
    source_url: str  # where it came from
    source_type: str  # "exposed_env" | "exposed_git" | "github_workflow" | "infostealer" | "code_leak"
    context: str  # one line of surrounding text (e.g., "DATABASE_URL=postgres://...")
    confidence: float  # 0.0–1.0
    validated: bool = False  # true if we confirmed it works (read-only check)
    validation_method: Optional[str] = None  # e.g., "aws sts get-caller-identity"
    validation_metadata: Dict[str, Any] = field(default_factory=dict)  # e.g., {"account_id": "...", "user_arn": "..."}
    next_steps: List[str] = field(default_factory=list)


async def harvest_credentials(state: Dict[str, Any], validate: bool = False) -> List[HarvestedCredential]:
    """
    Walk all intel sources, extract concrete credentials, optionally validate (read-only).
    `validate=False` by default — operator must opt in (config flag NEXUS_VALIDATE_CREDENTIALS=true).
    """
```

**Sources to harvest:**

1. **Exposed `.env` files** — from `state["infra_intel"][sub]["discovered_paths"]` where `path == "/.env"` and `status == 200`. Re-fetch the body, regex-parse `^([A-Z_][A-Z0-9_]*)=(.+)$` lines. Classify by name (KEY containing AWS, GITHUB, DATABASE, SECRET, etc.).

2. **Exposed `.git/config`** — same source, where `path == "/.git/config"`. Don't try to do full `git-dumper` here; that's intrusive (T3). Instead, fetch the config file and extract any embedded credentials in the `[remote]` URL (e.g., `https://user:token@github.com/...`).

3. **GitHub Actions leaks** — already structured in `state["code_intel"]["github_actions/{seed}"]["leaks"]`. Just consolidate.

4. **gitleaks/trufflehog** — `state["code_intel"]["gitleaks/{seed}"]["findings"]` — already structured.

5. **Infostealer hits** — `state["email_intel"]["emails"][em]["stealer_logs"]` and `state["breach_intel"][em]`. These contain account credentials with site/username/password — extract as `cred_type="password"` with `source_type="infostealer"`.

6. **Pastebin/gist leaks** (from Move 1) — `state["dark_intel"]["pastebin"]["pastes"][n]["leaked_secrets"]`.

### Credential classification regex set

```python
CRED_PATTERNS = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("aws_secret_key", r"(?i)aws.{0,20}?(?:secret|key).{0,20}?['\"]([0-9a-zA-Z/+]{40})['\"]"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("github_oauth", r"gho_[A-Za-z0-9]{36,}"),
    ("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("stripe_secret", r"sk_live_[A-Za-z0-9]{24,}"),
    ("private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("jwt", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("database_url", r"(?i)(?:postgres|mysql|mongodb)(?:\+\w+)?://[^:]+:[^@]+@[^/\s'\"]+"),
    ("generic_password", r"(?i)password['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
    ("generic_api_key", r"(?i)(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]"),
]
```

### Validation (gated behind config flag)

Only run when `state.get("validate_credentials") is True` (set via CLI flag `--validate-creds`).

- **AWS keys** — `boto3.client("sts").get_caller_identity()` — read-only, returns account ID. Do this in `asyncio.to_thread(...)` since boto3 isn't async.
- **GitHub tokens** — `GET https://api.github.com/user` with `Authorization: token {value}`.
- **Slack tokens** — `POST https://slack.com/api/auth.test` with `token={value}`.
- **JWTs** — decode with `jwt.decode(token, options={"verify_signature": False})` and report claims.

For everything else: `validated = False`, `next_steps` includes the manual verification command.

### Phase wiring

Add `phase7_5_harvest` to `nexusrecon/graph/nodes.py`:

```python
async def phase7_5_harvest(state: CampaignGraphState) -> CampaignGraphState:
    log.info("Phase 7.5: Credential harvest")
    state["current_phase"] = "phase7_5"
    creds = await harvest_credentials(state, validate=state.get("validate_credentials", False))
    state["harvested_credentials"] = [c.__dict__ for c in creds]
    state["completed_phases"] = list(state.get("completed_phases", [])) + ["phase7_5"]
    return state
```

Update the phase order in `route_to_next_phase()` and the graph builder.

### Report integration

Add `_harvested_credentials(state)` to `ReportEngine` in `engine.py`:
- Outputs `harvested_credentials.md` and `harvested_credentials.json`.
- Markdown groups by `source_type` then by `cred_type`, shows redacted value, source URL, validation status, next steps.
- **Header warning** at the top of the markdown: "⚠ This file contains real credentials. Treat as Secret. Rotate before sharing."

Update `_top_threads_to_pull()` to *also* surface validated credentials as standalone threads (category="harvested_credential", score=0.95 if validated, 0.7 if not).

### Acceptance criteria

- Phase 7.5 runs without error on a campaign with no exposed creds (returns empty list).
- Given a synthetic `.env` file with a fake AWS key, the harvester extracts and classifies it.
- `harvested_credentials.md` exists and is operator-readable.
- With `--validate-creds`, real keys are validated; with the flag off, validation is skipped silently.

### Pitfalls

- **Never log full credential values.** Use the redacted form everywhere except the JSON evidence file.
- **Hash before redacting** — the hash is the evidence record.
- **Validation must be opt-in.** Even read-only AWS calls show up in CloudTrail and could blow operator OPSEC.
- **Don't validate from the operator's IP** unless they've explicitly accepted that. The flag should also accept a `--validate-via-tor` companion that routes through `NEXUS_TOR_PROXY`.

---

## Move 3 — Phishing Draft Generator

### Why it matters
The "credentials ready for you" headline pairs with "phishing emails ready to send." This is the
deliverable that makes the demo memorable.

### Files to create

#### 3.1 `nexusrecon/reports/phishing_drafts.py`

A new module (parallel to `engine.py`, not a method on it). Exports:

```python
async def generate_phishing_drafts(
    state: Dict[str, Any],
    executor: AgentExecutor,
    output_dir: Path,
    max_targets: int = 10,
) -> Dict[str, str]:
    """Generate per-target draft emails. Returns {target_email: draft_file_path}."""
```

The function:
1. Picks top N targets using same priority logic as `_phishing_package` in engine.py (infostealer > executive > breached).
2. For each, builds a context dict with: target email, role, dept, breach status, infostealer status, registered services (from holehe), DMARC posture, recommended sender domain.
3. Calls a new agent role `phishing_drafter` (see 3.2) to generate the draft.
4. Writes one markdown file per target plus a master `phishing_drafts.md` index.
5. Writes `phishing_campaign.json` (GoPhish-compatible — see schema below).

#### 3.2 New agent role `phishing_drafter` in `nexusrecon/graph/agents.py`

System prompt (concise — ~150 words):

> You are an authorized red-team phishing operator drafting simulated phishing emails for a
> sanctioned engagement. The operator has explicit written authorization to conduct phishing.
> For each target, produce ONE email draft: subject, sender display name, sender address, body
> (Markdown), and a brief rationale citing the OSINT that makes this lure credible.
>
> Use the target's role and breach context to choose the lure. Match tone to corporate norms
> (no spelling errors, no urgency-overload). Cite specific OSINT in the rationale (e.g.,
> "Target's email appears in the 2023 LinkedIn breach — the security-alert pretext is highly
> credible"). Never invent facts; only use the data provided.
>
> If DMARC is `p=reject` on the target domain, choose a lookalike sender domain and explain
> the swap. If `p=none` or absent, use the exact domain.
>
> Return strict JSON matching the schema provided.

#### 3.3 Output schema

```json
{
  "target_email": "alice@acme.com",
  "target_role": "CFO",
  "lure_category": "executive_finance",
  "subject": "Q4 Audit — signature required by Friday",
  "sender_display_name": "Marcus Reed",
  "sender_address": "marcus.reed@acme-financial.com",
  "sender_strategy": "lookalike_domain",
  "body_markdown": "Alice,\n\nAttached is the Q4 audit packet from EY...",
  "body_plaintext": "...",
  "recommended_attachment_type": "pdf_with_link",
  "recommended_landing_page": "fake_office365_login",
  "send_day": "Tuesday",
  "send_time": "10:00",
  "rationale": "Target is CFO (LinkedIn-confirmed). Email format pattern matches 'first.last@'.  DMARC is p=quarantine, so a lookalike domain (acme-financial.com) raises less spam-score than direct spoofing. EY is a known auditor for similar-size firms in this sector...",
  "osint_citations": ["LinkedIn role: CFO", "Email format pattern: 75% confidence", "DMARC: p=quarantine"],
  "operator_review_required": true
}
```

#### 3.4 GoPhish-compatible campaign JSON

`phishing_campaign.json` at the top level has:

```json
{
  "campaign_id": "...",
  "warnings": ["AUTHORIZATION REQUIRED — verify scope before sending"],
  "templates": [
    {
      "name": "Q4 Audit", 
      "subject": "...", 
      "html": "...", 
      "text": "...",
      "envelope_sender": "marcus.reed@acme-financial.com"
    }
  ],
  "targets": [
    {"email": "alice@acme.com", "first_name": "Alice", "last_name": "...", "position": "CFO", "template": "Q4 Audit"}
  ],
  "landing_pages": [{"name": "fake_office365_login", "html": "..."}]
}
```

Note: do NOT include actual phishing-page HTML in `landing_pages` — emit the template *name* and a comment saying "operator must build the landing page; do not auto-generate functional credential-harvesting pages."

### Integration

Call from `_phishing_package()` in `engine.py` *after* the per-target pretext bundles section:

```python
# At the bottom of _phishing_package, before writing the file:
if state.get("generate_phishing_drafts"):
    drafts = asyncio.run(generate_phishing_drafts(state, executor, self.output_dir, max_targets=10))
    lines.append("\n## Generated Drafts\n")
    for target, path in drafts.items():
        lines.append(f"- [{target}]({Path(path).name})")
```

Gate behind `state["generate_phishing_drafts"]` (default `False`). Operator opts in via CLI flag `--generate-phishing`.

### Pitfalls

- **Authorization banner** — every generated draft file MUST start with:
  ```
  ⚠ AUTHORIZATION REQUIRED ⚠
  This file contains AI-generated phishing content for an authorized engagement only.
  Verify scope permits phishing simulations before sending. Do not send without operator review.
  ```
- **No payload generation.** Generate the email; do *not* generate exploit attachments or functional
  credential-harvesting landing pages. Only template names.
- **Draft per target, not per template.** It's tempting to batch all targets into one LLM call —
  don't. Per-target drafts are higher quality and let you cite per-target OSINT.
- **Rate-limit LLM calls** — `asyncio.Semaphore(3)` so we don't spike the Anthropic API. With 10
  targets that's still fast.
- **Cost** — 10 targets × ~2k tokens output × Sonnet pricing. Track via existing `llm_cost_usd`.

### Acceptance criteria

- `--generate-phishing` flag produces `phishing_drafts.md` + per-target `.md` files + `phishing_campaign.json`.
- Without the flag, no drafts are generated (no LLM calls made).
- Each draft includes the authorization banner.
- Schema validation: `phishing_campaign.json` parses as valid JSON with all required fields.
- Sender domain selection logic correctly differentiates `p=reject` (lookalike) vs `p=none` (direct).

---

## Move 4 — Make the Agent Loop Actually Agentic

### Why it matters
This is the architectural difference between "great aggregator" and "agentic platform."
Today, finding WordPress doesn't trigger WordPress-specific tooling — the next phase runs its
fixed list. We need the LLM to decide *what to run next* based on findings.

### Architecture decisions (PIN THESE)

- **Don't replace the phase pipeline.** Phases stay. We're inserting a *dynamic dispatcher* between
  phases that can run additional tools before progressing.
- **Two operating modes.** The dispatcher runs in `lite` mode by default (dispatches only after
  phases 1, 4, and 7 — the three "natural inflection points") or `full` mode (dispatches after every
  phase). Selected via `--dispatch-mode {lite|full}` CLI flag (default: `lite`). `--no-dynamic-dispatch`
  disables both.
- **Bounded autonomy.** Cap dynamic invocations at 5 per reflection cycle. Hard fail at 30 dynamic
  invocations across the whole campaign.
- **Use existing tools.** No new tool plumbing — the dispatcher routes through the existing
  `registry.execute()` path so scope/cache/audit still apply.
- **State pollution.** Dynamic tool results land in the same `*_intel` keys as their phase peers
  (e.g., a dynamically dispatched `wpscan` would land in `infra_intel` with key
  `dynamic/wpscan/{target}`).

### Files to create / modify

#### 4.1 `nexusrecon/graph/dynamic_dispatcher.py` (new)

```python
async def dispatch_dynamic_tools(
    state: CampaignGraphState,
    executor: AgentExecutor,
    max_dispatches: int = 5,
) -> List[Dict[str, Any]]:
    """
    Ask the LLM to pick 0–5 follow-up tools to run before the next phase.
    Returns list of {"tool": str, "target": str, "rationale": str, "result": ToolResult}.
    """
```

Steps:
1. Build a "findings summary" — last phase's key results, recent agent_messages, current entity counts.
2. Build a "tool catalog" — for each `registry.available_tools()`, include `name`, `description`,
   `category`, `tier`, `target_types`, and a new field `dynamic_trigger_hints` (see 4.2).
3. Call `executor.run_agent("dynamic_dispatcher", task_data={...})` with a prompt that returns
   a JSON list of `[{"tool": str, "target": str, "rationale": str}]` — empty list means "nothing
   useful to dispatch, proceed."
4. Validate each item: tool exists, target is non-empty, dispatch count is under cap.
5. Run them in parallel via `asyncio.gather(*(registry.execute(t["tool"], t["target"]) for t in plan))`.
6. Merge results back into appropriate state keys (heuristic: by tool category).
7. Return a record of what was dispatched + results.

#### 4.2 Add `dynamic_trigger_hints` to `OSINTTool`

In `nexusrecon/tools/base.py`:

```python
class OSINTTool(abc.ABC):
    ...
    dynamic_trigger_hints: List[str] = []  # e.g., ["WordPress detected", "wp-content found"]
```

Then add hints to high-leverage tools. Examples:
- `nuclei`: `["live HTTP service detected", "version banner exposed"]`
- `cms_detect`: `["unknown CMS, multiple framework hints"]`
- `subdomain_takeover` (Move 5): `["CNAME points to S3/Heroku/GitHub Pages", "404 with cloud provider header"]`
- `bucket_enum`: `["AWS detected", "S3 bucket name in JS"]`
- `holehe`: `["new email harvested", "executive email found"]`
- `harvested_credentials` validator: `["AWS key found in code", "GitHub token in .env"]`

Don't try to populate hints for every tool — focus on the top ~20 that benefit from triggered dispatch.

#### 4.3 New agent role `dynamic_dispatcher` in `agents.py`

System prompt:

> You are an OSINT campaign dispatcher. Given the recent findings and a catalog of available tools,
> decide which 0–5 tools to run next to follow up on the most promising leads.
>
> Prefer high-confidence, high-impact follow-ups: detected technology → tech-specific tooling;
> exposed credentials → validation; subdomain on takeover-prone CNAME → takeover check.
>
> Avoid: re-running tools that already ran; tools whose target_type doesn't match available targets;
> tools with prerequisites unmet (no key, no binary).
>
> Return strict JSON: a list of `{"tool": str, "target": str, "rationale": str}`. Empty list means
> "nothing useful to dispatch right now." Maximum 5 entries.

#### 4.4 Modify `reflection_node` in `nodes.py`

```python
LITE_DISPATCH_PHASES = {"phase1", "phase4", "phase7"}

async def reflection_node(state: CampaignGraphState) -> CampaignGraphState:
    # ... existing budget / hypothesis logic ...
    mode = state.get("dispatch_mode", "lite")  # "lite" | "full" | "off"
    if mode == "off":
        return state
    if mode == "lite" and state.get("current_phase") not in LITE_DISPATCH_PHASES:
        return state
    if len(state.get("dynamic_dispatch_log", [])) >= 30:
        log.warning("Global dispatch cap reached — skipping further dynamic dispatch")
        return state
    dispatched = await dispatch_dynamic_tools(state, _get_executor(), max_dispatches=5)
    state.setdefault("dynamic_dispatch_log", []).extend(dispatched)
    return state
```

CLI wiring: `--dispatch-mode lite|full` (default: `lite`); `--no-dynamic-dispatch` sets mode to `"off"`.

**Lite mode rationale:** phase 1 (post-passive footprinting — biggest finding density), phase 4
(post-correlation — confirmed leads ready for follow-up), phase 7 (post-vuln-correlation — CVEs
ready for exploit/template lookup). These are the three points where dynamic tooling adds the most
value per LLM call.

#### 4.5 Result-merge heuristic

```python
CATEGORY_TO_STATE_KEY = {
    Category.SUBDOMAIN: "subdomain_intel",
    Category.DNS: "domain_intel",
    Category.CERTIFICATE: "domain_intel",
    Category.EMAIL: "email_intel",
    Category.IDENTITY: "identity_intel",
    Category.BREACH: "breach_intel",
    Category.CLOUD: "cloud_intel",
    Category.CLOUD_AWS: "cloud_intel",
    Category.CLOUD_AZURE: "cloud_intel",
    Category.CLOUD_GCP: "cloud_intel",
    Category.CODE: "code_intel",
    Category.SECRET: "code_intel",
    Category.INFRASTRUCTURE: "infra_intel",
    Category.WEB: "infra_intel",
    Category.VULNERABILITY: "vuln_intel",
    Category.PRETEXT: "pretext_intel",
    Category.MOBILE: "mobile_intel",  # new key — add to TypedDict
    Category.SOCIAL: "social_intel",
}
```

Each dispatched tool's result lands at `state[mapping[tool.category]][f"dynamic/{tool.name}/{target}"]`.

### Cost / safety

- Add CLI flag `--no-dynamic-dispatch` to disable. Default ON.
- Dispatcher LLM calls go through the existing cost tracker (`state["llm_cost_usd"]`).
- If a dynamic tool fails, log it but don't halt — the pipeline must remain robust.
- Loops: track `(tool, target)` pairs already dispatched; deduplicate.

### Acceptance criteria

- Dispatcher runs after each phase; without findings, returns empty plan.
- Given a state with `cms_detect` reporting WordPress, the dispatcher chooses `nuclei` with
  WordPress-relevant context.
- Cap enforcement works: 6th dispatch in one cycle is rejected, 31st global dispatch is rejected.
- Disabling via flag bypasses LLM call entirely.
- Dynamically dispatched tool results appear in the correct `*_intel` state slots and are visible
  in the final report.

### Pitfalls

- **JSON parsing.** LLMs return malformed JSON sometimes. Wrap in try/except and treat parse failure
  as "empty plan" — don't crash the campaign.
- **Tool name hallucination.** Always validate `tool` against `registry.available_tools()` before
  dispatching.
- **Target type mismatch.** A tool with `target_types=["cve"]` shouldn't be dispatched against a
  domain — validate before invoking.
- **Cost amplification.** Each phase now costs +1 LLM call minimum. Make sure caching is hit on
  consecutive runs.

---

## Move 5 — Quick Wins (Subdomain Takeover, WAF, sslyze, Mobile)

### Why it matters
These are 1–2 hour adds each but their absence is conspicuous to reviewers. Bundle as one move.

### Tools to create

#### 5.1 `nexusrecon/tools/web/subdomain_takeover_tool.py`

- **Approach:** pure-Python — for each subdomain, resolve CNAME, check against a known-fingerprint
  table, then HTTP-probe for the takeover signature.
- **Tier:** T1 (passive lookup + non-intrusive HTTP GET).
- **Category:** `Category.WEB`
- **Implementation:**
  ```python
  TAKEOVER_FINGERPRINTS = [
      {"service": "S3 Bucket", "cname_contains": "s3.amazonaws.com", "body_contains": "NoSuchBucket"},
      {"service": "GitHub Pages", "cname_contains": "github.io", "body_contains": "There isn't a GitHub Pages site here"},
      {"service": "Heroku", "cname_contains": "herokuapp.com", "body_contains": "No such app"},
      {"service": "Azure", "cname_contains": ".azurewebsites.net", "body_contains": "404 Web Site not found"},
      {"service": "Shopify", "cname_contains": "myshopify.com", "body_contains": "Sorry, this shop is currently unavailable"},
      {"service": "Fastly", "cname_contains": "fastly.net", "body_contains": "Fastly error: unknown domain"},
      {"service": "Tumblr", "cname_contains": "tumblr.com", "body_contains": "There's nothing here"},
      {"service": "Unbounce", "cname_contains": "unbouncepages.com", "body_contains": "The requested URL was not found on this server"},
      {"service": "Bitbucket", "cname_contains": "bitbucket.io", "body_contains": "Repository not found"},
      {"service": "Cargo", "cname_contains": "cargocollective.com", "body_contains": "404 Not Found"},
      {"service": "Pantheon", "cname_contains": "pantheonsite.io", "body_contains": "The gods are wise"},
      {"service": "Zendesk", "cname_contains": "zendesk.com", "body_contains": "Help Center Closed"},
      {"service": "Surge", "cname_contains": "surge.sh", "body_contains": "project not found"},
  ]
  ```
- **Input:** target is a domain (the seed); tool internally iterates `state.get("subdomain_intel", {}).keys()` via `kwargs.get("subdomains")`.
- **Output shape:** `{"target": str, "vulnerable": [{"subdomain": str, "service": str, "cname": str, "evidence": str}], "tested_count": int}`
- **Pitfall:** must dnspython-resolve CNAME (not A); fall back to dig if dnspython isn't installed (it's already a dep). Use a `Semaphore(20)` for concurrency.

#### 5.2 `nexusrecon/tools/web/wafw00f_tool.py`

- **Approach:** pure-Python WAF detection via response signature matching.
- **Tier:** T1
- **Category:** `Category.WEB`
- **Implementation:** ~30 known WAF signatures (Cloudflare, AWS WAF, Akamai, Imperva, Sucuri, F5,
  ModSecurity, Wordfence, etc.). Send a benign request, then a deliberately-malicious request like
  `GET /?q=<script>alert(1)</script>`, compare responses. WAF presence reveals itself in headers
  (`server`, `x-cdn`, `x-sucuri-id`) and response codes (403/406 + canonical body strings).
- **Output:** `{"target": str, "wafs_detected": [{"name": str, "confidence": float, "evidence": str}]}`
- **Reference:** the `wafw00f` Python package fingerprints (~150 lines, BSD-licensed) — port the
  signature table; don't depend on the package itself (it's GPL-tainted in some forks).

#### 5.3 `nexusrecon/tools/web/sslyze_tool.py`

- **Approach:** use the `sslyze` Python library (`pip install sslyze`) — already on PyPI.
- **Tier:** T1 (TLS handshake is non-intrusive but does touch the server)
- **Category:** `Category.WEB`
- **Implementation:**
  ```python
  from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
  from sslyze.plugins.scan_commands import ScanCommand
  
  scanner = Scanner()
  scanner.queue_scans([ServerScanRequest(
      server_location=ServerNetworkLocation(hostname=target, port=443),
      scan_commands={ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES,
                     ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES,
                     ScanCommand.TLS_1_2_CIPHER_SUITES, ScanCommand.TLS_1_3_CIPHER_SUITES,
                     ScanCommand.HEARTBLEED, ScanCommand.ROBOT, ScanCommand.OPENSSL_CCS_INJECTION,
                     ScanCommand.CERTIFICATE_INFO, ScanCommand.TLS_COMPRESSION},
  )])
  for result in scanner.get_results():
      ...
  ```
- **Sslyze API is sync, not async** — wrap in `asyncio.to_thread(...)`.
- **Output:** `{"target": str, "supported_protocols": [...], "weak_ciphers": [...], "vulnerabilities": ["heartbleed"|"robot"|"ccs_injection"], "cert_chain": {...}, "grade": "A"|"B"|"C"|"F"}`
- **Pitfall:** sslyze ships a heavy dependency (cryptography). It's already in the project's
  dependency tree, so no new install.

#### 5.4 `nexusrecon/tools/mobile/playstore_tool.py` (new category dir)

- **Approach:** use `google-play-scraper` (`pip install google-play-scraper`).
- **Tier:** T0
- **Category:** `Category.MOBILE`
- **target_types:** `["domain"]` — derive company/app names from the seed, search Play Store.
- **Implementation:** search Play Store for company name, return matching apps with package names,
  developer info, install counts, last update.
- **Output:** `{"target": str, "apps": [{"package": str, "title": str, "developer": str, "developer_email": str, "install_count": int, "url": str, "last_updated": str}]}`
- **Pitfall:** the library is sync — wrap in `asyncio.to_thread`. Search is fuzzy and noisy;
  filter results where `developer_email` domain matches the seed domain or app `title` substring-matches the org name.

#### 5.5 `nexusrecon/tools/mobile/apk_analyzer_tool.py`

- **Approach:** for each app discovered by playstore_tool, download the APK from APKMirror
  (default), unzip, and run apkleaks-style regex scanning over `.smali`, `strings.xml`,
  `AndroidManifest.xml`, and any embedded JS/JSON.
- **Tier:** T1 (downloading the APK is HTTP traffic against APKMirror, not the target).
- **Category:** `Category.MOBILE`
- **target_types:** `["package"]` — takes a Play Store package name, not a domain.
- **Default source: APKMirror.** Search `https://www.apkmirror.com/?post_type=app_release&searchtype=apk&s={package}`,
  parse the result HTML for the latest stable variant, follow to the download page, follow to the
  signed direct-download URL. APKMirror has rate limits (~1 req/sec per IP) and serves community
  uploads, not Google-canonical builds.
- **Mandatory warning** emitted in the tool's `ToolResult.metadata["warnings"]` and surfaced in
  every report that references APK findings:
  > ⚠ APK fetched from APKMirror (third-party mirror). The build may differ from the production
  > Play Store version. Verify checksum against an authoritative source before relying on findings
  > for client deliverables. APKMirror downloads are subject to their ToS; verify your engagement
  > scope permits third-party APK retrieval.
- **Fallback chain:** APKMirror → APKPure → metadata-only mode (no download). Each fallback
  emits its own warning in `ToolResult.metadata["warnings"]`. If all sources fail, return
  `success=True` with empty `extracted_*` fields and `warnings` populated — don't error out.
- **Secret extraction patterns:** reuse `CRED_PATTERNS` from `core/credential_harvester.py`
  (Move 2). Plus mobile-specific: Firebase URLs (`https://[a-z0-9-]+\.firebaseio\.com`),
  Google API keys (`AIza[0-9A-Za-z_-]{35}`), hardcoded JWT secrets, S3 bucket references.
- **APK unzip:** stdlib `zipfile` is enough — APKs are zip files. For `.dex` decoding, defer to
  metadata-only mode unless `androguard` is available; check `importlib.util.find_spec("androguard")`
  and degrade gracefully.
- **Output:** `{"package": str, "version": str, "source": "apkmirror"|"apkpure"|"metadata_only", "warnings": [str], "extracted_secrets": [...], "extracted_endpoints": [...], "permissions": [...], "third_party_libs": [...], "checksum_sha256": str|None}`
- **Pitfall:** APKMirror's HTML changes occasionally — wrap parsing in try/except and degrade to
  next fallback. Don't write the APK to a long-lived path; use `tempfile.TemporaryDirectory()` and
  clean up. Cap APK size at 200MB before downloading (`HEAD` first, check `Content-Length`).

### Wiring

```bash
mkdir -p nexusrecon/tools/mobile
```

Create `nexusrecon/tools/mobile/__init__.py`:
```python
"""Mobile app reconnaissance tools."""
from . import playstore_tool, apk_analyzer_tool
```

Update `nexusrecon/tools/__init__.py` to also import `from . import mobile`.

Update the verification import block to include mobile.

### Integration into pipeline

- **subdomain_takeover** + **wafw00f** + **sslyze** — run in `phase5_light_active` for top 50 subdomains.
- **playstore** — run in `phase2_identity_cloud` (it's pretext/identity-adjacent for the org).
- **apk_analyzer** — only runs via dynamic dispatcher (Move 4) when playstore finds apps.

### Acceptance criteria

- Subdomain takeover correctly flags a known-vulnerable test domain (e.g., set up a
  `test.yourdomain.com` CNAME pointing to a non-existent S3 bucket).
- wafw00f correctly identifies Cloudflare on a known Cloudflare-fronted site.
- sslyze produces a TLS report with grade for any HTTPS endpoint.
- playstore returns a non-empty list for a major brand domain.
- All 5 tools register cleanly (`nexusrecon tools` shows them).

---

## Sequencing & Dependency Map

```
Move 1 (Coverage) ─┐
                   ├─ independent — can ship in any order, but Move 1 should land FIRST
                   │  because Move 2 and 3 benefit from holehe data and pastebin creds
Move 5 (Quick adds) ┘
                   
Move 2 (Credentials) ─── depends on Move 1 (pastebin creds), best after Move 1
                          
Move 3 (Phishing drafts) ── depends on Move 1 (holehe context for richer drafts)
                              and Move 2 (validated creds inform some pretexts)
                              
Move 4 (Agentic loop) ── depends on Move 5 (more triggerable tools = better dispatch)
                          best done LAST so the dispatcher can choose from a fuller catalog
```

**Recommended order:** 1 → 5 → 2 → 3 → 4.

---

## Global Verification Checklist

After each move:

```bash
cd /Users/waifumachine/agentic-osint

# 1. All Python compiles
python3 -m py_compile $(find nexusrecon -name '*.py')

# 2. All tools register (update import list to include new categories)
python3 -c "
import nexusrecon.tools.domain, nexusrecon.tools.pretext, nexusrecon.tools.cloud
import nexusrecon.tools.intel, nexusrecon.tools.web, nexusrecon.tools.vuln
import nexusrecon.tools.identity
# import nexusrecon.tools.mobile  # uncomment after Move 5
from nexusrecon.tools.registry import get_registry
reg = get_registry()
print(f'Total registered: {len(list(reg._tools.values()))}')
print(f'Available: {len(reg.available_tools())}')
"

# 3. CLI lists new tools
nexusrecon tools | grep -i {new_tool_name}

# 4. Smoke test against a known target (the operator's lab, NOT a third party)
nexusrecon run --seeds testlab.local --max-tier T1 --no-dynamic-dispatch  # for moves 1, 2, 5
nexusrecon run --seeds testlab.local --max-tier T1 --generate-phishing    # for move 3
nexusrecon run --seeds testlab.local --max-tier T1                        # for move 4 (full)
```

---

## Resolved Operator Decisions

These were resolved by the operator before implementation began. Sonnet should treat them as
binding constraints:

1. **Phishing drafts ship in OSS.** The draft generator (Move 3) is included in the public
   distribution. The mandatory authorization banner stays as the only gating mechanism.
   Misuse risk is accepted. **Do not** add commercial-only flags, EULA prompts, or signature checks.

2. **`--validate-creds` ships in the public version.** Implement as specified in Move 2.
   The opt-in flag and `--validate-via-tor` companion are both in scope.

3. **Two dispatch modes — `lite` is default.** Implement as specified in Move 4.4:
   `--dispatch-mode lite` runs the dynamic dispatcher only after phases 1, 4, 7 (default);
   `--dispatch-mode full` runs after every phase; `--no-dynamic-dispatch` disables.

4. **APKMirror is the default APK source — with mandatory warning.** Implement the fallback
   chain in Move 5.5: APKMirror → APKPure → metadata-only. Every report that surfaces APK
   findings must include the warning verbatim from the spec. Operators are not gated; they are
   informed.

---

## Estimated Effort (Sonnet 4.6 working autonomously)

- Move 1: ~2 hours (5 tools, each ~30 min)
- Move 2: ~3 hours (new module, validation logic, phase wiring, report integration)
- Move 3: ~2 hours (new agent role, draft generation, GoPhish JSON)
- Move 4: ~4 hours (new module, agent role, reflection rewiring, hint plumbing, end-to-end test)
- Move 5: ~3 hours (5 tools, sslyze integration is the only finicky one)

**Total: ~14 hours of autonomous Sonnet work**, assuming clean runs and no architecture pivots.

Budget for ~30% rework due to LLM JSON parsing edge cases, hidden state-shape mismatches, and the
inevitable dependency-version friction.
