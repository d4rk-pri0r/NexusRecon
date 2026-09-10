# Fixtures: provider OAuth CLI backends (`nexusrecon/llm`)

Placeholder-only fixtures for the provider-OAuth adapters. These files
represent the **stdout/stderr contract** NexusRecon parses when it delegates
inference to each provider's maintained official CLI. No real auth documents,
tokens, credentials, or private keys live here — every identifier, session id,
and key-shaped value is an explicit `PLACEHOLDER`.

## Upstream contracts each fixture represents

| File | Represents | Upstream contract |
| --- | --- | --- |
| `codex_success.jsonl` | `codex exec --json` success NDJSON | OpenAI Codex CLI JSON-lines event stream: `item.completed` carrying the final `item.type=agent_message` text, then `turn.completed` carrying `usage`. See <https://developers.openai.com/codex/noninteractive> and <https://github.com/openai/codex/blob/main/docs/exec.md>. |
| `codex_auth_error.jsonl` | `codex exec --json` auth failure NDJSON | `turn.failed` event whose `error.message` names the failed authentication. Shape per the same codex exec-json schema as `codex_success.jsonl`. |
| `claude_success.json` | `claude --safe-mode -p --output-format json` success envelope | Claude Code headless `result` envelope: `type/subtype/result/usage`. See <https://mintlify.wiki/VineeTagarwaL-code/claude-code/reference/sdk/overview> (output formats + result message) and Claude Code headless docs for `--output-format json`. |
| `claude_auth_error.json` | Claude Code auth-failure result envelope | `is_error: true` result envelope surfacing an authentication failure that must be redacted before it reaches the operator. |
| `grok_success.json` | `grok --output-format json` success object | xAI Grok Build headless single-JSON result: `text` + `usage`. See <https://docs.x.ai/build/cli/headless-scripting> and <https://github.com/xai-org/grok-build> `14-headless-mode.md`. |
| `grok_auth_error.txt` | `grok --output-format json` failure stderr | Grok Build non-zero-exit stderr text naming the failed authentication. The binary emits human text to stderr on auth failure; NexusRecon surfaces it sanitized. |

## Notes for maintainers

- Keep values placeholder-shaped. If the upstream CLI changes a field, update
  the fixture **and** the parser contract in `nexusrecon/llm/cli_backend.py`
  together, and note the CLI version observed.
- Auth-error fixtures may contain explicitly fake key-shaped placeholders so
  integration tests prove sanitizer behavior without real credentials. JWT
  redaction is covered with constructed values in the unit suite rather than
  token-shaped fixture text. Never replace a placeholder with a real value.
