# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**Subscription-billing arbitrage proxy.** Zero-dependency Node.js HTTP server that sits between **OpenClaw** (a third-party AI runtime) and **`api.anthropic.com`**. OpenClaw normally hits Anthropic as an API client and gets billed per-token via **Extra Usage**. Claude Code (Anthropic's official CLI) gets billed against your flat-rate **Claude Max/Pro subscription**. The proxy makes OpenClaw traffic look like Claude Code traffic so Anthropic bills it against the subscription instead.

Point OpenClaw at `http://127.0.0.1:18801` (its `baseUrl` / API endpoint config), run the proxy, done. Requires an active `claude auth login` session on the host — OAuth tokens are sourced fresh from `~/.claude/.credentials.json` per request.

See `README.md` for user-facing docs. See `docs/operations/weekly-review.md` for production monitoring.

## Commands

- Run proxy: `node proxy.js [--port 18801] [--config config.json] [--host 0.0.0.0]`
- Run with logging + hourly token refresh: `node -r ./proxy-logger.js proxy.js`
- Interactive setup (auto-detects OpenClaw tools, writes `config.json`): `node setup.js`
- Diagnostics (8-layer health check — credentials, token, API, billing header, trigger detection, proxy health, e2e): `node troubleshoot.js`
- Health endpoint: `curl http://127.0.0.1:18801/health` — token expiry + counters
- Metrics endpoint: `curl http://127.0.0.1:18801/metrics` — detailed request/detection counters
- Weekly log review: `node scripts/analyze-logs.js [--days 7]`
- Unit tests: `node --test tests/`
- Docker: `docker compose up -d` (mounts `$HOME/.claude` into the container for credentials)

Node 18+ required. Zero runtime deps.

## Architecture

Seven defense layers against Anthropic's CC/OC classifier stack. Every layer is required — the v1.x string-only approach stopped working **April 8, 2026** when Anthropic upgraded from string matching to tool-name fingerprinting and template detection.

1. **Billing header injection** — Anthropic's API checks the system prompt for an 84-char `x-anthropic-billing-header` identifier. Without it, OAuth requests bill to Extra Usage. Proxy computes a dynamic SHA256 fingerprint (`BILLING_HASH_SALT` + indexed chars of the first user message + CC version) and injects it into the outbound system prompt array. See `computeBillingFingerprint` in `proxy.js`.

2. **OAuth token swap** — Reads Claude Code's OAuth token fresh from `~/.claude/.credentials.json` on every request (token rotates ~24h). `proxy-logger.js` runs an hourly `claude -p ping` to keep it fresh. UTF-8 BOM is stripped before `JSON.parse` (editors reintroduce it). On macOS, checks Keychain services (`Claude Code-credentials`, `com.anthropic.claude-code`, etc.). Docker: `OAUTH_TOKEN` env var takes precedence.

3. **String trigger sanitization** (Layer 2) — Outbound split/join over the raw body (`DEFAULT_REPLACEMENTS`) rewrites phrases Anthropic's classifier flags as OC-specific: `OpenClaw`, `sessions_*`, `HEARTBEAT_OK`, `running inside`, `Prometheus`, `clawhub`, etc. Replacements must be **space-free** (`ocplatform`, not `assistant platform`) or filesystem paths break inside tool calls.

4. **Tool-name fingerprint bypass** (Layer 3) — `DEFAULT_TOOL_RENAMES` rewrites quoted OC tool names (`"exec"` → `"Bash"`, `"sessions_spawn"` → `"TaskCreate"`, etc.) to Claude Code's PascalCase convention. Detection checks the *set* of tool names, not just presence of individual triggers, so this must be comprehensive.

5. **System prompt template strip** (Layer 4) — Rips out OC's ~28K-char config block between the identity marker (`You are a personal assistant`) and the first workspace doc header (`\n## /` or `\n## C:\`), replaces with a brief paraphrase. The template itself is fingerprintable.

6. **Tool description + property renames** (Layers 5 & 6) — Strips `"description"` fields from all tool schemas and renames OC-specific schema properties (`session_id` → `thread_id`, `agent_id` → `worker_id`, etc.) to reduce fingerprint signal. Also injects CC tool stubs via `CC_TOOL_STUBS` to make the tool set shape match a real CC session.

7. **Full bidirectional reverse mapping** (Layer 7) — On SSE responses, unwinds every tool rename, property rename, and string replacement **per content block**, with cross-chunk holdback buffering (`HOLDBACK = max(reverseMap.pattern.length)`) so a sanitized token that spans two delta chunks still gets reversed. Both plain (`"Name"`) and escaped (`\"Name\"`) forms are handled because `input_json_delta` embeds tool args with escaped inner quotes. JSON (non-SSE) responses go through a single-pass `reverseMap` call. Thinking/redacted_thinking blocks are masked before any transform and restored byte-identical — Anthropic enforces byte-equality on the latest assistant message.

### Invariants

- Every `replacements` entry MUST have a matching `reverseMap` entry (outbound needs its inverse on inbound).
- Every `toolRenames` / `propRenames` entry reverses automatically in both quoted forms — don't maintain a separate reverse table for those.
- Thinking blocks go through unmodified. Never apply a transform that could touch them.
- `REQUIRED_BETAS` must stay in sync with what the Claude Code CLI sends (grep the CC source; the list changes when Anthropic ships new beta flags).
- `CC_VERSION` should be bumped when Anthropic rejects the current value. Billing fingerprint depends on it.

### Failure modes to watch

| Symptom | Likely cause | Check |
|---------|--------------|-------|
| 400 w/ `extra usage` in body | Billing header missing or stale | `/metrics` detection counter, `scripts/proxy.log` for `DETECTION!` |
| 400 w/ `Input tag 'X' found using 'type'` | Stale renamed content type in OC cache | `proxy-logger.js` `CONTENT_TYPE_FIXES` |
| 400 w/ `unexpected tool_use_id` | Orphaned tool_result after OC compaction | `proxy-logger.js` `stripOrphanedToolResults` |
| 400 w/ `thinking ... cannot be modified` | Transform mutated a thinking block | `maskThinkingBlocks` coverage gap |
| Tool-not-found loops client-side | Phantom stub the model called with no backing impl | `CC_TOOL_STUBS` hygiene (e.g. don't include `Agent`) |
| 401 | OAuth token expired and refresher failed | `claude auth login`; check refresher logs |
| Classifier catches a new phrase | Anthropic updated triggers | Binary-search request body, add to `DEFAULT_REPLACEMENTS` + `DEFAULT_REVERSE_MAP` |

## Files

- `proxy.js` — upstream proxy (HTTP server, credential loader, SSE stream rewriter, replacement engine). Defaults live at the top (`BILLING_BLOCK`, `REQUIRED_BETAS`, `DEFAULT_REPLACEMENTS`, `DEFAULT_REVERSE_MAP`). Exports pure transform functions (`processBody`, `reverseMap`, etc.) when required as a module — the HTTP server only boots when the file is run directly (`require.main === module`). Edit directly when fixing bugs; upstream is abandoned.
- `proxy-logger.js` — Node preload module (`node -r ./proxy-logger.js proxy.js`) for concerns that must wrap runtime I/O:
  - Request body logging to `logs/prompts-YYYY-MM-DD.jsonl`
  - `PROXY_HOST` env var bind override (0.0.0.0 for Docker/VM)
  - Hourly OAuth token refresh via `claude -p ping`
  - Outbound body patching (`CONTENT_TYPE_FIXES`) for stale renamed content types (e.g. `ImageGen` → `image`)
- `tests/` — Node built-in `node:test` unit tests for the transform pipeline (`node --test tests/`).
- `setup.js` — interactive config generator; scans the local OpenClaw install to detect `sessions_*` tool names the user's version exposes.
- `troubleshoot.js` — layered diagnostic; preferred first step when debugging user reports.
- `config.json` / `config.example.json` — user-overridable `port`, `credentialsPath`, `replacements`, `reverseMap`.
- `scripts/start.sh`, `scripts/stop.sh` — process wrappers; `scripts/proxy.log` is the runtime log (stdout/stderr sink).
- `scripts/analyze-logs.js` — weekly-review log analyzer. Scans `scripts/proxy.log` + `logs/prompts-*.jsonl` for detection events, status-code distribution, trigger leakage into bodies, token expiry warnings. Zero deps.
- `docs/operations/weekly-review.md` — operator checklist + triage tree.
- `Dockerfile` / `docker-compose.yml` — Alpine + Node 20 + globally installed `@anthropic-ai/claude-code` (the CLI is kept in the image so an in-container refresher can rotate credentials).

## Modification notes

- Upstream `zacdcook/openclaw-billing-proxy` is abandoned. Fix bugs wherever they live — no need to keep `proxy.js` pristine. Ship a test alongside every fix.
- Every `replacements` entry needs a matching `reverseMap` entry. Mirror new trigger phrases in `README.md`'s "How Anthropic's Detection Works" list.
- `CC_TOOL_STUBS` is decoy camouflage, not a tool registry. Only include names the model is unlikely to actually call — stubs with appealing names (`Agent`, `Task`) get invoked and fail because they have no backing implementation or reverse mapping. Real OC tools get renamed via `DEFAULT_TOOL_RENAMES` instead.
- `CONTENT_TYPE_FIXES` in `proxy-logger.js` handles stale renamed content block types (e.g. `ImageGen` → `image`) surviving in OpenClaw's conversation cache from older proxy versions.
- Streaming response rewriting happens per SSE chunk — any new sanitization must be chunk-boundary safe (don't assume a phrase lands in a single chunk). The per-content-block accumulator in `startServer` handles this; mirror that approach.
- Don't add runtime dependencies. Zero-dep is a hard project constraint so the proxy runs anywhere Node runs. Tests use Node's built-in `node:test`.
- Git remotes: `origin` = love1106 fork (push/pull), `upstream` = zacdcook original (abandoned).
