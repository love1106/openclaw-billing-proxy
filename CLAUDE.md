# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Zero-dependency Node.js HTTP proxy that sits between OpenClaw and `api.anthropic.com` to route requests through a Claude Max/Pro subscription instead of Extra Usage billing. See `README.md` for user-facing docs and the full rationale.

## Commands

- Run proxy: `node proxy.js [--port 18801] [--config config.json] [--host 0.0.0.0]`
- Interactive setup (auto-detects OpenClaw tools, writes `config.json`): `node setup.js`
- Diagnostics (8-layer health check — credentials, token, API, billing header, trigger detection, proxy health, e2e): `node troubleshoot.js`
- Health endpoint: `curl http://127.0.0.1:18801/health`
- Docker: `docker compose up -d` (mounts `$HOME/.claude` into the container for credentials)

No package.json, no dependencies, no build step, no test suite. Node 18+ required.

## Architecture

Single-purpose middleware with three coordinated concerns. Understanding all three is required before touching `proxy.js`:

1. **Billing header injection** — Anthropic's API checks the system prompt for an 84-char `x-anthropic-billing-header` string (`BILLING_BLOCK` in `proxy.js`). Without it, OAuth requests bill to Extra Usage. Proxy injects this block into the outbound request's system prompt array.

2. **OAuth token swap** — Reads Claude Code's OAuth token fresh from `~/.claude/.credentials.json` on every request (token rotates ~24h). Must strip UTF-8 BOM before `JSON.parse` (see v1.4.1 fix — editors/auto-refresh can reintroduce the BOM). On macOS, token may live in Keychain instead; proxy checks both `~/.claude/.credentials.json` and `~/.claude/credentials.json`.

3. **Bidirectional sanitization** — Anthropic runs a streaming classifier that refuses requests containing specific trigger phrases (`OpenClaw`, `sessions_*` tool names, `HEARTBEAT_OK`, `running inside`). The proxy:
   - **Outbound**: applies `replacements` (raw string replace on request body) to hide triggers.
   - **Inbound**: applies `reverseMap` per SSE chunk to restore original tool names/paths before OpenClaw sees them. Without reverse mapping the model would emit `.ocplatform/` paths that don't exist on disk.

   Every `replacements` entry MUST have a matching `reverseMap` entry. Replacements must be **space-free** (e.g., `ocplatform`, not `assistant platform`) or filesystem paths break inside tool calls.

`REQUIRED_BETAS` in `proxy.js` lists the Anthropic beta flags that must be forwarded for OAuth + Claude Code features to work; keep this list in sync with what Claude Code CLI sends.

## Files

- `proxy.js` — the entire proxy (HTTP server, credential loader, SSE stream rewriter, replacement engine). Defaults live at the top (`BILLING_BLOCK`, `REQUIRED_BETAS`, `DEFAULT_REPLACEMENTS`, `DEFAULT_REVERSE_MAP`).
- `setup.js` — interactive config generator; scans the local OpenClaw install to detect `sessions_*` tool names the user's version exposes.
- `troubleshoot.js` — layered diagnostic; preferred first step when debugging user reports.
- `config.json` / `config.example.json` — user-overridable `port`, `credentialsPath`, `replacements`, `reverseMap`.
- `scripts/start.sh`, `scripts/stop.sh` — process wrappers; `scripts/proxy.log` is the runtime log.
- `Dockerfile` / `docker-compose.yml` — Alpine + Node 20 + globally installed `@anthropic-ai/claude-code` (the CLI is kept in the image so an in-container refresher can rotate credentials).

## Modification notes

- When adding a new trigger phrase, update **both** `DEFAULT_REPLACEMENTS` and `DEFAULT_REVERSE_MAP` in `proxy.js`, and mirror the change in `README.md`'s "How Anthropic's Detection Works" list.
- Streaming response rewriting happens per SSE chunk — any new sanitization must be chunk-boundary safe (don't assume a phrase lands in a single chunk).
- Don't add dependencies. Zero-dep is a hard project constraint so the proxy runs anywhere Node runs.
