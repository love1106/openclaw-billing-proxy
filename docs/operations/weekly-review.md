# Weekly Review — Billing Proxy Health

One 10-minute session per week. Catches classifier regressions before they
silently start billing Extra Usage, and catches credential/refresh failures
before the proxy stops serving.

## When to run

Every Monday morning, or whenever a user reports sudden cost spikes / auth
errors. Also run immediately after:

- Claude Code CLI version bump (`REQUIRED_BETAS` may have changed)
- OpenClaw update (new tool names or system prompt format)
- Any 4xx spike noticed in Anthropic billing dashboard

## Step 1 — Run the analyzer

```bash
cd /workspace/openclaw-billing-proxy
node scripts/analyze-logs.js --days 7
```

Exit code convention:
- `0` — clean, proceed to step 3
- `2` — anomalies detected (detections, > 10 upstream errors, refresh spawn failures, or trigger leakage). Proceed to step 2.
- `1` — script crashed. Check `logs/` and `scripts/proxy.log` exist.

For machine consumption:

```bash
node scripts/analyze-logs.js --json > /tmp/proxy-weekly.json
```

## Step 2 — Triage by signal

### DETECTION events > 0

A 400 response containing `extra usage` means Anthropic's classifier rejected
the request as non-CC. Root causes, in order of likelihood:

1. **New trigger phrase** — Anthropic shipped a new classifier rule.
   - Replay a failing body (captured in `logs/prompts-*.jsonl` by `reqNum`).
   - Binary-search the body: halve, halve again until the smallest failing
     slice is isolated. The differentiating token is the new trigger.
   - Add to `DEFAULT_REPLACEMENTS` AND `DEFAULT_REVERSE_MAP` in `proxy.js`.
   - Ship a test.
2. **CC_VERSION stale** — Anthropic rejected the version in the billing
   fingerprint. Bump `CC_VERSION` in `proxy.js:40` to the latest CC CLI version.
3. **REQUIRED_BETAS drift** — CC CLI added a new beta flag. Grep the CC
   source, sync the list at `proxy.js:51`.
4. **Missing reverse map entry** — check `LEAKAGE_PATTERNS` hits in the same
   report; if a trigger leaked, add the missing entry.

### Trigger leakage > 0

A trigger phrase appeared in the post-sanitization body logged to
`logs/prompts-*.jsonl`. Means `DEFAULT_REPLACEMENTS` missed it. Add the
missing entries (both outbound replacement + inbound reverseMap) and ship
a test.

### Upstream errors > 10 / week

ETIMEDOUT or similar network failures. Check Anthropic status page. If
persistent, check outbound connectivity from the proxy host
(`curl -v https://api.anthropic.com/v1/messages` should 401, not timeout).

### Refresh spawn failures > 0

`claude -p ping` couldn't spawn. Causes: `claude` not in `PATH`, node not
installed inside the Docker image, filesystem perms on `~/.claude`. Fix and
restart the proxy.

### Status code distribution: rising 429

Anthropic rate-limit hits. If the 429 rate exceeds 5% and user is on the
highest tier, consider spreading traffic with jittered retries (not currently
implemented — add to backlog).

### Status code distribution: 401

OAuth token expired and refresher isn't keeping up. Run
`claude auth login` on the host, then verify `/health` shows `status: ok`.

## Step 3 — Health endpoint sanity

```bash
curl -s http://127.0.0.1:18801/health | jq
curl -s http://127.0.0.1:18801/metrics | jq
```

Expected:
- `status: "ok"` (not `token_expired`)
- `tokenExpiresInHours > 6`
- `detectionRate < 0.001` (< 0.1% of requests classified as non-CC)
- `tokenReadErrors == 0`

## Step 4 — Archive anomalous bodies

If step 2 surfaces a new trigger, save the raw body before logs rotate:

```bash
# Find the request number in scripts/proxy.log, then extract from jsonl:
grep -l "\"ts\":" logs/prompts-*.jsonl | head -1 | xargs -I {} \
  jq -c --argjson n 1234 'select(.reqNum == $n)' {} > /tmp/body-1234.json
```

(Proxy-logger doesn't store the req number in jsonl currently — match by
timestamp instead. Consider adding `reqNum` to the jsonl entry as an
improvement.)

## Step 5 — Ship fixes with tests

Every proxy.js edit must ship alongside a unit test:

```bash
node --test tests/
```

If the anomaly involved a new trigger phrase, add a targeted regression test
in `tests/transform-pipeline.test.js`. If it involved classifier/billing
header, add to `tests/billing-fingerprint.test.js`.

## Operator checklist (copy-paste)

```
[ ] Ran analyze-logs.js, exit code noted
[ ] Detection count = 0 (or investigated)
[ ] Trigger leakage = 0 (or investigated)
[ ] Upstream errors reasonable for traffic level
[ ] Refresh spawn failures = 0
[ ] /health and /metrics both return 200 with expected fields
[ ] Any fixes shipped with a passing test
[ ] Archived anomalous bodies if classifier regression found
```
