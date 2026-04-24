// Pure parsing/aggregation helpers for weekly log review.
//
// Two log sources:
//   1. scripts/proxy.log — stdout/stderr of the running proxy. Line-based.
//      Key patterns written by proxy.js:
//        [HH:MM:SS] #N METHOD URL (inB -> outB)
//        [HH:MM:SS] #N > STATUS
//        [HH:MM:SS] #N DETECTION! Body: Nb
//        [HH:MM:SS] #N ERR: message
//      Plus non-request framing lines from [logger]/[refresh]/[STRIP].
//
//   2. logs/prompts-YYYY-MM-DD.jsonl — one request body per line, written
//      by proxy-logger.js. Used for trigger leakage detection (did any OC
//      trigger phrase survive sanitization?) and tool-call frequency.
//
// No I/O here — callers read files and pass strings in. Makes tests fast
// and deterministic.

const REQ_LINE_RE = /^\[(\d{2}:\d{2}:\d{2})\]\s+#(\d+)\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+\((\d+)b\s*->\s*(\d+)b\)/;
const RES_LINE_RE = /^\[(\d{2}:\d{2}:\d{2})\]\s+#(\d+)\s+>\s+(\d+)\s*$/;
const DETECTION_RE = /^\[(\d{2}:\d{2}:\d{2})\]\s+#(\d+)\s+DETECTION!\s+Body:\s+(\d+)b/;
const ERR_RE = /^\[(\d{2}:\d{2}:\d{2})\]\s+#(\d+)\s+ERR:\s+(.+)$/;
const STRIP_RE = /^\[STRIP\]\s+Removed\s+(\d+)\s+chars/;
const REFRESH_SPAWN_RE = /^\[refresh\]\s+spawn failed:/;

// Triggers that should NEVER appear in the post-sanitization body sent to
// Anthropic. If any shows up in logs/prompts-*.jsonl, either the
// DEFAULT_REPLACEMENTS table is missing an entry or a new OC content source
// is emitting the token in a form we don't intercept.
const LEAKAGE_PATTERNS = [
  'OpenClaw',
  'openclaw',
  'sessions_spawn',
  'sessions_list',
  'sessions_history',
  'sessions_send',
  'HEARTBEAT_OK',
  'HEARTBEAT',
  'Prometheus',
  'clawhub',
  'clawd'
];

function parseProxyLogLine(line) {
  let m;
  if ((m = line.match(REQ_LINE_RE))) {
    return { type: 'req', ts: m[1], reqNum: Number(m[2]), method: m[3], url: m[4], bytesIn: Number(m[5]), bytesOut: Number(m[6]) };
  }
  if ((m = line.match(RES_LINE_RE))) {
    return { type: 'res', ts: m[1], reqNum: Number(m[2]), status: Number(m[3]) };
  }
  if ((m = line.match(DETECTION_RE))) {
    return { type: 'detection', ts: m[1], reqNum: Number(m[2]), bodySize: Number(m[3]) };
  }
  if ((m = line.match(ERR_RE))) {
    return { type: 'err', ts: m[1], reqNum: Number(m[2]), message: m[3] };
  }
  if ((m = line.match(STRIP_RE))) {
    return { type: 'strip', stripped: Number(m[1]) };
  }
  if (REFRESH_SPAWN_RE.test(line)) {
    return { type: 'refresh_spawn_fail' };
  }
  return null;
}

function summarizeProxyLog(logText) {
  const summary = {
    totalLines: 0,
    requests: 0,
    byStatus: Object.create(null),
    detections: [],
    upstreamErrors: [],
    stripEvents: 0,
    stripTotalBytes: 0,
    refreshSpawnFailures: 0,
    bytesInTotal: 0,
    bytesOutTotal: 0,
    bytesInMax: 0
  };
  if (!logText) return summary;
  const lines = logText.split('\n');
  summary.totalLines = lines.length;
  for (const line of lines) {
    const ev = parseProxyLogLine(line);
    if (!ev) continue;
    switch (ev.type) {
      case 'req':
        summary.requests++;
        summary.bytesInTotal += ev.bytesIn;
        summary.bytesOutTotal += ev.bytesOut;
        if (ev.bytesIn > summary.bytesInMax) summary.bytesInMax = ev.bytesIn;
        break;
      case 'res':
        summary.byStatus[ev.status] = (summary.byStatus[ev.status] || 0) + 1;
        break;
      case 'detection':
        summary.detections.push({ ts: ev.ts, reqNum: ev.reqNum, bodySize: ev.bodySize });
        break;
      case 'err':
        summary.upstreamErrors.push({ ts: ev.ts, reqNum: ev.reqNum, message: ev.message });
        break;
      case 'strip':
        summary.stripEvents++;
        summary.stripTotalBytes += ev.stripped;
        break;
      case 'refresh_spawn_fail':
        summary.refreshSpawnFailures++;
        break;
    }
  }
  return summary;
}

// Scan a single JSONL prompt log, return trigger-leakage hits and tool usage.
// `lineHandler` lets callers stream (avoid loading huge files into memory).
function createPromptScanner(patterns = LEAKAGE_PATTERNS) {
  const hits = Object.create(null);
  const toolUsage = Object.create(null);
  let records = 0;
  let failedParses = 0;

  function onLine(line) {
    if (!line) return;
    records++;
    let rec;
    try { rec = JSON.parse(line); } catch (_) { failedParses++; return; }

    // Scan the full line text for triggers — cheaper than traversing the
    // parsed structure and catches tokens anywhere (system, messages, tools).
    for (const pat of patterns) {
      if (line.includes(pat)) {
        hits[pat] = (hits[pat] || 0) + 1;
      }
    }

    if (Array.isArray(rec.tools)) {
      for (const name of rec.tools) {
        if (typeof name === 'string') {
          toolUsage[name] = (toolUsage[name] || 0) + 1;
        }
      }
    }
  }

  function summary() {
    return {
      records,
      failedParses,
      triggerLeakage: { ...hits },
      toolUsage: { ...toolUsage }
    };
  }

  return { onLine, summary };
}

// Format a summary as a human-readable report (CLI output).
function formatReport(proxySummary, promptSummary, opts = {}) {
  const lines = [];
  const title = opts.title || 'Billing Proxy — Log Review';
  lines.push('='.repeat(title.length));
  lines.push(title);
  lines.push('='.repeat(title.length));
  lines.push('');

  lines.push('## Proxy runtime log (scripts/proxy.log)');
  lines.push(`  lines parsed:        ${proxySummary.totalLines}`);
  lines.push(`  requests:            ${proxySummary.requests}`);
  lines.push(`  upstream errors:     ${proxySummary.upstreamErrors.length}`);
  lines.push(`  detections:          ${proxySummary.detections.length}`);
  lines.push(`  template strip evs:  ${proxySummary.stripEvents}  (${proxySummary.stripTotalBytes} bytes removed total)`);
  lines.push(`  refresh spawn fails: ${proxySummary.refreshSpawnFailures}`);
  lines.push(`  bytes in total:      ${proxySummary.bytesInTotal}`);
  lines.push(`  bytes out total:     ${proxySummary.bytesOutTotal}`);
  lines.push(`  largest request:     ${proxySummary.bytesInMax}`);
  lines.push('');

  lines.push('### Status code distribution');
  const codes = Object.keys(proxySummary.byStatus).sort();
  if (codes.length === 0) lines.push('  (no response lines parsed)');
  for (const code of codes) {
    const pct = proxySummary.requests > 0
      ? ((proxySummary.byStatus[code] / proxySummary.requests) * 100).toFixed(2)
      : '0.00';
    const marker = Number(code) >= 400 ? ' <-- ERROR' : '';
    lines.push(`  ${code}: ${proxySummary.byStatus[code]} (${pct}%)${marker}`);
  }
  lines.push('');

  if (proxySummary.detections.length > 0) {
    lines.push('### DETECTION events (classifier rejected as non-CC)');
    for (const d of proxySummary.detections.slice(-20)) {
      lines.push(`  [${d.ts}] req #${d.reqNum} body=${d.bodySize}b`);
    }
    lines.push('');
  }

  if (proxySummary.upstreamErrors.length > 0) {
    lines.push('### Upstream errors (last 10)');
    for (const e of proxySummary.upstreamErrors.slice(-10)) {
      lines.push(`  [${e.ts}] req #${e.reqNum}: ${e.message}`);
    }
    lines.push('');
  }

  if (promptSummary) {
    lines.push('## Prompt logs (logs/prompts-*.jsonl)');
    lines.push(`  records:        ${promptSummary.records}`);
    lines.push(`  parse failures: ${promptSummary.failedParses}`);
    lines.push('');

    const leakKeys = Object.keys(promptSummary.triggerLeakage);
    lines.push('### Trigger leakage (triggers present in post-sanitization bodies)');
    if (leakKeys.length === 0) {
      lines.push('  none -- good');
    } else {
      for (const k of leakKeys.sort((a, b) => promptSummary.triggerLeakage[b] - promptSummary.triggerLeakage[a])) {
        lines.push(`  "${k}": ${promptSummary.triggerLeakage[k]} hit(s) <-- add to DEFAULT_REPLACEMENTS`);
      }
    }
    lines.push('');

    const tools = Object.entries(promptSummary.toolUsage).sort((a, b) => b[1] - a[1]);
    if (tools.length > 0) {
      lines.push('### Top tools in outbound tools[]');
      for (const [name, count] of tools.slice(0, 20)) {
        lines.push(`  ${name}: ${count}`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

module.exports = {
  parseProxyLogLine,
  summarizeProxyLog,
  createPromptScanner,
  formatReport,
  LEAKAGE_PATTERNS
};
