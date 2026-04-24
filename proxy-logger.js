// Preload module: node -r ./proxy-logger.js proxy.js
// Hooks http.createServer to log post-sanitized request bodies to logs/prompts-YYYY-MM-DD.jsonl
// without modifying proxy.js. Next upstream pull remains conflict-free.

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

// Override bind host (proxy.js v2 hardcoded 127.0.0.1).
// Set PROXY_HOST=0.0.0.0 for external access (Docker/VM clients).
const BIND_HOST = process.env.PROXY_HOST;
if (BIND_HOST) {
  const origCreateServer = http.createServer.bind(http);
  http.createServer = function (...args) {
    const server = origCreateServer(...args);
    const origListen = server.listen.bind(server);
    server.listen = function (port, host, ...rest) {
      // Replace any host argument with BIND_HOST.
      if (typeof host === 'string') return origListen(port, BIND_HOST, ...rest);
      return origListen(port, BIND_HOST, host, ...rest);
    };
    return server;
  };
  console.log('[logger] bind host override -> ' + BIND_HOST);
}

const LOG_DIR = path.join(__dirname, 'logs');

function logPrompt(method, url, bodyStr) {
  try {
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
    const now = new Date();
    const file = path.join(LOG_DIR, `prompts-${now.toISOString().slice(0, 10)}.jsonl`);
    let parsed = null;
    try { parsed = JSON.parse(bodyStr); } catch (_) {}
    const entry = {
      ts: now.toISOString(),
      method,
      url,
      model: parsed && parsed.model,
      system: parsed && parsed.system,
      messages: parsed && parsed.messages,
      tools: parsed && parsed.tools ? parsed.tools.map(t => t.name || t) : undefined,
      raw: parsed ? undefined : bodyStr
    };
    fs.appendFileSync(file, JSON.stringify(entry) + '\n');
  } catch (e) {
    console.error('[logger] failed:', e.message);
  }
}

// Strategy: intercept outbound https.request (proxy.js forwards to api.anthropic.com
// via https.request — that's where the post-sanitized body gets written). We tap
// write()/end() to capture the actual body sent upstream.
const origHttpsRequest = https.request.bind(https);
https.request = function (options, cb) {
  const req = origHttpsRequest(options, cb);
  const host = (typeof options === 'object' && options.hostname) || '';
  const isAnthropicMessages =
    host === 'api.anthropic.com' &&
    typeof options.path === 'string' &&
    options.path.includes('/messages') &&
    options.method === 'POST';

  if (!isAnthropicMessages) return req;

  const chunks = [];
  const origWrite = req.write.bind(req);
  const origEnd = req.end.bind(req);

  // Fix stale content block types that upstream deliberately removed from
  // tool renames (proxy.js issue #14). OpenClaw may cache renamed types
  // from earlier conversations and resend them as content block "type" values.
  // Anthropic rejects unknown types, so we patch them just before send.
  const CONTENT_TYPE_FIXES = [
    ['"ImageGen"', '"image"'],
  ];

  // Strip orphaned tool_results whose tool_use_id has no matching tool_use
  // in the previous assistant message. OpenClaw's context compaction can merge
  // hundreds of tool_results into one user message while losing the assistant
  // tool_use blocks they reference. Anthropic rejects these with:
  //   "unexpected tool_use_id found in tool_result blocks"
  function stripOrphanedToolResults(body) {
    const msgs = body.messages;
    if (!Array.isArray(msgs)) return false;
    let changed = false;
    for (let i = 1; i < msgs.length; i++) {
      const content = msgs[i].content;
      if (!Array.isArray(content)) continue;
      // Collect tool_use ids from previous message
      const prev = msgs[i - 1].content;
      const validIds = new Set();
      if (Array.isArray(prev)) {
        for (const b of prev) {
          if (b.type === 'tool_use' && b.id) validIds.add(b.id);
        }
      }
      // Filter out tool_results with no matching tool_use
      const filtered = content.filter(b => {
        if (b.type !== 'tool_result') return true;
        return validIds.has(b.tool_use_id);
      });
      if (filtered.length < content.length) {
        const removed = content.length - filtered.length;
        console.log(`[patch] Stripped ${removed} orphaned tool_result(s) from msg[${i}]`);
        msgs[i].content = filtered.length > 0 ? filtered : [{ type: 'text', text: '(compacted)' }];
        changed = true;
      }
    }
    return changed;
  }

  function patchBody(bodyStr) {
    let patched = bodyStr;
    // Fix stale content block types
    for (const [bad, good] of CONTENT_TYPE_FIXES) {
      patched = patched.split(bad).join(good);
    }
    // Fix orphaned tool_results (requires JSON parse)
    try {
      const body = JSON.parse(patched);
      if (stripOrphanedToolResults(body)) {
        patched = JSON.stringify(body);
      }
    } catch (_) {}
    return patched;
  }

  req.write = function (chunk, ...rest) {
    // Buffer chunks — we may need to patch the body before sending
    if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    // Suppress encoding arg, return true to signal writable
    return true;
  };
  req.end = function (chunk, ...rest) {
    if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    const bodyStr = Buffer.concat(chunks).toString('utf8');
    try { logPrompt(options.method, options.path, bodyStr); } catch (_) {}

    // Apply content type fixes and send as single chunk
    const fixed = patchBody(bodyStr);
    const buf = Buffer.from(fixed, 'utf8');
    req.setHeader('content-length', buf.length);
    origWrite(buf);
    return origEnd(null, ...rest);
  };
  return req;
};

// Credentials refresher: periodically spawn `claude -p ping` to rotate the
// OAuth token in ~/.claude/.credentials.json. Proxy re-reads the file per
// request, so the new token is picked up automatically. Unref'd so it dies
// with the main process.
function startCredsRefresher(intervalMs) {
  const { spawn } = require('child_process');
  const tick = () => {
    const p = spawn('claude', ['-p', 'ping', '--max-turns', '1', '--no-session-persistence'], {
      stdio: 'ignore', detached: false
    });
    p.on('error', (e) => console.error('[refresh] spawn failed:', e.message));
  };
  tick(); // warm immediately on startup
  const handle = setInterval(tick, intervalMs);
  if (handle.unref) handle.unref();
  console.log(`[refresh] creds refresher active (every ${intervalMs / 60000}min)`);
}
startCredsRefresher(60 * 60 * 1000); // hourly

console.log('[logger] proxy-logger preloaded -> ' + LOG_DIR);
