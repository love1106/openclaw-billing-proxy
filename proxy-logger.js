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
  req.write = function (chunk, ...rest) {
    if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    return origWrite(chunk, ...rest);
  };
  req.end = function (chunk, ...rest) {
    if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    try {
      logPrompt(options.method, options.path, Buffer.concat(chunks).toString('utf8'));
    } catch (_) {}
    return origEnd(chunk, ...rest);
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
