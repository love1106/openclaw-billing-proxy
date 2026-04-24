// log-analyzer tests — proxy.log parser, prompt scanner, report formatter.

const test = require('node:test');
const assert = require('node:assert');
const {
  parseProxyLogLine,
  summarizeProxyLog,
  createPromptScanner,
  formatReport,
  LEAKAGE_PATTERNS
} = require('../log-analyzer');

test('parseProxyLogLine: request line', () => {
  const ev = parseProxyLogLine('[12:34:56] #42 POST /v1/messages (1000b -> 800b)');
  assert.deepStrictEqual(ev, {
    type: 'req', ts: '12:34:56', reqNum: 42,
    method: 'POST', url: '/v1/messages',
    bytesIn: 1000, bytesOut: 800
  });
});

test('parseProxyLogLine: response line', () => {
  const ev = parseProxyLogLine('[12:34:56] #42 > 200');
  assert.deepStrictEqual(ev, { type: 'res', ts: '12:34:56', reqNum: 42, status: 200 });
});

test('parseProxyLogLine: detection line', () => {
  const ev = parseProxyLogLine('[12:34:56] #42 DETECTION! Body: 5000b');
  assert.deepStrictEqual(ev, { type: 'detection', ts: '12:34:56', reqNum: 42, bodySize: 5000 });
});

test('parseProxyLogLine: upstream error', () => {
  const ev = parseProxyLogLine('[12:34:56] #42 ERR: read ETIMEDOUT');
  assert.deepStrictEqual(ev, { type: 'err', ts: '12:34:56', reqNum: 42, message: 'read ETIMEDOUT' });
});

test('parseProxyLogLine: STRIP line', () => {
  assert.deepStrictEqual(
    parseProxyLogLine('[STRIP] Removed 31991 chars of config template'),
    { type: 'strip', stripped: 31991 }
  );
});

test('parseProxyLogLine: refresh spawn failure', () => {
  assert.deepStrictEqual(
    parseProxyLogLine('[refresh] spawn failed: ENOENT'),
    { type: 'refresh_spawn_fail' }
  );
});

test('parseProxyLogLine: unknown line returns null', () => {
  assert.strictEqual(parseProxyLogLine('random chatter'), null);
  assert.strictEqual(parseProxyLogLine(''), null);
});

test('summarizeProxyLog: aggregates real log shape', () => {
  const log = [
    '[logger] proxy-logger preloaded',
    '[12:00:00] #1 POST /v1/messages (1000b -> 800b)',
    '[STRIP] Removed 31991 chars of config template',
    '[12:00:01] #1 > 200',
    '[12:00:10] #2 POST /v1/messages (500b -> 400b)',
    '[12:00:11] #2 > 400',
    '[12:00:11] #2 DETECTION! Body: 400b',
    '[12:00:20] #3 POST /v1/messages (600b -> 500b)',
    '[12:00:21] #3 ERR: read ETIMEDOUT'
  ].join('\n');
  const s = summarizeProxyLog(log);
  assert.strictEqual(s.requests, 3);
  assert.deepStrictEqual({ ...s.byStatus }, { '200': 1, '400': 1 });
  assert.strictEqual(s.detections.length, 1);
  assert.strictEqual(s.detections[0].reqNum, 2);
  assert.strictEqual(s.upstreamErrors.length, 1);
  assert.strictEqual(s.stripEvents, 1);
  assert.strictEqual(s.stripTotalBytes, 31991);
  assert.strictEqual(s.bytesInTotal, 2100);
  assert.strictEqual(s.bytesOutTotal, 1700);
  assert.strictEqual(s.bytesInMax, 1000);
});

test('summarizeProxyLog: empty input yields zero summary', () => {
  const s = summarizeProxyLog('');
  assert.strictEqual(s.requests, 0);
  assert.strictEqual(s.detections.length, 0);
});

test('createPromptScanner: detects trigger leakage', () => {
  const scanner = createPromptScanner();
  scanner.onLine(JSON.stringify({ messages: [{ content: 'hello OpenClaw' }] }));
  scanner.onLine(JSON.stringify({ messages: [{ content: 'clean body' }] }));
  scanner.onLine(JSON.stringify({ messages: [{ content: 'sessions_spawn leaked' }] }));
  const s = scanner.summary();
  assert.strictEqual(s.records, 3);
  assert.strictEqual(s.failedParses, 0);
  assert.strictEqual(s.triggerLeakage['OpenClaw'], 1);
  assert.strictEqual(s.triggerLeakage['sessions_spawn'], 1);
});

test('createPromptScanner: counts tool usage', () => {
  const scanner = createPromptScanner();
  scanner.onLine(JSON.stringify({ tools: ['Bash', 'Grep'] }));
  scanner.onLine(JSON.stringify({ tools: ['Bash', 'TaskCreate'] }));
  const s = scanner.summary();
  assert.strictEqual(s.toolUsage.Bash, 2);
  assert.strictEqual(s.toolUsage.Grep, 1);
  assert.strictEqual(s.toolUsage.TaskCreate, 1);
});

test('createPromptScanner: tracks parse failures', () => {
  const scanner = createPromptScanner();
  scanner.onLine('{not valid json');
  scanner.onLine(JSON.stringify({ tools: ['Bash'] }));
  const s = scanner.summary();
  assert.strictEqual(s.records, 2);
  assert.strictEqual(s.failedParses, 1);
});

test('createPromptScanner: accepts custom patterns', () => {
  const scanner = createPromptScanner(['CustomTrigger']);
  scanner.onLine(JSON.stringify({ data: 'has CustomTrigger here' }));
  scanner.onLine(JSON.stringify({ data: 'OpenClaw here but not in patterns' }));
  const s = scanner.summary();
  assert.strictEqual(s.triggerLeakage['CustomTrigger'], 1);
  assert.strictEqual(s.triggerLeakage['OpenClaw'], undefined);
});

test('formatReport: human-readable output includes all sections', () => {
  const proxySummary = summarizeProxyLog([
    '[12:00:00] #1 POST /v1/messages (1000b -> 800b)',
    '[12:00:01] #1 > 200'
  ].join('\n'));
  const scanner = createPromptScanner();
  scanner.onLine(JSON.stringify({ tools: ['Bash'] }));
  const promptSummary = scanner.summary();
  const report = formatReport(proxySummary, promptSummary);
  assert.ok(report.includes('Proxy runtime log'));
  assert.ok(report.includes('Status code distribution'));
  assert.ok(report.includes('200:'));
  assert.ok(report.includes('Prompt logs'));
  assert.ok(report.includes('Top tools'));
  assert.ok(report.includes('Bash:'));
});

test('formatReport: flags detections with warning', () => {
  const proxySummary = summarizeProxyLog([
    '[12:00:00] #1 POST /v1/messages (100b -> 90b)',
    '[12:00:01] #1 > 400',
    '[12:00:01] #1 DETECTION! Body: 90b'
  ].join('\n'));
  const report = formatReport(proxySummary, null);
  assert.ok(report.includes('DETECTION events'));
  assert.ok(report.includes('ERROR'));
});

test('LEAKAGE_PATTERNS covers critical OC triggers', () => {
  // Sanity — if someone strips the patterns list we should break loudly.
  assert.ok(LEAKAGE_PATTERNS.includes('OpenClaw'));
  assert.ok(LEAKAGE_PATTERNS.includes('sessions_spawn'));
  assert.ok(LEAKAGE_PATTERNS.includes('HEARTBEAT_OK'));
});
