// proxy-metrics tests — counters, detection detector, ring buffer.

const test = require('node:test');
const assert = require('node:assert');
const m = require('../proxy-metrics');

test('createMetrics initializes zero counters', () => {
  const state = m.createMetrics();
  assert.strictEqual(state.requests, 0);
  assert.strictEqual(state.detections, 0);
  assert.strictEqual(state.upstreamErrors, 0);
  assert.strictEqual(state.tokenReadErrors, 0);
  assert.deepStrictEqual(state.byStatus, Object.create(null));
  assert.deepStrictEqual(state.detectionSamples, []);
});

test('recordRequest increments counter and sums bytes', () => {
  const state = m.createMetrics();
  m.recordRequest(state, 100);
  m.recordRequest(state, 50);
  assert.strictEqual(state.requests, 2);
  assert.strictEqual(state.bytesIn, 150);
});

test('recordResponse tallies by status code', () => {
  const state = m.createMetrics();
  m.recordResponse(state, 200, 10);
  m.recordResponse(state, 200, 20);
  m.recordResponse(state, 429, 5);
  assert.deepStrictEqual({ ...state.byStatus }, { '200': 2, '429': 1 });
  assert.strictEqual(state.bytesOut, 35);
});

test('isDetection matches 400 with "extra usage"', () => {
  assert.ok(m.isDetection(400, '{"error":{"message":"extra usage required"}}'));
  assert.ok(!m.isDetection(400, '{"error":{"message":"other"}}'));
  assert.ok(!m.isDetection(200, 'extra usage'));  // wrong status
  assert.ok(!m.isDetection(400, null));           // non-string body
  assert.ok(!m.isDetection(401, 'extra usage'));  // not a detection
});

test('recordDetection stores sample with request context', () => {
  const state = m.createMetrics();
  m.recordDetection(state, 42, 1024, '{"error":{"message":"extra usage required"}}');
  assert.strictEqual(state.detections, 1);
  assert.strictEqual(state.detectionSamples.length, 1);
  const sample = state.detectionSamples[0];
  assert.strictEqual(sample.reqNum, 42);
  assert.strictEqual(sample.bodySize, 1024);
  assert.ok(sample.errSnippet.includes('extra usage'));
  assert.ok(sample.ts.match(/^\d{4}-\d{2}-\d{2}T/));
});

test('detectionSamples is bounded by DETECTION_SAMPLE_CAP', () => {
  const state = m.createMetrics();
  for (let i = 0; i < m.DETECTION_SAMPLE_CAP + 10; i++) {
    m.recordDetection(state, i, 100, 'extra usage');
  }
  assert.strictEqual(state.detections, m.DETECTION_SAMPLE_CAP + 10);
  assert.strictEqual(state.detectionSamples.length, m.DETECTION_SAMPLE_CAP);
  // Oldest evicted — newest kept
  assert.strictEqual(state.detectionSamples[0].reqNum, 10);
  assert.strictEqual(
    state.detectionSamples[state.detectionSamples.length - 1].reqNum,
    m.DETECTION_SAMPLE_CAP + 9
  );
});

test('errSnippet is truncated to 500 chars', () => {
  const state = m.createMetrics();
  const huge = 'extra usage ' + 'x'.repeat(2000);
  m.recordDetection(state, 1, 0, huge);
  assert.strictEqual(state.detectionSamples[0].errSnippet.length, 500);
});

test('snapshot includes detectionRate', () => {
  const state = m.createMetrics();
  for (let i = 0; i < 99; i++) m.recordResponse(state, 200, 0);
  m.recordResponse(state, 400, 0);
  m.recordRequest(state, 0);
  m.recordRequest(state, 0);
  // 2 requests, 1 detection would give rate 0.5. But we haven't recorded a detection.
  m.recordDetection(state, 1, 0, 'extra usage');
  const snap = m.snapshot(state);
  assert.strictEqual(snap.requests, 2);
  assert.strictEqual(snap.detections, 1);
  assert.strictEqual(snap.detectionRate, 0.5);
});

test('snapshot detectionRate is 0 with no requests (no NaN)', () => {
  const snap = m.snapshot(m.createMetrics());
  assert.strictEqual(snap.detectionRate, 0);
  assert.ok(!Number.isNaN(snap.detectionRate));
});

test('snapshot is a defensive copy, not live state', () => {
  const state = m.createMetrics();
  m.recordResponse(state, 200, 0);
  const snap = m.snapshot(state);
  m.recordResponse(state, 200, 0);
  // snap should still reflect the state at snapshot time
  assert.strictEqual(snap.byStatus['200'], 1);
});
