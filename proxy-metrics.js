// Production observability for the billing proxy.
//
// Counters + recent-detection ring buffer exposed via /health and /metrics.
// Stateful singleton (one per running server). No I/O, no deps — pure state
// manipulation so it's trivially testable.
//
// The key signal is "detections": responses where Anthropic returned a 400
// containing "extra usage", meaning the classifier flagged our request as
// non-CC and billed it to Extra Usage instead of the subscription. A spike
// here means the camouflage broke — likely a new trigger phrase, a CC version
// bump, or a missed reverse-map entry. Keep a ring buffer of recent events
// with enough context to replay via `binary search` on the stored body size.

const DETECTION_MARKER = 'extra usage';
const DETECTION_SAMPLE_CAP = 20;

function createMetrics(now = () => Date.now()) {
  return {
    _now: now,
    startedAt: now(),
    requests: 0,
    byStatus: Object.create(null),
    detections: 0,
    detectionSamples: [],
    upstreamErrors: 0,
    tokenReadErrors: 0,
    bytesIn: 0,
    bytesOut: 0
  };
}

function recordRequest(m, bytes) {
  m.requests++;
  m.bytesIn += bytes || 0;
}

function recordResponse(m, status, bodySize) {
  const key = String(status);
  m.byStatus[key] = (m.byStatus[key] || 0) + 1;
  m.bytesOut += bodySize || 0;
}

// Returns true if this error response is an "Extra Usage" detection event.
// The classifier-reject signature is a 400 with `extra usage` in the body
// (case sensitive, Anthropic's exact wording).
function isDetection(status, body) {
  if (status !== 400) return false;
  if (typeof body !== 'string') return false;
  return body.includes(DETECTION_MARKER);
}

function recordDetection(m, reqNum, bodySize, errSnippet) {
  m.detections++;
  m.detectionSamples.push({
    ts: new Date(m._now()).toISOString(),
    reqNum,
    bodySize,
    errSnippet: typeof errSnippet === 'string' ? errSnippet.slice(0, 500) : ''
  });
  while (m.detectionSamples.length > DETECTION_SAMPLE_CAP) {
    m.detectionSamples.shift();
  }
}

function recordUpstreamError(m) { m.upstreamErrors++; }
function recordTokenReadError(m) { m.tokenReadErrors++; }

function snapshot(m) {
  const uptimeMs = m._now() - m.startedAt;
  return {
    uptimeSeconds: Math.floor(uptimeMs / 1000),
    requests: m.requests,
    byStatus: { ...m.byStatus },
    detections: m.detections,
    detectionRate: m.requests > 0 ? m.detections / m.requests : 0,
    recentDetections: m.detectionSamples.slice(),
    upstreamErrors: m.upstreamErrors,
    tokenReadErrors: m.tokenReadErrors,
    bytesIn: m.bytesIn,
    bytesOut: m.bytesOut
  };
}

module.exports = {
  createMetrics,
  recordRequest,
  recordResponse,
  isDetection,
  recordDetection,
  recordUpstreamError,
  recordTokenReadError,
  snapshot,
  DETECTION_MARKER,
  DETECTION_SAMPLE_CAP
};
