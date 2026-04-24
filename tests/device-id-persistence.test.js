// DEVICE_ID persistence — must remain stable across proxy restarts.
//
// Anthropic's abuse detection can flag device_id churn. A real Claude Code
// CLI keeps the same value across process launches. The proxy stores it in
// ~/.claude/proxy-device.json; to avoid polluting the real home dir during
// testing, we spawn child Node processes with HOME pointing at a temp dir
// and inspect DEVICE_ID via a one-shot eval.

const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function getDeviceIdFromChild(fakeHome) {
  const script = [
    'require("./proxy");',
    'const fs = require("fs");',
    'const path = require("path");',
    'const stored = path.join(process.env.HOME, ".claude", "proxy-device.json");',
    'process.stdout.write(fs.existsSync(stored) ? fs.readFileSync(stored, "utf8") : "MISSING");'
  ].join(' ');
  const r = spawnSync(process.execPath, ['-e', script], {
    cwd: path.resolve(__dirname, '..'),
    env: { ...process.env, HOME: fakeHome },
    encoding: 'utf8'
  });
  if (r.status !== 0) {
    throw new Error(`child failed: ${r.stderr || r.stdout}`);
  }
  return r.stdout.trim();
}

test('DEVICE_ID is persisted to ~/.claude/proxy-device.json on first run', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'obp-device-'));
  try {
    const payload = getDeviceIdFromChild(tmp);
    assert.notStrictEqual(payload, 'MISSING', 'proxy-device.json not created');
    const parsed = JSON.parse(payload);
    assert.match(parsed.deviceId, /^[0-9a-f]{64}$/);
    assert.ok(parsed.createdAt);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('DEVICE_ID is the same across two proxy runs with the same HOME', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'obp-device-'));
  try {
    const first = JSON.parse(getDeviceIdFromChild(tmp)).deviceId;
    const second = JSON.parse(getDeviceIdFromChild(tmp)).deviceId;
    assert.strictEqual(first, second, 'device id should persist across runs');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('corrupted proxy-device.json causes a new id to be generated (no crash)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'obp-device-'));
  try {
    fs.mkdirSync(path.join(tmp, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(tmp, '.claude', 'proxy-device.json'), '{not json');
    const payload = getDeviceIdFromChild(tmp);
    const parsed = JSON.parse(payload);
    assert.match(parsed.deviceId, /^[0-9a-f]{64}$/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('proxy-device.json with wrong-shape content is overwritten (no crash)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'obp-device-'));
  try {
    fs.mkdirSync(path.join(tmp, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(tmp, '.claude', 'proxy-device.json'), '{"deviceId":"short"}');
    const payload = getDeviceIdFromChild(tmp);
    const parsed = JSON.parse(payload);
    assert.match(parsed.deviceId, /^[0-9a-f]{64}$/, 'short id should be rejected, new one written');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
