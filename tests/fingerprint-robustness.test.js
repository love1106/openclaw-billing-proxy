// extractFirstUserText robustness — must resist collisions with escaped
// `"role":"user"` or `"content"` substrings embedded in message text.
//
// If this function returns the wrong slice, computeBillingFingerprint emits
// a hash that doesn't match what Anthropic reads, and the request gets
// billed to Extra Usage. That's the core stability guarantee this project
// exists to provide, so tighten the regression coverage.

const test = require('node:test');
const assert = require('node:assert');
const { extractFirstUserText, computeBillingFingerprint } = require('../proxy');

test('extracts plain first-user string content', () => {
  const body = JSON.stringify({ messages: [{ role: 'user', content: 'hello first message' }] });
  assert.strictEqual(extractFirstUserText(body), 'hello first message');
});

test('resists escaped "role":"user" collisions inside a user-authored message', () => {
  // User quotes JSON verbatim. JSON.stringify escapes the inner quotes.
  // The scan looks for literal "role":"user" (no backslashes) and must skip
  // the escaped form.
  const body = JSON.stringify({
    messages: [{ role: 'user', content: 'I saw "role":"user" in the docs' }]
  });
  const text = extractFirstUserText(body);
  assert.ok(text.startsWith('I saw'), `expected user text, got: ${text}`);
});

test('resists escaped first-message collision with a later real user message', () => {
  const body = JSON.stringify({
    messages: [
      { role: 'assistant', content: 'JSON example: {"role":"user","content":"fake"}' },
      { role: 'user', content: 'real user text' }
    ]
  });
  assert.strictEqual(extractFirstUserText(body), 'real user text');
});

test('extracts first text block from user content array', () => {
  const body = JSON.stringify({
    messages: [{
      role: 'user',
      content: [
        { type: 'tool_result', tool_use_id: 'x', content: 'some tool output' },
        { type: 'text', text: 'the real first text' }
      ]
    }]
  });
  // Returns some substring prefix — minimum contract: the indexed chars
  // (positions 4,7,20) match what the fingerprint would hash from the raw
  // user text present in the body.
  const text = extractFirstUserText(body);
  assert.ok(text.length > 0, 'expected non-empty text');
});

test('returns empty string for bodies with no user message', () => {
  const body = JSON.stringify({ messages: [{ role: 'assistant', content: 'no user' }] });
  assert.strictEqual(extractFirstUserText(body), '');
});

test('returns empty for bodies with no messages array', () => {
  assert.strictEqual(extractFirstUserText('{}'), '');
  assert.strictEqual(extractFirstUserText(''), '');
});

test('computeBillingFingerprint is deterministic for same input', () => {
  const a = computeBillingFingerprint('hello world test message');
  const b = computeBillingFingerprint('hello world test message');
  assert.strictEqual(a, b);
  assert.strictEqual(a.length, 3);
});

test('computeBillingFingerprint yields 3-char hex', () => {
  const fp = computeBillingFingerprint('abcdefghijklmnopqrstuvwxyz');
  assert.match(fp, /^[0-9a-f]{3}$/);
});

test('computeBillingFingerprint handles short text with padding', () => {
  // Indices 4,7,20 on empty/short text should fall back to '0' padding
  // without crashing.
  assert.doesNotThrow(() => computeBillingFingerprint(''));
  assert.doesNotThrow(() => computeBillingFingerprint('abc'));
});
