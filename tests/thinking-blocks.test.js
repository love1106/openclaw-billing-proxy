// Thinking block protection tests.
//
// Anthropic rejects any mutation of thinking/redacted_thinking content blocks
// in the latest assistant message. processBody and reverseMap MUST mask these
// blocks before split/join transforms run and restore them byte-identical.

const test = require('node:test');
const assert = require('node:assert');
const {
  processBody,
  reverseMap,
  maskThinkingBlocks,
  unmaskThinkingBlocks,
  DEFAULT_REPLACEMENTS,
  DEFAULT_TOOL_RENAMES,
  DEFAULT_PROP_RENAMES,
  DEFAULT_REVERSE_MAP
} = require('../proxy');

function makeConfig() {
  return {
    replacements: DEFAULT_REPLACEMENTS,
    toolRenames: DEFAULT_TOOL_RENAMES,
    propRenames: DEFAULT_PROP_RENAMES,
    reverseMap: DEFAULT_REVERSE_MAP,
    stripSystemConfig: false,
    stripToolDescriptions: false,
    injectCCStubs: false,
    stripTrailingAssistantPrefill: false
  };
}

test('maskThinkingBlocks + unmask is identity for body without thinking blocks', () => {
  const body = '{"messages":[{"role":"user","content":"hello"}]}';
  const { masked, masks } = maskThinkingBlocks(body);
  assert.strictEqual(masks.length, 0);
  assert.strictEqual(unmaskThinkingBlocks(masked, masks), body);
});

test('maskThinkingBlocks preserves thinking content byte-identical across round-trip', () => {
  const thinking = '{"type":"thinking","thinking":"OpenClaw subagents spawn internal reasoning","signature":"sig123"}';
  const body = `{"messages":[{"role":"assistant","content":[${thinking}]}]}`;
  const { masked, masks } = maskThinkingBlocks(body);
  assert.strictEqual(masks.length, 1);
  assert.strictEqual(unmaskThinkingBlocks(masked, masks), body);
});

test('processBody does not mutate OpenClaw trigger inside thinking block', () => {
  // The trigger string `OpenClaw` would normally be sanitized to `OCPlatform`.
  // Inside a thinking block it MUST remain byte-identical.
  const thinking = '{"type":"thinking","thinking":"Analyzing OpenClaw subagents","signature":"s"}';
  const body = `{"messages":[{"role":"assistant","content":[${thinking}]}]}`;
  const out = processBody(body, makeConfig());
  assert.ok(
    out.includes(thinking),
    'thinking block content must be preserved verbatim through processBody'
  );
});

test('reverseMap does not mutate renamed tokens inside thinking block', () => {
  // If the assistant previously produced a thinking block containing an
  // already-renamed token, reverseMap must not rewrite it on the way back.
  const thinking = '{"type":"redacted_thinking","data":"opaque OCPlatform data"}';
  const response = `{"content":[${thinking},{"type":"text","text":"hello"}]}`;
  const { masked, masks } = maskThinkingBlocks(response);
  const reversed = unmaskThinkingBlocks(reverseMap(masked, makeConfig()), masks);
  assert.ok(
    reversed.includes(thinking),
    'redacted_thinking block must survive reverse map byte-identical'
  );
});

test('maskThinkingBlocks handles multiple thinking blocks', () => {
  const t1 = '{"type":"thinking","thinking":"first","signature":"a"}';
  const t2 = '{"type":"thinking","thinking":"second with {nested: braces}","signature":"b"}';
  const body = `[${t1},${t2}]`;
  const { masked, masks } = maskThinkingBlocks(body);
  assert.strictEqual(masks.length, 2);
  assert.strictEqual(unmaskThinkingBlocks(masked, masks), body);
});
