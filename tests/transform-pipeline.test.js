// Transform pipeline tests: processBody (outbound) + reverseMap (inbound).
//
// Verifies Layer 2 (string replacements), Layer 3 (tool renames), Layer 6
// (property renames) and that inbound reverse is a true inverse of outbound
// for a round-trip request body.

const test = require('node:test');
const assert = require('node:assert');
const {
  processBody,
  reverseMap,
  DEFAULT_REPLACEMENTS,
  DEFAULT_TOOL_RENAMES,
  DEFAULT_PROP_RENAMES,
  DEFAULT_REVERSE_MAP
} = require('../proxy');

// Minimal config sufficient for processBody/reverseMap. Uses defaults only.
// stripSystemConfig/stripToolDescriptions/injectCCStubs OFF so tests stay
// focused on the replacement layers.
function makeConfig(overrides = {}) {
  return {
    replacements: DEFAULT_REPLACEMENTS,
    toolRenames: DEFAULT_TOOL_RENAMES,
    propRenames: DEFAULT_PROP_RENAMES,
    reverseMap: DEFAULT_REVERSE_MAP,
    stripSystemConfig: false,
    stripToolDescriptions: false,
    injectCCStubs: false,
    stripTrailingAssistantPrefill: false,
    ...overrides
  };
}

test('processBody renames "subagents" tool to "AgentControl"', () => {
  const body = JSON.stringify({
    tools: [{ name: 'subagents' }],
    messages: []
  });
  const out = processBody(body, makeConfig());
  assert.ok(out.includes('"AgentControl"'), 'expected AgentControl in output');
  assert.ok(!out.includes('"subagents"'), 'expected subagents removed from output');
});

test('processBody renames "create_task" tool to "TaskCreate"', () => {
  const body = JSON.stringify({ tools: [{ name: 'create_task' }], messages: [] });
  const out = processBody(body, makeConfig());
  assert.ok(out.includes('"TaskCreate"'));
  assert.ok(!out.includes('"create_task"'));
});

test('processBody sanitizes OpenClaw trigger string', () => {
  const body = JSON.stringify({
    messages: [{ role: 'user', content: 'Running on OpenClaw' }]
  });
  const out = processBody(body, makeConfig());
  assert.ok(!out.includes('OpenClaw'), 'trigger string must be removed');
  assert.ok(out.includes('OCPlatform'), 'expected replacement token present');
});

test('reverseMap restores tool name on inbound response', () => {
  // Simulate Anthropic response referencing the renamed tool
  const sseChunk = 'event: content_block_start\ndata: {"type":"tool_use","name":"AgentControl"}\n\n';
  const out = reverseMap(sseChunk, makeConfig());
  assert.ok(out.includes('"subagents"'), 'expected subagents restored');
  assert.ok(!out.includes('"AgentControl"'), 'expected AgentControl replaced');
});

test('reverseMap handles escaped tool names in partial_json deltas', () => {
  // input_json_delta embeds tool arg JSON with escaped inner quotes.
  const sseChunk = 'data: {"type":"input_json_delta","partial_json":"{\\"name\\":\\"SendMessage\\"}"}';
  const out = reverseMap(sseChunk, makeConfig());
  assert.ok(
    out.includes('\\"message\\"'),
    'expected escaped SendMessage reversed to escaped message'
  );
});

test('reverseMap restores OCPlatform -> OpenClaw', () => {
  const text = 'Running on the OCPlatform stack';
  const out = reverseMap(text, makeConfig());
  assert.strictEqual(out, 'Running on the OpenClaw stack');
});

test('round-trip: pure-rename tools survive outbound+inbound', () => {
  // Pick tools that participate ONLY in the Layer 3 rename step (no Layer 2
  // string replacement). `sessions_*` tools go through both layers, so their
  // true original name is the `sessions_*` form (see next test).
  const replacedKeys = new Set(
    DEFAULT_REPLACEMENTS
      .filter(([, replace]) => DEFAULT_TOOL_RENAMES.some(([orig]) => orig === replace))
      .map(([, replace]) => replace)
  );
  const pureRenames = DEFAULT_TOOL_RENAMES
    .map(([orig]) => orig)
    .filter(n => !replacedKeys.has(n));

  assert.ok(pureRenames.length > 0, 'expected at least one pure-rename tool');

  const body = JSON.stringify({
    tools: pureRenames.map(n => ({ name: n })),
    messages: []
  });
  const config = makeConfig();
  const restored = reverseMap(processBody(body, config), config);

  for (const name of pureRenames) {
    assert.ok(
      restored.includes(`"${name}"`),
      `pure-rename tool ${name} not restored after round-trip`
    );
  }
});

test('round-trip: sessions_* tools go through both replace and rename layers', () => {
  // OC-native sessions_* names are the true originals. They become
  // `sessions_list` -> `list_tasks` -> `TaskList` outbound, then
  // `TaskList` -> `list_tasks` -> `sessions_list` inbound.
  const ocNativeNames = [
    'sessions_spawn',
    'sessions_list',
    'sessions_history',
    'sessions_send',
    'sessions_yield',
    'sessions_store',
    'sessions_yield_interrupt'
  ];
  const body = JSON.stringify({
    tools: ocNativeNames.map(n => ({ name: n })),
    messages: []
  });
  const config = makeConfig();
  const restored = reverseMap(processBody(body, config), config);

  for (const name of ocNativeNames) {
    assert.ok(
      restored.includes(`"${name}"`),
      `sessions_* tool ${name} not restored after round-trip`
    );
  }
});

test('processBody renames property "session_id" to "thread_id"', () => {
  const body = JSON.stringify({ foo: { session_id: 'abc' } });
  const out = processBody(body, makeConfig());
  assert.ok(out.includes('"thread_id"'));
  assert.ok(!out.includes('"session_id"'));
});

test('processBody does NOT rename unquoted occurrences of tool names', () => {
  // Layer 3 uses quoted replacement (`"name"` -> `"Name"`) for precision.
  // A substring like `create_task_something` (no quotes) should not be touched.
  const body = JSON.stringify({
    messages: [{ role: 'user', content: 'create_task_something in prose' }]
  });
  const out = processBody(body, makeConfig());
  assert.ok(
    out.includes('create_task_something'),
    'tool rename must not match unquoted prose substrings'
  );
});
