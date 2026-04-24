// Regression tests for CC_TOOL_STUBS.
//
// CC_TOOL_STUBS is decoy camouflage injected into the outbound tools array to
// make the tool set look like a Claude Code session. Stubs MUST be names the
// model is unlikely to actually call — if the model invokes one, there's no
// local implementation and no reverse mapping, so the client errors out.
//
// Specifically, "Agent" was previously included (proxy.js:67, removed
// 2026-04-23). Claude Code's native subagent-spawning tool is called "Agent",
// so the model happily called it — producing 80+ failed retries per session
// because the real OC subagent tool is renamed `subagents` -> `AgentControl`
// and `create_task` -> `TaskCreate`, not `Agent`.

const test = require('node:test');
const assert = require('node:assert');
const { CC_TOOL_STUBS, DEFAULT_TOOL_RENAMES } = require('../proxy');

function stubNames() {
  return CC_TOOL_STUBS.map(s => JSON.parse(s).name);
}

test('CC_TOOL_STUBS does not include phantom "Agent" tool', () => {
  assert.ok(
    !stubNames().includes('Agent'),
    'The "Agent" stub is a phantom — the model calls it but there is no backing tool. ' +
    'Real subagent spawning uses `subagents` -> `AgentControl` or `create_task` -> `TaskCreate`.'
  );
});

test('CC_TOOL_STUBS entries are valid JSON with name + input_schema', () => {
  for (const raw of CC_TOOL_STUBS) {
    const parsed = JSON.parse(raw);
    assert.ok(parsed.name, `stub missing name: ${raw}`);
    assert.ok(parsed.input_schema, `stub missing input_schema: ${parsed.name}`);
    assert.strictEqual(typeof parsed.name, 'string');
  }
});

test('CC_TOOL_STUBS names do not collide with tool rename targets', () => {
  // A stub colliding with a rename target would mean two tool schemas share a
  // name in the outbound tools array — Anthropic rejects duplicate names.
  const renameTargets = new Set(DEFAULT_TOOL_RENAMES.map(([, cc]) => cc));
  const collisions = stubNames().filter(n => renameTargets.has(n));
  assert.deepStrictEqual(
    collisions, [],
    `Stub names collide with rename targets: ${collisions.join(', ')}`
  );
});

test('CC_TOOL_STUBS does not include names semantically appealing for subagent dispatch', () => {
  // Guard against future regressions re-introducing phantoms that the model
  // will invoke. Keep this list short and specific.
  const phantomTraps = ['Agent', 'Task', 'Subagent', 'SpawnAgent', 'LaunchAgent'];
  const hits = stubNames().filter(n => phantomTraps.includes(n));
  assert.deepStrictEqual(
    hits, [],
    `Phantom stub(s) present — the model will call these and fail: ${hits.join(', ')}`
  );
});
