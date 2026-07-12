const assert = require("node:assert");
const { activate } = require("./index.js");

let handler;
const api = { on: (name, fn) => { if (name === "before_dispatch") handler = fn; } };
process.env.GATEWAY_GROUP_GUARD = "enforce";
activate(api);

const PUB = "100000000000000001@g.us";     // Publishable Research
const OTHER = "100000000000000002@g.us";   // Humanoid Alpha
const SAI = "+15551234567";                // exempt (fictional)
const PARAG = "+15550000002";              // pinned to PUB only
const STRANGER = "+19999999999";           // in groupAllowFrom? irrelevant — not in the pin map

const ev = (senderId, jid, isGroup = true) => [
  { isGroup, senderId, sessionKey: `agent:sai:whatsapp:group:${jid}` },
  { conversationId: jid, senderId },
];

(async () => {
  const cases = [
    ["DM (not a group) -> allow",              await handler(...ev(STRANGER, PUB, false)), undefined],
    ["exempt Sai in Publishable -> allow",     await handler(...ev(SAI, PUB)),             undefined],
    ["exempt Sai in another group -> allow",   await handler(...ev(SAI, OTHER)),           undefined],
    ["Parag in Publishable (pinned) -> allow", await handler(...ev(PARAG, PUB)),           undefined],
  ];
  for (const [name, got, want] of cases) {
    assert.deepStrictEqual(got, want, `${name}: expected allow, got ${JSON.stringify(got)}`);
    console.log(`  PASS  ${name}`);
  }

  const blocked = [
    ["Parag in a group he is NOT pinned to -> BLOCK", await handler(...ev(PARAG, OTHER))],
    ["stranger in Publishable -> BLOCK",              await handler(...ev(STRANGER, PUB))],
    ["stranger in any group -> BLOCK",                await handler(...ev(STRANGER, OTHER))],
  ];
  for (const [name, got] of blocked) {
    assert.deepStrictEqual(got, { handled: true }, `${name}: expected block, got ${JSON.stringify(got)}`);
    assert.ok(!("text" in (got || {})), "a block must send NOTHING");
    console.log(`  PASS  ${name}`);
  }

  // Ambiguity must not block (no sender / no jid).
  assert.deepStrictEqual(await handler({ isGroup: true }, {}), undefined);
  console.log("  PASS  indeterminate sender/jid -> allow (no false block)");
  console.log("\nall group-guard tests passed");
})();
