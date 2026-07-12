// group-guard tests — HERMETIC. No real phone numbers, no real group ids, and no dependency on the
// machine's live ~/.gateway/group-pin.json.
//
// This test used to read the OPERATOR'S REAL group-pin.json (PIN_PATH is derived from $HOME) and
// hardcoded real phone numbers — the owner's, and a group member's — in a PUBLIC repo. Two problems
// in one: third-party PII published to the internet, and a test whose result depended on the state
// of one particular laptop. It broke the instant the numbers were scrubbed, which is how it was
// found (2026-07-11).
//
// $HOME is redirected to a temp dir holding a fixture pin BEFORE index.js is required — PIN_PATH is
// computed at module load, so the order matters.
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const HOME = fs.mkdtempSync(path.join(os.tmpdir(), "group-guard-test-"));
fs.mkdirSync(path.join(HOME, ".gateway"), { recursive: true });
process.env.HOME = HOME;

const OWNER = "+15550000001";      // exempt everywhere
const MEMBER = "+15550000002";     // pinned to PUB only
const STRANGER = "+15550000003";   // pinned nowhere
const PUB = "100000000000000001@g.us";
const OTHER = "100000000000000002@g.us";

// Real schema: { exempt: [sender], map: { sender: [jid, ...] } }
fs.writeFileSync(
  path.join(HOME, ".gateway", "group-pin.json"),
  JSON.stringify({ exempt: [OWNER], map: { [MEMBER]: [PUB] } }, null, 2),
);

process.env.GATEWAY_GROUP_GUARD = "enforce";
const { activate } = require("./index.js");

let handler;
const api = { on: (name, fn) => { if (name === "before_dispatch") handler = fn; } };
activate(api);

const ev = (senderId, jid, isGroup = true) => [
  { isGroup, senderId, sessionKey: `agent:sai:whatsapp:group:${jid}` },
  { conversationId: jid, senderId },
];

(async () => {
  const cases = [
    ["DM (not a group) -> allow",                await handler(...ev(STRANGER, PUB, false)), undefined],
    ["exempt owner in Publishable -> allow",     await handler(...ev(OWNER, PUB)),           undefined],
    ["exempt owner in another group -> allow",   await handler(...ev(OWNER, OTHER)),         undefined],
    ["pinned member in his group -> allow",      await handler(...ev(MEMBER, PUB)),          undefined],
  ];
  for (const [name, got, want] of cases) {
    assert.deepStrictEqual(got, want, `${name}: expected allow, got ${JSON.stringify(got)}`);
    console.log(`  PASS  ${name}`);
  }

  const blocked = [
    ["pinned member in a group he is NOT pinned to -> BLOCK", await handler(...ev(MEMBER, OTHER))],
    ["stranger in Publishable -> BLOCK",                      await handler(...ev(STRANGER, PUB))],
    ["stranger in any group -> BLOCK",                        await handler(...ev(STRANGER, OTHER))],
  ];
  for (const [name, got] of blocked) {
    assert.deepStrictEqual(got, { handled: true }, `${name}: expected block, got ${JSON.stringify(got)}`);
    assert.ok(!("text" in (got || {})), "a block must send NOTHING");
    console.log(`  PASS  ${name}`);
  }

  // Ambiguity must not block (no sender / no jid).
  assert.deepStrictEqual(await handler({ isGroup: true }, {}), undefined);
  console.log("  PASS  indeterminate sender/jid -> allow (no false block)");

  fs.rmSync(HOME, { recursive: true, force: true });
  console.log("\nall group-guard tests passed");
})();
