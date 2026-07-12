// Outbound gate: REWRITE-to-send, not refuse-to-send.
//
// The behaviour under test is the one that was broken in production on 2026-07-12: a group reply
// that mentioned an absolute path was dropped and replaced with a canned apology ("I drafted a
// reply... so I'm not sending it"). Five times. Every one of them was a bare path leak — a thing
// the guard could simply have rewritten. These tests assert the message now LANDS.
//
// Hermetic: child_process.execFile is stubbed, so no Python, no gateway, no network, no real send.
// The stub stands in for jataayu_recover_outbound and asserts the plugin honours its contract.

const assert = require("node:assert");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const realExecFile = childProcess.execFile;

let recoverCalls = [];
let alertCalls = [];
let nextRecover = null;
let guardExplodes = false;

// index.js destructures execFile at require() time, so this stub must be installed BEFORE the
// require below and must never be reassigned afterwards — the plugin would keep the old reference.
// Later tests steer it through the flags above instead.
childProcess.execFile = (bin, args, opts, cb) => {
  // alertOwner() — the out-of-band ping to Sai when a credential is withheld.
  if (Array.isArray(args) && args[0] === "message" && args[1] === "send") {
    alertCalls.push({ target: args[args.indexOf("--target") + 1], message: args[args.indexOf("--message") + 1] });
    const child = { unref() {} };
    if (cb) cb(null, "", "");
    return child;
  }

  const script = Array.isArray(args) ? String(args[1] || "") : "";
  if (script.includes("jataayu_recover_outbound")) {
    recoverCalls.push(script);
    if (guardExplodes) { cb(new Error("python exploded"), "", "boom"); return; }
    cb(null, JSON.stringify(nextRecover), "");
    return;
  }

  cb(null, JSON.stringify({ blocked: false, reason: "clean", findings: [] }), "");
};

const plugin = require("./index.js");

function makeHook() {
  const hooks = {};
  const memDir = fs.mkdtempSync(path.join(os.tmpdir(), "jataayu-outbound-test-"));
  const api = {
    pluginConfig: {
      python: "python3",
      gatewayBin: "/fake/gateway",
      protectedNames: ["Sai Krishna"],
      alertDiscordTarget: "user:12345",
      quarantinePath: path.join(memDir, "quarantine.jsonl"),
      capturePath: path.join(memDir, "capture.jsonl"),
      dmGuard: { memDir, ownerRecipients: [], allowReactivate: true },
    },
    on: (name, handler) => { (hooks[name] = hooks[name] || []).push(handler); },
    registerTool: () => {},
  };
  plugin.activate(api);
  const handlers = hooks.message_sending || [];
  assert.ok(handlers.length > 0, "message_sending hook should be registered");
  return async (event) => {
    let result;
    for (const handler of handlers) {
      const next = await handler(event, {});
      if (next !== undefined) result = next;
    }
    return result;
  };
}

const GROUP = "100000000000000001@g.us";

(async () => {
  try {
    const send = makeHook();

    // 1. The exact 2026-07-12 decline. The LLM strips the path; the message is DELIVERED, with its
    //    answer intact. This is the whole point: the group learns the project was scaffolded, and
    //    does not learn where it lives on disk.
    nextRecover = {
      action: "send",
      text: "Done: project_agent_guardrail_drift is patched.",
      changed: true,
      withheld_category: null,
      findings: ["Absolute local filesystem path"],
      reason: "rephrased by the LLM and re-screened clean",
      stages: ["llm-rephrase"],
      llm_used: true,
    };
    let result = await send({
      to: GROUP,
      content: "Done: /home2/srallaba/projects/project_agent_guardrail_drift is patched.",
    });
    assert.deepEqual(result, { content: "Done: project_agent_guardrail_drift is patched." },
      "a path leak must be rewritten and SENT, never declined");
    assert.equal(alertCalls.length, 0, "a path leak is not worth waking Sai for");

    // 2. A clean message is passed through untouched — the hook must return undefined, not a
    //    rewritten copy, or every message in every group would be needlessly reconstructed.
    nextRecover = { action: "send", text: "all good", changed: false, findings: [], reason: "already clean", stages: [], llm_used: false };
    result = await send({ to: GROUP, content: "all good" });
    assert.equal(result, undefined, "a clean message must pass through untouched");

    // 3. Credential: the one hard floor. Nothing is rewritten, nothing is sent, and Sai is told
    //    out-of-band. The group still hears something — silence would fail them too.
    recoverCalls = []; alertCalls = [];
    nextRecover = {
      action: "withhold",
      text: "",
      changed: false,
      withheld_category: "credential",
      findings: ["[CRED_013] Anthropic API key (sk-ant-...)"],
      reason: "credential leak — withheld rather than rephrased",
      stages: [],
      llm_used: false,
    };
    result = await send({ to: GROUP, content: "here you go: sk-ant-api03-XXXX" });
    assert.ok(result && result.content, "a withheld credential must still produce a reply, not silence");
    assert.ok(!/sk-ant/.test(result.content), "the decline must not echo the credential");
    assert.equal(alertCalls.length, 1, "a withheld credential MUST alert Sai");
    assert.equal(alertCalls[0].target, "user:12345");
    assert.ok(/credential/i.test(alertCalls[0].message));

    // 4. Unrecoverable: rewrite AND redaction both failed. Rare, and a real failure — but the
    //    recipient still gets a reply rather than being left waiting on nothing.
    alertCalls = [];
    nextRecover = {
      action: "withhold",
      text: "",
      changed: true,
      withheld_category: "unrecoverable",
      findings: ["Internal strategy codename: Cassandra"],
      reason: "still leaking after llm-rephrase → redact",
      stages: ["llm-rephrase", "redact"],
      llm_used: true,
    };
    result = await send({ to: GROUP, content: "the Cassandra numbers are strong" });
    assert.ok(result && result.content, "an unrecoverable block must still say something");
    assert.ok(!/Cassandra/i.test(result.content), "the decline must not echo the leak");
    assert.equal(alertCalls.length, 0, "only credentials alert Sai");

    // 5. Owner DMs are never screened — they legitimately carry family and internal context.
    //    (Fixture identifiers only. This repo is public: no real number or id belongs in it.)
    recoverCalls = [];
    const OWNER = "+15550001111";
    const dmHooks = {};
    const memDir = fs.mkdtempSync(path.join(os.tmpdir(), "jataayu-dm-test-"));
    plugin.activate({
      pluginConfig: {
        python: "python3",
        ownerRecipients: [OWNER],
        quarantinePath: path.join(memDir, "q.jsonl"),
        dmGuard: { memDir, ownerRecipients: [], allowReactivate: true },
      },
      on: (n, h) => { (dmHooks[n] = dmHooks[n] || []).push(h); },
      registerTool: () => {},
    });
    for (const h of dmHooks.message_sending || []) {
      await h({ to: OWNER, content: "Your key is in /home2/user/.env" }, {});
    }
    assert.equal(recoverCalls.length, 0, "owner DMs must never reach the outbound guard");

    // 6. The guard is a subprocess. When it dies, comms must NOT die with it — a broken guard that
    //    silences every group is a worse outage than the leak it was protecting against.
    guardExplodes = true;
    result = await send({ to: GROUP, content: "Done: /home2/srallaba/projects/x is patched." });
    guardExplodes = false;
    assert.equal(result, undefined, "a dead guard must fail OPEN, not cancel the send");

    console.log("all outbound recover tests passed (6/6)");
  } finally {
    childProcess.execFile = realExecFile;
  }
})();
