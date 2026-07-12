const assert = require("node:assert");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const realExecFile = childProcess.execFile;
let inferCalls = 0;

childProcess.execFile = (bin, args, opts, cb) => {
  if (Array.isArray(args) && args[0] === "infer") {
    inferCalls += 1;
    cb(new Error("infer must not be used for deterministic scrub"), "", "unexpected infer call");
    return;
  }

  const script = Array.isArray(args) ? String(args[1] || "") : "";
  const blocked = script.includes("/home/srallaba/.openclaw/workspace/project_agent_guardrail_drift") ||
    script.includes("/home2/srallaba/projects/project_agent_guardrail_drift") ||
    script.includes("https://192.168.1.10:8123/config") ||
    script.includes("sai@example.com") ||
    script.includes("+1 555 123 4567");
  const payload = blocked
    ? { blocked: true, reason: "private outbound leak", findings: ["Absolute local filesystem path"] }
    : { blocked: false, reason: "clean", findings: [] };
  cb(null, JSON.stringify(payload), "");
};

const plugin = require("./index.js");

function makeHook() {
  const hooks = {};
  const memDir = fs.mkdtempSync(path.join(os.tmpdir(), "jataayu-outbound-test-"));
  const api = {
    pluginConfig: {
      python: "python3",
      protectedNames: ["Sai Krishna"],
      declineOnBlock: false,
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

(async () => {
  try {
    const raw = "Fix lives at /home/srallaba/.openclaw/workspace/project_agent_guardrail_drift/index.js for Sai Krishna.";
    const scrubbed = plugin._test.scrubOutboundText(raw, ["Sai Krishna"]);
    assert.equal(scrubbed.changed, true);
    assert.equal(scrubbed.text, "Fix lives at [local path] for [person].");
    assert.deepEqual(scrubbed.hits, ["local-path", "protected-name"]);

    const pii = plugin._test.scrubOutboundText(
      "Email sai@example.com, call +1 555 123 4567, or open https://192.168.1.10:8123/config.",
      []
    );
    assert.equal(pii.text, "Email [email], call [phone], or open [internal url].");
    assert.deepEqual(pii.hits, ["email", "internal-url", "phone"]);

    const send = makeHook();
    const result = await send({
      to: "100000000000000001@g.us",
      content: "Done: /home2/srallaba/projects/project_agent_guardrail_drift is patched.",
    });
    assert.deepEqual(result, { content: "Done: [local path] is patched." });
    assert.equal(inferCalls, 0, "deterministic scrub should avoid LLM rewrite path");

    console.log("all outbound scrub tests passed");
  } finally {
    childProcess.execFile = realExecFile;
  }
})();
