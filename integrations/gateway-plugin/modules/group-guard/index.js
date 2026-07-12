/**
 * group-guard — the group-pin gate, on a SUPPORTED hook.
 *
 * WHY THIS EXISTS
 * ---------------
 * The gate used to be a hand-patch inside the BUILT whatsapp bundle
 * (~/.gateway/extensions/whatsapp/dist/access-control-*.js). That file is re-unpacked
 * from its skill-registry tarball whenever the extension is provisioned, so an gateway update
 * DELETES the patch — with no error and no log line. And it fails OPEN: group-pin.json
 * survives, but the code enforcing it dies, so every number in `groupAllowFrom` could
 * suddenly trigger the bot in EVERY group. The patch author's own comment said
 * "Re-apply after gateway update." It survived the 2026.5.27 bump only by luck.
 *
 * This reimplements the same gate on the `before_dispatch` plugin hook, which is a
 * supported, versioned API that an update cannot silently erase.
 *
 * SEMANTICS — deliberately identical to the dist patch it replaces:
 *   - non-group message            -> allow
 *   - sender in `exempt`           -> allow (any group)
 *   - sender's map[] includes JID  -> allow
 *   - sender absent / JID not listed -> BLOCK  (fail-CLOSED)
 *   - group-pin.json missing or unparseable -> allow (fail-OPEN, matching the original:
 *     a broken config must not brick every group; a corrupt file is loud in the log)
 *
 * Returning { handled: true } with NO text completes the inbound without running the
 * agent and without sending anything — i.e. the bot simply does not react. Verified in
 * dispatch-from-config.ts: `if (beforeDispatchResult?.handled)` → sends only if `text`
 * is set, then `recordProcessed("completed", { reason: "before_dispatch_handled" })`.
 *
 * `senderId` is the E164 for WhatsApp (confirmed against live session records:
 * senderId === senderE164 === "+1..."), so the existing group-pin.json keys work as-is.
 *
 * MODE: set GATEWAY_GROUP_GUARD=observe to log decisions WITHOUT blocking. Used to
 * prove the hook fires correctly before handing it the security role. `enforce` blocks.
 */
const fs = require("node:fs");
const path = require("node:path");

const PIN_PATH = path.join(process.env.HOME || "/home/user", ".gateway", "group-pin.json");
const CACHE_MS = 5000;

let cacheRaw = null;
let cacheVal = null;
let cacheAt = 0;

function loadPin() {
  try {
    const now = Date.now();
    if (now - cacheAt > CACHE_MS) {
      const raw = fs.readFileSync(PIN_PATH, "utf8");
      if (raw !== cacheRaw) {
        cacheRaw = raw;
        cacheVal = JSON.parse(raw);
      }
      cacheAt = now;
    }
    return cacheVal;
  } catch (e) {
    // Fail OPEN, but say so — a silently-disabled gate is how this class of bug hides.
    try {
      console.error(`[group-guard] group-pin.json unreadable (${e.message}) — gate DISABLED (fail-open)`);
    } catch (_) {}
    return null;
  }
}

/** The group JID. `sessionKey` looks like `agent:<id>:whatsapp:group:<jid>@g.us`. */
function groupJidOf(event, ctx) {
  const conv = ctx?.conversationId || event?.conversationId;
  if (typeof conv === "string" && conv.includes("@g.us")) return conv;
  const key = event?.sessionKey || ctx?.sessionKey || "";
  const m = /:group:([^:]+@g\.us)/.exec(String(key));
  return m ? m[1] : null;
}

function activate(api) {
  const mode = (process.env.GATEWAY_GROUP_GUARD || "enforce").toLowerCase();

  api.on(
    "before_dispatch",
    async (event, ctx) => {
      try {
        if (!event?.isGroup) return;

        const sender = event.senderId || ctx?.senderId;
        const jid = groupJidOf(event, ctx);

        // In observe mode, log EVERY group dispatch — not just would-blocks. Sai is exempt,
        // so a would-block-only log would stay empty and prove nothing about whether the
        // hook actually fires with a usable sender/JID on real traffic.
        if (mode === "observe") {
          console.error(`[group-guard] OBSERVE saw sender=${sender || "?"} jid=${jid || "?"}`);
        }
        if (!sender || !jid) {
          // Cannot identify the sender or the room -> cannot make a safe decision.
          // Do NOT block on ambiguity; log so it is visible.
          console.error(
            `[group-guard] indeterminate (sender=${sender || "?"} jid=${jid || "?"}) — allowing`,
          );
          return;
        }

        const pin = loadPin();
        if (!pin) return; // fail-open, already logged

        if ((pin.exempt || []).includes(sender)) return;

        const allowed = (pin.map || {})[sender];
        if (Array.isArray(allowed) && allowed.includes(jid)) return;

        if (mode === "observe") {
          console.error(`[group-guard] OBSERVE would-block ${sender} in ${jid}`);
          return;
        }
        console.error(`[group-guard] BLOCKED ${sender} in ${jid} (group-pin gate)`);
        return { handled: true }; // no text -> agent never runs, nothing is sent
      } catch (e) {
        // A fault in the gate must never break inbound. Fail open, loudly.
        try {
          console.error(`[group-guard] error, failing open: ${e.message}`);
        } catch (_) {}
        return;
      }
    },
    { priority: 100 },
  );

  try {
    console.error(`[group-guard] active (mode=${mode}, pin=${PIN_PATH})`);
  } catch (_) {}
}

module.exports = { activate };
