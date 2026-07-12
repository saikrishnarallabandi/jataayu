/**
 * group-capture — the WhatsApp group shadow-log, on a SUPPORTED hook.
 *
 * WHY THIS EXISTS
 * ---------------
 * This used to be a hand-patch inside the BUILT whatsapp bundle
 * (~/.gateway/extensions/whatsapp/dist/monitor-*.js), hooking
 * `skipGroupMessageAndStoreHistory` to append every ambient group message to
 * memory/group-capture/YYYY-MM-DD.jsonl.
 *
 * That patch is deleted by any gateway update — the extension is re-unpacked from its
 * skill-registry tarball. It survived the 2026.5.27 bump only by luck, and the 2026.6.11 upgrade
 * finally wiped it (the bundle even changed shape, so the saved patch no longer applies).
 *
 * 2026.6.11 exposes `message_received` as an opt-in WhatsApp plugin hook
 * (channels.whatsapp.pluginHooks.messageReceived), which fires for BOTH `dispatch` and
 * `observe` admissions — `observe` being exactly the ambient group chatter the bot does not
 * reply to, i.e. what the old patch captured. Verified in
 * extensions/whatsapp/src/auto-reply/monitor/process-message.ts:507, emitted before the
 * dispatch/observe branch.
 *
 * So the capture is now a plugin on a versioned API. With this, ZERO hand-patched bundles
 * remain, and an gateway update can no longer silently delete our behaviour.
 *
 * Enabling the hook also wakes dm-guard's inbound feed, which has been running on an empty
 * feed because WhatsApp never emitted `message_received` without the opt-in.
 *
 * SCHEMA: byte-compatible with the old patch so downstream readers keep working —
 *   captured_at, group_jid, sender_e164, sender_name, sender_jid, body, msg_id, msg_ts, account_id
 * Unknown/renamed fields are recovered from `metadata` where possible; anything genuinely
 * absent is written as null rather than guessed. Set GATEWAY_GROUP_CAPTURE=debug to log the
 * real event shape once, so the mapping can be tightened against live data.
 */
const fs = require("node:fs");
const path = require("node:path");

const DIR = path.join(
  process.env.HOME || "/home/user",
  ".gateway", "workspace", "memory", "group-capture",
);

let loggedShape = false;

function pick(...vals) {
  for (const v of vals) {
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return null;
}

/** The group JID, or null for a DM (we only capture groups). */
function groupJid(event, ctx) {
  for (const c of [ctx?.conversationId, event?.from, event?.sessionKey, ctx?.sessionKey]) {
    if (typeof c === "string" && c.includes("@g.us")) {
      const m = /([\w-]+@g\.us)/.exec(c);
      if (m) return m[1];
    }
  }
  return null;
}

function activate(api) {
  const debug = (process.env.GATEWAY_GROUP_CAPTURE || "").toLowerCase() === "debug";

  api.on(
    "message_received",
    async (event, ctx) => {
      try {
        const jid = groupJid(event, ctx);
        if (!jid) return; // DMs are not captured — this is the GROUP shadow log

        const md = (event && event.metadata) || {};

        if (debug && !loggedShape) {
          loggedShape = true;
          console.error(
            `[group-capture] event keys=${Object.keys(event || {})} ctx keys=${Object.keys(ctx || {})} metadata keys=${Object.keys(md)}`,
          );
        }

        const row = {
          captured_at: new Date().toISOString(),
          group_jid: jid,
          sender_e164: pick(event.senderId, ctx?.senderId, md.senderE164),
          sender_name: pick(md.senderName, md.pushName, ctx?.senderName, event.senderName),
          // NOT event.from -- that is the CONVERSATION (the group JID), which would make
          // sender_jid identical to group_jid.
          // CAVEAT: `message_received` does NOT expose the raw Baileys `@lid` the old dist
          // patch recorded here (metadata carries senderId/senderName/senderE164/senderUsername
          // but no LID). So on rows written from 2026-07-11 onward this falls back to the E164
          // and therefore mirrors sender_e164. It is a real sender identifier, not a guess --
          // but it is NOT the same value the pre-2026-07-11 rows carry. Do not join across the
          // boundary on this field; use sender_e164.
          sender_jid: pick(md.senderJid, md.participant, md.senderUsername, md.senderId),
          body: pick(event.content, event.body, ""),
          msg_id: pick(event.messageId, md.messageId),
          msg_ts: pick(event.timestamp, md.timestamp),
          account_id: pick(ctx?.accountId, md.accountId, "default"),
        };

        fs.mkdirSync(DIR, { recursive: true });
        const file = path.join(DIR, `${row.captured_at.slice(0, 10)}.jsonl`);
        fs.appendFileSync(file, JSON.stringify(row) + "\n");
      } catch (e) {
        // A capture failure must never affect message handling. Log and move on.
        try {
          console.error(`[group-capture] write failed (inbound unaffected): ${e.message}`);
        } catch (_) {}
      }
    },
    { priority: 50 },
  );

  try {
    console.error(`[group-capture] active (dir=${DIR}${debug ? ", debug" : ""})`);
  } catch (_) {}
}

module.exports = { activate };
