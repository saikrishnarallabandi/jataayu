/**
 * dm-guard — outbound hygiene for Judith (rev 3, 2026-07-11)
 *
 * WHY THIS IS A HOOK AND NOT A RULE IN A MARKDOWN FILE:
 * Every behavioural failure on 2026-07-11 came from a rule written somewhere the model could
 * reason its way past. The two things that DID hold were enforced by the gateway: the group
 * systemPrompt, and the Jataayu message_sending hook. So output hygiene is enforced HERE, at the
 * wire, where it cannot be skipped.
 *
 * ============================================================================================
 * THE GOVERNING CONSTRAINT (Sai, 2026-07-11): "volume is not an issue for me. until i tell u
 * otherwise, i love volume."
 *
 * So this plugin is NOT a throttle, a rate limiter, or a batcher. It never reduces the number of
 * messages that carry information. It removes exactly four classes of DEFECT — outputs that carry
 * ZERO information, so deleting them loses nothing:
 *
 *   A/B  A DUPLICATE. The same bytes, or the same file, sent to the same chat twice.
 *        (mp3 mem1_..._ep24_2026-07-11.mp3 -> group at 07:23:49 AND 07:24:30 CDT;
 *         byte-identical text -> same group at 08:53:08 AND 08:53:12 CDT.)
 *        A duplicate is a defect, not volume.
 *   C    A FILLER ACK. "Done." x12, "Sent." x6, "Stored." x2, "Handled." x1 in his DM in one day.
 *        No artifact, no link, no number, no path. A phone buzz with nothing in it.
 *   G    A LEAKED SENTINEL. The literal string "NO_REPLY" was SENT as a message 5 times today
 *        (07:29, 10:54, 12:34, 12:39, 14:16 CDT). That is the model's don't-reply marker escaping
 *        as message content. It is never something a human should read.
 *   I    A SYSTEM-PROMPT DUMP. Chunks of Judith's own instructions echoed verbatim into the DM.
 *
 * Plus one non-suppressing REPAIR:
 *   H    ABSOLUTE PATHS IN A DM are rewritten, not dropped: /home2/srallaba/projects/x/y.py
 *        becomes ~/projects/x/y.py. The receipt survives (his DM systemPrompt explicitly demands
 *        "exact files touched"); only the machine-absolute prefix goes. Jataayu already covers
 *        group surfaces, so H is DM-only and cannot collide with it.
 *
 * Everything that COULD reduce the count of informative messages — near-duplicate collapsing,
 * same-turn burst dropping, closed-decision suppression — is present but DEFAULT OFF, and stays
 * off until Sai says volume is a problem. In particular: the ~20 "Published on X/Instagram/
 * Threads/YouTube" notices carry information and must keep flowing. There is a test for that.
 * ============================================================================================
 *
 * DESIGN RULES (in order of importance):
 *   1. FAIL OPEN. A broken guard must never take Sai's comms down. Everything is in try/catch;
 *      the host also swallows hook exceptions and delivers anyway.
 *   2. A FALSE SUPPRESSION IS WORSE THAN THE NOISE. Every enabled rule is EXACT: a content hash,
 *      a media basename, a hand-written filler list, a literal sentinel, a verbatim shingle match.
 *      Nothing enabled here suppresses on "looks similar-ish".
 *   3. THE USER CAN ALWAYS UNSTICK IT. If an inbound arrives in a conversation after we sent X,
 *      sending X again is a REPLY to him, not a repeat -- the dedup rules are bypassed.
 *      ("Send that again", "resend the file", "post it in the group too" must all still work.)
 *   4. NEVER SILENCE A MEDIA SEND on ack grounds. Rule C only ever fires on a bare text payload
 *      with no attachment ("Done." as a caption on the podcast still goes out).
 *
 * SCOPE: dedup + ack + sentinel rules apply to ALL surfaces (bug A hit DMs *and* groups).
 * The path rewrite (H), system-prompt-dump drop (I) and closed-decision rule (E) are DM-only;
 * groups are Jataayu's business.
 *
 * WIRING: activated from plugins/jataayu/index.js -- the gateway does not load a hooks-only
 * plugin as a standalone entry (it registers no tools, so it never lands in the loaded set;
 * see commit da34f43). Because of that, api.pluginConfig here is JATAAYU's config, and our knobs
 * live under its `dmGuard` sub-object. The message_sending hook is registered at priority 200 so
 * it runs BEFORE Jataayu's own (priority 100; hooks run highest-priority-first) -- a duplicate
 * should never even reach the privacy scan.
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const DEFAULTS = {
  memDir: "/home/srallaba/.gateway/workspace/memory",

  // ===== ON: zero-information defects. Removing these loses nothing. =========================

  // --- A: exact duplicate (same target, same bytes) ---
  dupWindowSec: 120,

  // --- B: same media file re-sent to the same target (caption may differ) ---
  mediaWindowSec: 600,

  // --- C: content-free turn-final ack ("Done." / "Sent." / "Stored." / "Handled.") ---
  emptyAck: true,
  emptyAckMaxChars: 40,

  // --- G: the NO_REPLY sentinel leaking out as message content (5x today) ---
  sentinels: ["no_reply", "noreply", "no reply"],

  // --- H: absolute paths in a DM -> rewritten to ~, NOT dropped. The receipt survives. ---
  pathScrubDm: true,
  homePrefixes: ["/home2/srallaba", "/home/srallaba"],

  // --- I: a verbatim dump of Judith's own system prompt into the DM ---
  systemPromptGuard: true,
  configPath: "/home/srallaba/.gateway/gateway.json",
  shingleWords: 12,      // a normal reply never reproduces 12 consecutive words of the prompt
  shingleHits: 3,        // ...let alone 3 separate runs of them

  // ===== OFF: anything that could reduce the count of INFORMATIVE messages. ==================
  // Sai 2026-07-11: "volume is not an issue for me. until i tell u otherwise, i love volume."
  // These stay off until he says otherwise. They are kept (and tested) so they can be flipped on.

  // --- D: near-duplicate. Collapses reworded restatements. Fuzzy => can eat a real message. ---
  nearDup: false,
  nearDupWindowSec: 600,
  nearDupThreshold: 0.92,
  nearDupMinTokens: 8,   // below this, jaccard is meaningless: "Episode 24 is up." and
                         // "Episode 25 is up." both reduce to {episode} and score 1.0.

  // --- E: re-opening a decision Sai already closed (owner DM only) ---
  // Drops the WHOLE message on a topic-term substring hit -- too blunt to run while volume is fine.
  closedDecisions: false,
  askedWindowMin: 45,

  // --- F: same-turn burst (ANY 2nd DM in the window, even with different content) ---
  // Would eat the second half of a turn that sends "here is the summary" then "here is the file".
  burstDropSameTurn: false,
  burstWindowSec: 150,

  // Owner DM addresses. NO DEFAULT ON PURPOSE — this is a public repo and these are personal
  // contact details (they were hardcoded here until 2026-07-11). Supply them in gateway.json
  // under plugins.entries.jataayu.config.dmGuard.ownerRecipients. With none configured, the
  // owner-DM rules simply do not match, which fails OPEN (nothing is suppressed) — consistent
  // with design rule 1.
  ownerRecipients: [],
  keepSent: 500,
  keepInbound: 200,
};

// ---------------------------------------------------------------------------------------------
// text helpers
// ---------------------------------------------------------------------------------------------

/** Light normalisation for the EXACT-dup hash: whitespace + case only. Nothing semantic. */
const normExact = (s) => String(s || "").replace(/\s+/g, " ").trim().toLowerCase();

/** Aggressive normalisation, for the similarity check only. */
const norm = (s) =>
  String(s || "")
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, " ")
    .replace(/`[^`]*`/g, " ")
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();

const STOP = new Set(["the","a","an","and","or","but","to","of","in","on","is","it","that","this",
  "i","you","we","for","with","as","at","be","was","were","are","not","no","so","if","then","now"]);

const tokens = (s) => new Set(norm(s).split(" ").filter((w) => w.length > 2 && !STOP.has(w)));

/** Jaccard over content tokens. Robust to reordering and to differing preambles. */
function similarity(a, b) {
  const A = tokens(a), B = tokens(b);
  if (!A.size || !B.size) return 0;
  let inter = 0;
  for (const t of A) if (B.has(t)) inter++;
  return inter / (A.size + B.size - inter);
}

const sha256 = (s) => crypto.createHash("sha256").update(String(s), "utf8").digest("hex");

/**
 * The hard payload of a message: numbers, links, filenames, ids. Two messages that carry
 * different signals are NEVER the same message, however similar the prose around them reads.
 * Used only as a veto on the (opt-in) fuzzy near-dup rule.
 */
function signals(s) {
  const t = String(s || "");
  const out = new Set();
  for (const m of t.match(/https?:\/\/\S+/g) || []) out.add(m.toLowerCase());
  for (const m of t.match(/\b[\w.-]+\.(mp3|mp4|wav|pdf|png|jpg|csv|json|md|py|js|ts|sh|yml|yaml)\b/gi) || []) {
    out.add(m.toLowerCase());
  }
  for (const m of t.match(/\d+/g) || []) out.add(m);
  return [...out];
}

/** Media identity: basename only. The same file re-attached gets a fresh tmp path but one name. */
function mediaKeys(mediaUrls) {
  const list = Array.isArray(mediaUrls) ? mediaUrls : (mediaUrls ? [mediaUrls] : []);
  return list
    .map((u) => {
      const s = String(u || "").trim();
      if (!s) return "";
      const noQuery = s.split("?")[0].split("#")[0];
      const base = noQuery.split("/").pop() || noQuery;
      return base.toLowerCase();
    })
    .filter(Boolean)
    .sort();
}

/** Target identity: the conversation we are sending into. */
const targetKey = (to) => String(to || "").trim().toLowerCase();

// ---------------------------------------------------------------------------------------------
// RULE C -- content-free ack
// ---------------------------------------------------------------------------------------------
/**
 * Deliberately a CLOSED LIST, not a heuristic.
 *
 * We cannot reliably tell "Done." (noise) from "Yes." (the answer to a direct question) at the
 * wire: both are short, both follow an inbound, and the hook cannot see the question. So rather
 * than guess, we suppress ONLY the completion-ack family actually observed in the logs, plus close
 * variants of it, matched against the WHOLE message. Anything outside this list ships.
 *
 * NOT on this list, on purpose:
 *   "Yes." / "No." / "Correct." / "It works." -- these ARE the answer to a yes/no question.
 *   "Fixed." / "Merged." / "Deployed."        -- content-free, but plausibly the literal answer
 *                                                to "did you fix/merge/deploy it?".
 *   anything with a digit, URL, filename, or an attachment -- that is a payload, not filler.
 */
const ACK_CORE = "(done|sent|stored|saved|handled|noted|logged|posted|updated|ack|acknowledged" +
                 "|ok|okay|kk|k|got it|on it|onit|will do|understood|roger|copy|copy that|sure)";
const ACK_RE = new RegExp(
  "^\\s*(all\\s+|it'?s\\s+|that'?s\\s+|already\\s+)?" +      // "all done", "it's done"
  ACK_CORE +
  "(\\s+(it|that|this|now|already|there|for you))?" +        // "done it", "noted that", "sent now"
  "\\s*[.!…]*\\s*$",
  "i",
);
const HAS_DIGIT = /\d/;
const HAS_URL =
  /https?:\/\/|www\.|\b\S+\.(com|org|net|io|dev|ai|co|md|py|js|ts|json|mp3|mp4|wav|pdf|png|jpg|csv|sh|yml|yaml)\b/i;

/** Strip emoji/markdown decoration so "Done ✅" and "**Done.**" both match the closed list. */
const stripDecoration = (s) =>
  String(s || "")
    .replace(/[*_~`>#\-]/g, " ")
    .replace(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}\u{2705}\u{1F44D}]/gu, " ")
    .replace(/\s+/g, " ")
    .trim();

function isContentFreeAck(content, hasMedia, maxChars) {
  if (hasMedia) return false;                                 // never silence an attachment
  const raw = String(content || "").trim();
  if (!raw) return false;
  if (raw.length >= (maxChars || DEFAULTS.emptyAckMaxChars)) return false;
  if (raw.includes("?")) return false;                        // a question is never filler
  if (HAS_DIGIT.test(raw)) return false;                      // a number is a payload
  if (HAS_URL.test(raw)) return false;                        // a link / filename is a payload
  return ACK_RE.test(stripDecoration(raw));
}

// ---------------------------------------------------------------------------------------------
// RULE G -- leaked sentinel
// ---------------------------------------------------------------------------------------------
/**
 * "NO_REPLY" is the model's marker for "this turn produces no message". It was SENT as the
 * message body 5 times today. Only ever fires when the sentinel is the ENTIRE body (after
 * stripping quotes/backticks/punctuation) -- a message that merely *mentions* NO_REPLY while
 * explaining the bug is a real message and ships.
 */
function isLeakedSentinel(content, sentinels) {
  const bare = String(content || "")
    .trim()
    .replace(/^[`'"*_\[(]+|[`'"*_\])]+$/g, "")
    .replace(/[.!…]+$/, "")
    .trim()
    .toLowerCase();
  if (!bare) return false;
  return (sentinels || []).some((s) => bare === String(s).toLowerCase());
}

// ---------------------------------------------------------------------------------------------
// RULE H -- absolute paths in a DM (REWRITE, never a drop)
// ---------------------------------------------------------------------------------------------
/**
 * His DM systemPrompt explicitly demands receipts -- "exact files touched". So a path in a DM is
 * NOT noise, it is the payload. We keep the receipt and drop only the machine-absolute prefix:
 *   /home2/srallaba/projects/project_ascent/scripts/apply.py  ->  ~/projects/project_ascent/scripts/apply.py
 * Returns the rewritten string, or null when nothing changed.
 */
function scrubPaths(content, homePrefixes) {
  let out = String(content || "");
  for (const p of (homePrefixes || [])) {
    if (!p) continue;
    const esc = String(p).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    out = out.replace(new RegExp(esc, "g"), "~");
  }
  return out === String(content || "") ? null : out;
}

// ---------------------------------------------------------------------------------------------
// RULE I -- verbatim system-prompt dump
// ---------------------------------------------------------------------------------------------
const words = (s) => norm(s).split(" ").filter(Boolean);

function shingles(list, n) {
  const out = new Set();
  for (let i = 0; i + n <= list.length; i++) out.add(list.slice(i, i + n).join(" "));
  return out;
}

/** Every `systemPrompt` string anywhere in gateway.json, cached on the file's mtime. */
function loadSystemPromptShingles(configPath, n, cache) {
  try {
    const st = fs.statSync(configPath);
    if (cache.mtime === st.mtimeMs && cache.set) return cache.set;
    const cfg = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    const prompts = [];
    const walk = (o) => {
      if (!o || typeof o !== "object") return;
      for (const [k, v] of Object.entries(o)) {
        if (k === "systemPrompt" && typeof v === "string" && v.length > 200) prompts.push(v);
        else if (v && typeof v === "object") walk(v);
      }
    };
    walk(cfg);
    const set = new Set();
    for (const p of prompts) for (const s of shingles(words(p), n)) set.add(s);
    cache.mtime = st.mtimeMs;
    cache.set = set;
    return set;
  } catch (_) {
    cache.set = cache.set || new Set();
    return cache.set;
  }
}

/** How many distinct n-word runs of the message appear verbatim in a system prompt. */
function systemPromptHits(content, promptShingles, n) {
  if (!promptShingles || !promptShingles.size) return 0;
  let hits = 0;
  for (const s of shingles(words(content), n)) if (promptShingles.has(s)) hits++;
  return hits;
}

// ---------------------------------------------------------------------------------------------
// state — in memory, persisted to jsonl best-effort
//
// The send path must NEVER block. An earlier revision did a mkdirSync + a full re-read of the log
// on every outbound message; on this kernel a recursive mkdirSync under a pathological path HANGS
// forever, which would have wedged the gateway's delivery loop rather than failing open. So: the
// in-memory ring is the source of truth for the running process, disk is loaded once at activate
// (to survive a restart) and appended to best-effort. If the disk side is broken, the guard still
// works and comms still flow.
// ---------------------------------------------------------------------------------------------
function readJsonl(file) {
  try {
    return fs.readFileSync(file, "utf-8").split("\n").filter(Boolean).map((l) => {
      try { return JSON.parse(l); } catch (_) { return null; }
    }).filter(Boolean);
  } catch (_) { return []; }
}

/** A capped in-memory list with best-effort jsonl persistence. Never throws, never blocks. */
function makeLog(file, cap, dirOk) {
  const rows = dirOk ? readJsonl(file).slice(-cap) : [];
  let dirty = 0;
  return {
    rows,
    push(rec) {
      rows.push(rec);
      if (rows.length > cap) rows.splice(0, rows.length - cap);
      if (!dirOk) return;
      try {
        fs.appendFileSync(file, JSON.stringify(rec) + "\n");
        // compact occasionally rather than on every write
        if (++dirty >= cap) {
          fs.writeFileSync(file, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
          dirty = 0;
        }
      } catch (_) { /* disk is optional */ }
    },
  };
}

module.exports = {
  name: "DM Guard",

  /** Pure helpers, exported so test.js can unit-test the logic with no gateway running. */
  _internals: { similarity, isContentFreeAck, isLeakedSentinel, scrubPaths, systemPromptHits,
                loadSystemPromptShingles, mediaKeys, sha256, normExact, targetKey, DEFAULTS },

  activate(api) {
    // Idempotent. If the loader is ever taught to load this plugin standalone, it would activate
    // alongside Jataayu's require() of it and register the hook TWICE -- two independent state
    // rings, every send recorded twice. Refuse the second activation instead.
    if (module.exports._active && !((api.pluginConfig || {}).dmGuard || {}).allowReactivate) {
      try { console.error("[dm-guard] already active in this process; skipping re-activation"); }
      catch (_) {}
      return;
    }
    module.exports._active = true;

    // api.pluginConfig is JATAAYU's config (we are activated from it); our knobs sit under dmGuard.
    const cfg = Object.assign({}, DEFAULTS, ((api.pluginConfig || {}).dmGuard) || {});
    const MEM = cfg.memDir;
    const F_DECISIONS = path.join(MEM, "decisions.jsonl");
    const F_SENT      = path.join(MEM, "dm-sent.jsonl");
    const F_INBOUND   = path.join(MEM, "sai-inbound.jsonl");
    const owner = (cfg.ownerRecipients || []).map(String).filter(Boolean);

    const isGroup = (to) =>
      /@g\.us|@broadcast|:group:|group-chat|:channel:|discord-channel/i.test(String(to || ""));
    const isOwnerDm = (to) => {
      const t = targetKey(to);
      if (isGroup(t)) return false;
      return owner.some((id) => id && t.includes(String(id).toLowerCase()));
    };

    const log = (m) => { try { console.error(`[dm-guard] ${m}`); } catch (_) {} };
    const spCache = { mtime: 0, set: null };   // system-prompt shingles, invalidated on config mtime

    if (typeof api.on !== "function") return;

    // One mkdir, at boot, off the send path. If it fails the guard runs purely in memory.
    let dirOk = false;
    try { fs.mkdirSync(MEM, { recursive: true }); dirOk = true; }
    catch (e) { log(`state dir unavailable (${e && e.code}); running in memory only`); }

    const sentLog    = makeLog(F_SENT, cfg.keepSent, dirOk);
    const inboundLog = makeLog(F_INBOUND, cfg.keepInbound, dirOk);

    // -- Record inbound, per conversation. This is what lets Sai unstick every dedup rule: if he
    //    wrote into a conversation after we sent X, sending X again is a REPLY, not a repeat.
    const recordInbound = (convo, text) => {
      inboundLog.push(
        { ts: Date.now(), convo: targetKey(convo), text: String(text || "").slice(0, 2000) });
    };

    api.on("message_received", async (event, ctx) => {
      try {
        const convo = (event && event.from) || (ctx && ctx.conversationId) || "";
        recordInbound(convo, (event && event.content) || "");
      } catch (_) {}
    }, { priority: 200 });

    // Belt and braces: keeps the closed-decision check fed even on paths where we do not see a
    // message_received we can attribute to a conversation.
    api.on("before_agent_run", async (event, ctx) => {
      try {
        const text = String((event && (event.prompt || event.content || event.text)) || "");
        if (!text.trim()) return;
        const convo = (ctx && ctx.conversationId) || (event && event.senderId) || "";
        recordInbound(convo, text);
      } catch (_) {}
    }, { priority: 200 });

    /** ts of the most recent inbound in this conversation (0 if we have never seen one). */
    const lastInboundFor = (toKey, rows) => {
      let best = 0;
      for (const r of rows) {
        const c = String(r.convo || "");
        if (!c) continue;
        // Loose match: an id is formatted differently inbound vs outbound
        // (e.g. "15551234567@s.whatsapp.net" vs "+15551234567").
        if (c === toKey || toKey.includes(c) || c.includes(toKey)) {
          if (r.ts > best) best = r.ts;
        }
      }
      return best;
    };

    // ---- the gate ----
    api.on("message_sending", async (event, _ctx) => {
      try {
        const to = String((event && event.to) || "");
        const toKey = targetKey(to);
        if (!toKey) return;
        const content = String((event && event.content) || "");
        const meta = (event && event.metadata) || {};
        const media = mediaKeys(meta.mediaUrls);
        const hasMedia = media.length > 0;
        if (!content.trim() && !hasMedia) return;      // nothing to guard
        const now = Date.now();

        const inboundRows = inboundLog.rows;
        const lastInboundTs = lastInboundFor(toKey, inboundRows);
        const lastInboundGlobal = inboundRows.length ? inboundRows[inboundRows.length - 1].ts : 0;

        // Compare only against messages that actually WENT OUT, to this same target. A dropped
        // message stays in the log for audit but must never poison the cache -- one suppression
        // must not go on to suppress a later legitimate message that happens to resemble it.
        const horizon = Math.max(cfg.dupWindowSec, cfg.mediaWindowSec, cfg.nearDupWindowSec,
                                 cfg.burstWindowSec) * 1000;
        const sent = sentLog.rows
          .filter((r) => !r.dropped && r.ts > now - horizon && String(r.to || "") === toKey);

        /** He wrote into this conversation after we sent that -> re-sending it is a reply. */
        const answeredSince = (prevTs) => lastInboundTs > prevTs;

        const hash = sha256(`${toKey} ${normExact(content)} ${media.join("|")}`);

        const drop = (kind, reason, extra) => {
          log(`DROPPED [${kind}] -> ${to}: ${reason}`);
          sentLog.push(Object.assign(
            { ts: now, to: toKey, dropped: kind, text: content.slice(0, 500), media },
            extra || {}));
          return { cancel: true, cancelReason: `dm-guard: ${reason}` };
        };

        // ---- A. EXACT DUPLICATE ------------------------------------------------------------
        // Byte-identical payload (text + attachments) to the same target inside the window.
        // This is the 08:53:08/08:53:12 group text, and the 07:23:49/07:24:30 mp3.
        for (const prev of sent.slice().reverse()) {
          if (prev.hash !== hash) continue;
          if (now - prev.ts > cfg.dupWindowSec * 1000) continue;
          if (answeredSince(prev.ts)) break;    // he replied in between -> he is asking for it again
          const ago = Math.round((now - prev.ts) / 1000);
          return drop("exact-dup",
            `identical message already sent to this chat ${ago}s ago. Do not send it twice.`,
            { of_ts: prev.ts, hash });
        }

        // ---- B. SAME MEDIA RE-SENT ---------------------------------------------------------
        // Same attachment(s), same target, caption possibly reworded. Re-uploading a file the chat
        // already has, minutes apart, is never useful; it is the loudest form of the bug.
        if (hasMedia) {
          const key = media.join("|");
          for (const prev of sent.slice().reverse()) {
            if (!Array.isArray(prev.media) || prev.media.join("|") !== key) continue;
            if (now - prev.ts > cfg.mediaWindowSec * 1000) continue;
            if (answeredSince(prev.ts)) break;
            const ago = Math.round((now - prev.ts) / 1000);
            return drop("dup-media",
              `${media.join(", ")} was already sent to this chat ${ago}s ago. Do not re-upload it.`,
              { of_ts: prev.ts });
          }
        }

        // ---- G. LEAKED SENTINEL ------------------------------------------------------------
        // The bare string "NO_REPLY" is the model's don't-reply marker, not a message. It reached
        // a human 5 times today. It carries no information under any reading.
        if (isLeakedSentinel(content, cfg.sentinels) && !hasMedia) {
          return drop("sentinel",
            `"${content.trim()}" is the internal no-reply sentinel, not a message. ` +
            `If there is nothing to say, produce no message at all.`, {});
        }

        // ---- C. CONTENT-FREE ACK -----------------------------------------------------------
        // "Done." / "Sent." / "Stored." / "Handled." -- a phone notification with nothing in it.
        if (cfg.emptyAck && isContentFreeAck(content, hasMedia, cfg.emptyAckMaxChars)) {
          return drop("empty-ack",
            `"${content.trim()}" carries no result -- no artifact, link, or number. Either say what ` +
            `actually happened (files touched, counts, a link) or say nothing at all.`, {});
        }

        // ---- I. SYSTEM-PROMPT DUMP (DM only) -----------------------------------------------
        // Judith echoing her own instructions back at him. Requires several verbatim 12-word runs
        // of the configured systemPrompt -- a normal reply cannot do that by accident. If he asked
        // to see his instructions, he gets them.
        if (cfg.systemPromptGuard && isOwnerDm(to) && !hasMedia && content.length > 120) {
          const promptShingles = loadSystemPromptShingles(cfg.configPath, cfg.shingleWords, spCache);
          const hits = systemPromptHits(content, promptShingles, cfg.shingleWords);
          if (hits >= cfg.shingleHits) {
            const askedForIt = inboundRows
              .filter((r) => r.ts > now - cfg.askedWindowMin * 60e3)
              .some((r) => /system\s*prompt|your instructions|what are you told/i.test(r.text || ""));
            if (!askedForIt) {
              return drop("systemprompt-leak",
                `this message reproduces ${hits} verbatim runs of your own system prompt. ` +
                `Your instructions are not an update -- report the WORK, not the brief.`,
                { hits });
            }
            log(`allowed system-prompt echo (${hits} runs) -- Sai asked to see it`);
          }
        }

        // ---- D. NEAR-DUPLICATE (opt-in, default OFF) ---------------------------------------
        // Collapses a reworded restatement. OFF while "volume is not an issue": it is the only
        // FUZZY rule here, and fuzzy means it can eat a real message. Guarded two ways when on:
        // a minimum token count (short messages are unjudgeable by jaccard -- "Episode 24 is up."
        // and "Episode 25 is up." both reduce to {episode} and score 1.0), and an exact veto on
        // any new signal (a digit/link/filename the earlier message did not have).
        if (cfg.nearDup) {
          for (const prev of sent.slice().reverse()) {
            if (now - prev.ts > cfg.nearDupWindowSec * 1000) continue;
            if (answeredSince(prev.ts)) break;
            if (tokens(content).size < cfg.nearDupMinTokens) break;
            if (signals(content).some((sig) => !signals(prev.text || "").includes(sig))) continue;
            const s = similarity(content, prev.text || "");
            if (s >= cfg.nearDupThreshold) {
              const ago = Math.round((now - prev.ts) / 1000);
              return drop("near-dup",
                `you already said this to this chat ${ago}s ago (${(s * 100).toFixed(0)}% identical). ` +
                `Rewording a message you already sent is still sending it twice.`,
                { similarity: +s.toFixed(2), of_ts: prev.ts });
            }
          }
        }

        // ---- F. SAME-TURN BURST (opt-in, default OFF) --------------------------------------
        if (cfg.burstDropSameTurn && isOwnerDm(to)) {
          const lastSent = sent.length ? sent[sent.length - 1] : null;
          if (lastSent && (now - lastSent.ts) < cfg.burstWindowSec * 1000 &&
              (lastSent.after_inbound_ts || 0) === lastInboundGlobal) {
            const gap = Math.round((now - lastSent.ts) / 1000);
            return drop("burst",
              `you already DM'd Sai ${gap}s ago and he has not replied since. Say it in ONE message.`,
              { gap_sec: gap });
          }
        }

        // ---- E. CLOSED DECISION (owner DM only, default OFF) --------------------------------
        // A decision he closed must not be re-opened proactively. But if HE raises the topic,
        // answering him is never blocked -- blocking his own question is worse than the repeat.
        if (cfg.closedDecisions && isOwnerDm(to)) {
          const decisions = readJsonl(F_DECISIONS).filter((d) => d.closed !== false);
          if (decisions.length) {
            const recentInbound = inboundRows
              .filter((r) => r.ts > now - cfg.askedWindowMin * 60e3)
              .map((r) => norm(r.text)).join(" ");
            const body = norm(content);
            for (const d of decisions) {
              const terms = [d.topic, ...(d.aliases || [])].filter(Boolean)
                .map((t) => norm(t)).filter(Boolean);
              if (!terms.some((t) => t && body.includes(t))) continue;
              if (terms.some((t) => t && recentInbound.includes(t))) {
                log(`allowed "${d.topic}" -- Sai raised it himself within ${cfg.askedWindowMin}m`);
                break;
              }
              return drop("closed-decision",
                `"${d.topic}" is a CLOSED decision (${d.decision}) and Sai did not raise it. ` +
                `Do not resurface it.`, { topic: d.topic });
            }
          }
        }

        // ---- H. ABSOLUTE PATHS IN A DM -> REWRITE, NOT DROP --------------------------------
        // Jataayu screens group surfaces and never looks at the owner's DM, so machine-absolute
        // paths land in his DM raw (9 times today). But his DM systemPrompt demands receipts --
        // "exact files touched" -- so the path IS the payload; dropping the message would eat the
        // answer. Keep every character of the receipt, take only the absolute prefix:
        //   /home2/srallaba/projects/x/y.py -> ~/projects/x/y.py
        // DM-only, so this can never collide with Jataayu's group path-leak rewrite.
        let outbound = content;
        if (cfg.pathScrubDm && isOwnerDm(to)) {
          const scrubbed = scrubPaths(content, cfg.homePrefixes);
          if (scrubbed !== null) {
            log(`REWROTE absolute path(s) in DM -> ${to} (paths kept, prefix stripped)`);
            outbound = scrubbed;
          }
        }

        // ---- allow + record. Recording happens HERE, not in a step the model must remember. ----
        sentLog.push({
          ts: now, to: toKey, hash, media,
          after_inbound_ts: lastInboundGlobal,
          text: outbound.slice(0, 2000),
        });
        // Returning content rewrites the payload; returning nothing sends it untouched.
        return outbound === content ? undefined : { content: outbound };
      } catch (e) {
        log(`error, failing open: ${e && e.message}`);   // never take his comms down
        return;
      }
    }, { priority: 200 });   // > jataayu's 100; hooks run highest-first, so a duplicate never even
                             // reaches the privacy scan.
  },
};
