/**
 * dm-guard unit tests — run with:  node /home/srallaba/.gateway/plugins/dm-guard/test.js
 *
 * Drives the REAL activate() path against a fake `api` and a throwaway memDir, replaying the
 * actual traces from 2026-07-11. No gateway, no network, and above all NO live WhatsApp sends:
 * a spam filter that is tested by spamming the user is self-defeating.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const assert = require("assert");

const plugin = require("./index.js");

const GROUP = "100000000000000001@g.us";   // fictional — never a real group id in a public repo
const SAI_DM = "+15551234567";                 // fictional — never a real number in a public repo

let pass = 0, fail = 0;
const ok = (name) => { pass++; console.log(`  PASS  ${name}`); };
const no = (name, msg) => { fail++; console.log(`  FAIL  ${name}\n        ${msg}`); };
const check = (name, fn) => { try { fn(); ok(name); } catch (e) { no(name, e.message); } };

/**
 * A guard instance with an isolated state dir.
 *
 * The plugin keeps its state in memory and persists it to jsonl (the send path must never touch
 * the disk). So to simulate the passage of time, `rewind()` rewrites the timestamps in the jsonl
 * files and re-activates the plugin, which reloads them. That means every `rewind` test also
 * proves the guard survives a gateway restart.
 */
function makeGuard(overrides, memDirIn) {
  const memDir = memDirIn || fs.mkdtempSync(path.join(os.tmpdir(), "dmguard-test-"));
  let hooks = {};
  const api = {
    pluginConfig: {
      // allowReactivate: the plugin refuses a second activate() in one process (that would
      // double-register the hook); the suite deliberately activates many isolated instances.
      dmGuard: Object.assign(
        { memDir, ownerRecipients: [SAI_DM, "100000000000000000"], allowReactivate: true },
        overrides || {}),
    },
    on: (name, handler) => { (hooks[name] = hooks[name] || []).push(handler); },
  };
  plugin.activate(api);

  const fire = async (name, event, ctx) => {
    let last;
    for (const h of (hooks[name] || [])) last = await h(event, ctx || {});
    return last;
  };
  const rows = (f) => {
    const p = path.join(memDir, f);
    if (!fs.existsSync(p)) return [];
    return fs.readFileSync(p, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  };

  const self = {
    memDir,
    /** returns {cancel:true,...} if suppressed, {content} if rewritten, undefined if sent as-is */
    send: (to, content, mediaUrls) =>
      fire("message_sending", { to, content, metadata: { channel: "whatsapp", mediaUrls } }, {}),
    recv: (from, content) => fire("message_received", { from, content }, {}),
    sentLog: () => rows("dm-sent.jsonl"),
    /** age every recorded event by N seconds, then reload the plugin from disk (= a restart) */
    rewind: (seconds) => {
      for (const f of ["dm-sent.jsonl", "sai-inbound.jsonl"]) {
        const p = path.join(memDir, f);
        if (!fs.existsSync(p)) continue;
        const aged = rows(f).map((r) => Object.assign(r, { ts: r.ts - seconds * 1000 }));
        fs.writeFileSync(p, aged.map((r) => JSON.stringify(r)).join("\n") + "\n");
      }
      hooks = {};
      plugin.activate(api);   // reloads state from the rewound files
    },
  };
  return self;
}

const suppressed = (r) => !!(r && r.cancel === true);

(async () => {
  console.log("\n=== BUG A — duplicate sends ===");

  // --- the real trace: identical mp3 to the group at 07:23:49 and 07:24:30 CDT (41s apart) ---
  {
    const g = makeGuard();
    const MP3 = "/home/srallaba/podcasts/mem1_learning_memory_reasoning_ep24_2026-07-11.mp3";
    const a = await g.send(GROUP, "Episode 24 is up.", [MP3]);
    g.rewind(41);
    const b = await g.send(GROUP, "Episode 24 is up.", [MP3]);
    check("group: identical mp3 41s apart -> 1st sent, 2nd dropped", () => {
      assert(!suppressed(a), "first send must go out");
      assert(suppressed(b), "second (identical) send must be dropped");
      assert(/identical message already sent/.test(b.cancelReason), b.cancelReason);
    });
  }

  // --- the real trace: byte-identical group text 4s apart (08:53:08 / 08:53:12) ---
  {
    const g = makeGuard();
    const T = "The 50k scaling plan is now in the repo and attached to the same PR, with the " +
              "cost table and the rollout stages.";
    const a = await g.send(GROUP, T);
    g.rewind(4);
    const b = await g.send(GROUP, T);
    check("group: byte-identical text 4s apart -> 2nd dropped", () => {
      assert(!suppressed(a) && suppressed(b), "expected 1 sent, 1 dropped");
    });
  }

  // --- dedup must work in the DM too (he got the podcast news twice via DM) ---
  {
    const g = makeGuard();
    const T = "Podcast episode 24 is uploaded.";
    const a = await g.send(SAI_DM, T);
    g.rewind(30);
    const b = await g.send(SAI_DM, T);
    check("dm: byte-identical text 30s apart -> 2nd dropped", () =>
      assert(!suppressed(a) && suppressed(b)));
  }

  // --- same mp3, DIFFERENT caption (rule B) — this is "the same thing in different forms" ---
  {
    const g = makeGuard();
    const MP3 = "/tmp/render-9f2/mem1_learning_memory_reasoning_ep24_2026-07-11.mp3";
    const MP3_AGAIN = "/tmp/render-3ab/mem1_learning_memory_reasoning_ep24_2026-07-11.mp3"; // re-render
    const a = await g.send(GROUP, "Episode 24 is up.", [MP3]);
    g.rewind(120);
    const b = await g.send(GROUP, "Here's the ep24 podcast, just uploaded.", [MP3_AGAIN]);
    check("same media basename, different caption + path, 2m apart -> dropped", () => {
      assert(!suppressed(a));
      assert(suppressed(b), "same file must not be re-uploaded");
      assert(/was already sent to this chat/.test(b.cancelReason), b.cancelReason);
    });
  }

  console.log("\n=== BUG A — things that must NOT be suppressed ===");

  {
    const g = makeGuard();
    const a = await g.send(GROUP, "Episode 24 is up.", ["/x/ep24.mp3"]);
    g.rewind(30);
    const b = await g.send(GROUP, "Episode 25 is up.", ["/x/ep25.mp3"]);
    check("different episode, different file -> both sent", () =>
      assert(!suppressed(a) && !suppressed(b)));
  }

  {
    const g = makeGuard();
    const a = await g.send(SAI_DM, "Podcast ep24 uploaded, PR 12 is green.");
    g.rewind(20);
    const b = await g.send(SAI_DM, "Podcast ep25 uploaded, PR 13 is green.");
    check("same shape, new numbers -> both sent", () =>
      assert(!suppressed(a) && !suppressed(b)));
  }

  // Sai 2026-07-11: "volume is not an issue for me... i love volume." A reworded restatement is
  // volume, not a defect, so it SHIPS unless the fuzzy rule is explicitly turned on.
  {
    const g = makeGuard();
    const a = await g.send(SAI_DM, "The 50k scaling plan is in the repo and attached to the PR.");
    g.rewind(60);
    const b = await g.send(SAI_DM, "The 50k scaling plan is attached to the PR and in the repo.");
    check("reworded restatement -> BOTH sent (near-dup is OFF: volume is not a defect)", () =>
      assert(!suppressed(a) && !suppressed(b)));
  }

  {
    const g = makeGuard({ nearDup: true });
    const a = await g.send(SAI_DM,
      "The scaling plan lives in the repo, attached to the same pull request, " +
      "with the cost table and the staged rollout written up.");
    g.rewind(60);
    const b = await g.send(SAI_DM,
      "The scaling plan is attached to the same pull request and lives in the repo, " +
      "written up with the staged rollout and the cost table.");
    check("near-dup rule works when explicitly enabled", () =>
      assert(!suppressed(a) && suppressed(b)));
  }

  {
    // the false positive this test suite caught on rev 2: jaccard on a short message is garbage
    const g = makeGuard({ nearDup: true });
    const a = await g.send(GROUP, "Episode 24 is up.");
    g.rewind(30);
    const b = await g.send(GROUP, "Episode 25 is up.");
    check("near-dup ON: short messages differing only by a number -> still BOTH sent", () =>
      assert(!suppressed(a) && !suppressed(b), "the min-token + new-signal vetoes must hold"));
  }

  // The ~20 "Published on ..." notices carry information. They must never be collapsed.
  {
    const g = makeGuard({ nearDup: true });
    const r = [];
    r.push(await g.send(SAI_DM, "Published on X: the ep24 thread is live."));
    g.rewind(20);
    r.push(await g.send(SAI_DM, "Published on Instagram: the ep24 reel is live."));
    g.rewind(20);
    r.push(await g.send(SAI_DM, "Published on Threads: the ep24 post is live."));
    g.rewind(20);
    r.push(await g.send(SAI_DM, "Published on YouTube: the ep24 video is live."));
    check("publish notices to 4 platforms -> all 4 sent, even with near-dup ON", () =>
      assert(r.every((x) => !suppressed(x)), "he wants these; they carry information"));
  }

  {
    const g = makeGuard();
    const a = await g.send(SAI_DM, "Here is the summary: the 50k plan is costed at 3 stages.");
    const b = await g.send(SAI_DM, "And here is the file with the cost table.", ["/x/costs.csv"]);
    check("multi-part turn (summary then file) -> BOTH sent (no blanket burst drop)", () =>
      assert(!suppressed(a) && !suppressed(b), "a real second message must never be eaten"));
  }

  {
    const g = makeGuard();
    const MP3 = "/x/ep24.mp3";
    const a = await g.send(GROUP, "Episode 24 is up.", [MP3]);
    g.rewind(60);
    await g.recv(GROUP, "can you send that podcast again? it didn't download");
    const b = await g.send(GROUP, "Episode 24 is up.", [MP3]);
    check("he asked for it again -> identical re-send IS allowed", () =>
      assert(!suppressed(a) && !suppressed(b), "an explicit resend request must never be blocked"));
  }

  {
    const g = makeGuard();
    const T = "The 50k scaling plan is now in the repo.";
    const a = await g.send(SAI_DM, T);
    const b = await g.send(GROUP, T);   // same text, DIFFERENT target
    check("same text to a different chat -> both sent (dedup is per-target)", () =>
      assert(!suppressed(a) && !suppressed(b)));
  }

  {
    const g = makeGuard();
    const T = "The 50k scaling plan is now in the repo.";
    const a = await g.send(SAI_DM, T);
    g.rewind(3600);                     // an hour later — well outside every window
    const b = await g.send(SAI_DM, T);
    check("identical text an hour later -> allowed (windows expire)", () =>
      assert(!suppressed(a) && !suppressed(b)));
  }

  console.log("\n=== BUG B — content-free filler ===");

  const FILLER = ["Done.", "Done", "done.", "Sent.", "Stored.", "Handled.", "Noted.", "Saved.",
                  "Logged.", "Posted.", "Updated.", "OK", "Okay.", "Got it.", "On it.",
                  "Will do.", "Understood.", "All done.", "Done ✅", "**Done.**", "Ack",
                  "Acknowledged.", "Done!", "Sure."];
  for (const f of FILLER) {
    const g = makeGuard();
    const r = await g.send(SAI_DM, f);
    check(`filler ${JSON.stringify(f)} -> dropped`, () => {
      assert(suppressed(r), `"${f}" should have been suppressed`);
      assert(/carries no result/.test(r.cancelReason), r.cancelReason);
    });
  }

  console.log("\n=== BUG B — short messages that must SURVIVE ===");

  const KEEP = [
    "Yes.",                                       // the answer to a yes/no question
    "No.",
    "Yes, it works.",
    "Correct.",
    "Fixed.",                                     // plausibly the literal answer to "did you fix it?"
    "Merged.",
    "Deployed.",
    "It works.",
    "Done — PR 41 is merged.",                    // has a number => a payload
    "Done: https://x.com/a",                      // has a link => a payload
    "Sent the ep24.mp3 to the group.",            // has a filename => a payload
    "Done?",                                      // a question is never filler
    "Not done.",
    "Nothing to do here.",
    "Done with the audit; 3 findings.",
    "Blocked — I need the API key.",
    "Stored in faiss, 412 vectors.",
    "Handled by the cron, next run 06:00.",
  ];
  for (const m of KEEP) {
    const g = makeGuard();
    const r = await g.send(SAI_DM, m);
    check(`keep ${JSON.stringify(m)} -> sent`, () =>
      assert(!suppressed(r), `"${m}" must NOT be suppressed`));
  }

  {
    const g = makeGuard();
    const r = await g.send(GROUP, "Done.", ["/x/ep24.mp3"]);
    check("filler text used as a CAPTION on an attachment -> sent (never silence media)", () =>
      assert(!suppressed(r)));
  }

  {
    const g = makeGuard();
    const r = await g.send(GROUP, "Done.");
    check("filler in a GROUP -> dropped too (same rule everywhere)", () => assert(suppressed(r)));
  }

  console.log("\n=== NO_REPLY sentinel leaking as a message (5x today) ===");

  for (const s of ["NO_REPLY", "no_reply", "  NO_REPLY  ", "`NO_REPLY`", "**NO_REPLY**",
                   "NO_REPLY.", "noreply"]) {
    const g = makeGuard();
    const r = await g.send(SAI_DM, s);
    check(`sentinel ${JSON.stringify(s)} -> dropped`, () => {
      assert(suppressed(r), `"${s}" must never reach a human`);
      assert(/no-reply sentinel/.test(r.cancelReason), r.cancelReason);
    });
  }
  {
    const g = makeGuard();
    const r = await g.send(SAI_DM,
      "The NO_REPLY sentinel is leaking into your DM as message content — I am fixing the hook.");
    check("a message ABOUT NO_REPLY -> sent (only a bare sentinel is dropped)", () =>
      assert(!suppressed(r)));
  }
  {
    const g = makeGuard();
    const r = await g.send(GROUP, "NO_REPLY");
    check("sentinel in a group -> dropped too", () => assert(suppressed(r)));
  }

  console.log("\n=== absolute paths in a DM: REWRITTEN, never dropped ===");

  {
    const g = makeGuard();
    const r = await g.send(SAI_DM,
      "Fixed the verify hang: /home2/srallaba/projects/project_ascent/scripts/apply.py and " +
      "/home/srallaba/.gateway/plugins/jataayu/index.js. Tests 242 green.");
    check("DM with absolute paths -> sent, rewritten to ~ (receipt survives)", () => {
      assert(!suppressed(r), "a receipt must NEVER be dropped — his DM prompt demands file names");
      assert(r && typeof r.content === "string", "expected a rewritten payload");
      assert(!/\/home2?\/srallaba/.test(r.content), `prefix survived: ${r.content}`);
      assert(/~\/projects\/project_ascent\/scripts\/apply\.py/.test(r.content), r.content);
      assert(/~\/\.gateway\/plugins\/jataayu\/index\.js/.test(r.content), r.content);
      assert(/242 green/.test(r.content), "the rest of the message must be untouched");
    });
  }
  {
    const g = makeGuard();
    const r = await g.send(SAI_DM, "PR 41 is merged, 3 files touched.");
    check("DM with no path -> untouched (no rewrite)", () =>
      assert(r === undefined, "must not rewrite a message that has no path"));
  }
  {
    const g = makeGuard();
    const r = await g.send(GROUP, "See /home2/srallaba/projects/project_ascent/README.md");
    check("GROUP path -> left for jataayu (dm-guard does not touch group content)", () =>
      assert(r === undefined, "dm-guard must not pre-empt jataayu's group rewrite"));
  }

  console.log("\n=== system-prompt dump into the DM ===");

  {
    // build a throwaway gateway.json with a systemPrompt, and echo a chunk of it back
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dmguard-cfg-"));
    const cfgPath = path.join(dir, "gateway.json");
    const SP = "You are Judith, in Sai's private DM. He is the person you work for. DO THE WORK, " +
      "THEN REPORT. When Sai asks for anything real research code a fix a check a build a lookup " +
      "a decision actually DO it in this same turn and come back with the concrete result. " +
      "NEVER send just On it or I'll start or Let me check and stop. That is a wasted ping.";
    fs.writeFileSync(cfgPath, JSON.stringify({ agents: { sai: { systemPrompt: SP } } }));

    const g = makeGuard({ configPath: cfgPath });
    const r = await g.send(SAI_DM, "Here is how I operate: " + SP);
    check("DM echoing the system prompt verbatim -> dropped", () => {
      assert(suppressed(r), "a system-prompt dump carries no information");
      assert(/verbatim runs of your own system prompt/.test(r.cancelReason), r.cancelReason);
    });

    const g2 = makeGuard({ configPath: cfgPath });
    const r2 = await g2.send(SAI_DM,
      "Done the work then reported: PR 41 merged, 3 files touched, tests green. " +
      "I did not just send an On it ping this time — the result is in the repo already.");
    check("a normal report that reuses a few prompt words -> sent", () =>
      assert(!suppressed(r2), "only several VERBATIM 12-word runs may trip this"));

    const g3 = makeGuard({ configPath: cfgPath });
    await g3.recv(SAI_DM, "show me your system prompt");
    const r3 = await g3.send(SAI_DM, "Here is how I operate: " + SP);
    check("...unless he asked to see it -> sent", () =>
      assert(!suppressed(r3), "answering his own question must never be blocked"));
  }

  console.log("\n=== safety ===");

  {
    const g = makeGuard();
    const r = await g.send(SAI_DM, "");
    check("empty payload -> ignored, not suppressed (nothing to guard)", () =>
      assert(!suppressed(r)));
  }

  {
    // A suppression must not poison the cache: the dropped message must never itself become the
    // thing a later legitimate message is compared against.
    const g = makeGuard();
    await g.send(SAI_DM, "Done.");                        // dropped (filler)
    const r = await g.send(SAI_DM, "Done reviewing: 4 issues, all filed.");
    check("a dropped message never blocks a later real one", () => {
      assert(!suppressed(r));
      const dropped = g.sentLog().filter((x) => x.dropped);
      assert.strictEqual(dropped.length, 1, "the drop is still audited in the log");
    });
  }

  {
    const g = makeGuard({ burstDropSameTurn: true });
    const a = await g.send(SAI_DM, "First half of the answer.");
    const b = await g.send(SAI_DM, "Second, unrelated half.");
    check("burst rule is opt-in and works when explicitly enabled", () =>
      assert(!suppressed(a) && suppressed(b)));
  }

  {
    // /dev/null/nope is not a directory -> mkdir fails -> the guard must run in memory and the
    // message must still go out. (NB: do NOT use a /proc path here -- a recursive mkdirSync under
    // /proc HANGS on this kernel, which is precisely why the guard now mkdirs once at activate,
    // off the send path, instead of on every message.)
    const bad = { pluginConfig: { dmGuard: { memDir: "/dev/null/nope", allowReactivate: true } },
                  on: (n, h) => { (bad._h = bad._h || {})[n] = h; } };
    plugin.activate(bad);
    const r1 = await bad._h.message_sending(
      { to: SAI_DM, content: "PR 41 merged, tests green." }, {});
    const r2 = await bad._h.message_sending(
      { to: SAI_DM, content: "PR 41 merged, tests green." }, {});
    check("broken state dir -> fails OPEN, message still goes out", () =>
      assert(!suppressed(r1), "a broken guard must never take his comms down"));
    check("broken state dir -> dedup still works from memory", () =>
      assert(suppressed(r2)));
  }

  {
    // the in-memory ring is rebuilt from jsonl at activate, so a gateway restart does not reopen
    // the duplicate window
    const g = makeGuard();
    const T = "The 50k scaling plan is now in the repo and attached to the same PR.";
    const a = await g.send(GROUP, T);
    g.rewind(5);                       // rewind() re-activates the plugin => simulates a restart
    const b = await g.send(GROUP, T);
    check("dedup survives a gateway restart (state reloaded from jsonl)", () =>
      assert(!suppressed(a) && suppressed(b)));
  }

  {
    // A double activation (standalone loader AND jataayu's require) would register the hook twice,
    // giving two independent state rings and recording every send twice. It must refuse.
    const seen = [];
    const a1 = { pluginConfig: {}, on: (n) => seen.push(n) };
    plugin.activate(a1);   // no allowReactivate => refused (the suite has already activated)
    check("a second activate() in one process is refused", () =>
      assert.strictEqual(seen.length, 0, "the hook must not be registered twice"));
  }

  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
})();
