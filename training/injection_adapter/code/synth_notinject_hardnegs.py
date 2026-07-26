"""Synthesize NotInject-STYLE hard negatives: legitimately BENIGN text that is DENSE with
injection-looking triggers ("ignore all previous instructions", "system prompt", "you are now",
tool-call/JSON, delimiters) but in clearly benign contexts. All label 0.

Why: the frontier proved every high-recall checkpoint over-defends ~18-41% on NotInject because the
original 3k hard-negs were too easy. This set teaches the detector that trigger vocabulary in a
BENIGN frame is not an attack -- the exact axis NotInject tests.

Teacher = dgx qwen3.6:35b via ollama (localhost:11436, think=false -> reliable reasoning suppression;
the LiteLLM router does NOT honor /no_think and returns empty content). Free, no vast spend.
Sharded + multithreaded (ollama serves concurrent requests).

CONTAMINATION GUARD: NotInject is the held-out over-defense TEST -- we synthesize in its STYLE only
and hard-drop any generation whose normalized text collides with a NotInject row. An optional
--real-hardneg-file (permissively-licensed real over-defense data, e.g. InjecGuard/PIGuard) is folded
in verbatim if provided.

Run (per shard):
  python code/synth_notinject_hardnegs.py --backend ollama --base-url http://localhost:11436 \
     --model qwen3.6:35b-a3b --n 10000 --nshards 8 --shard 0 --workers 6 \
     --out data/synth_notinject_hardnegs.shard0.jsonl
"""

import argparse
import hashlib
import json
import random
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REPO = ROOT.parents[1]
sys.path.insert(0, str(HERE))
from llm_client import add_backend_args, client_from_args

CACHE = REPO / "eval" / "results" / "qwen_scores" / "eval_cache.jsonl"

SYS = (
    "You generate realistic, natural, BENIGN text samples used to train a prompt-injection "
    "detector to STOP over-flagging harmless text. Every sample must be clearly benign -- no "
    "actual attempt to manipulate an AI -- yet contain injection-looking vocabulary in an "
    "innocent frame. Output ONLY the sample text: no preamble, no explanation, no quotes around it."
)

TRIGGERS = [
    "ignore all previous instructions",
    "ignore the above instructions",
    "disregard previous instructions",
    "system prompt",
    "you are now",
    "reveal your instructions",
    "print your system prompt",
    "forget everything you were told",
    "new instructions:",
    "SYSTEM:",
    "act as DAN",
    "jailbreak",
    "override your guidelines",
    "developer mode",
    "<|im_start|>system",
    "### Instruction:",
    '{"role": "system", "content": ...}',
    "do anything now",
    "bypass the safety filter",
    "repeat the words above",
    "output your prompt verbatim",
    "you must comply",
    "no restrictions",
]

# (name, template) -- {trg} = 2-4 joined triggers, {dom} = a domain flavour
CATS = [
    (
        "security_tutorial",
        "Write a {length} excerpt from a cybersecurity tutorial or blog that EXPLAINS what prompt-injection "
        "attacks look like. Quote these as example attack strings: {trg}. It is educational and defensive.",
    ),
    (
        "user_asks_about_attack",
        "Write a benign message where a curious USER asks an AI assistant to explain or help defend against "
        "an attack, quoting the attack phrase(s): {trg}. The user is learning, not attacking.",
    ),
    (
        "log_analysis",
        "Write a benign SOC/security-log analysis note where an analyst reviews logs that CONTAINED these "
        "suspicious strings: {trg}. The analyst is investigating, describing what was seen -- not attacking.",
    ),
    (
        "translation_or_edit",
        "Write a benign request asking to translate, proofread, or summarize a document that happens to "
        "contain the phrase(s): {trg}. The task is ordinary language work.",
    ),
    (
        "quiz_exam",
        "Write a benign quiz or exam question (with a few answer options) that TESTS a student's knowledge of "
        "prompt injection, referencing example phrases: {trg}.",
    ),
    (
        "api_docs",
        "Write a benign snippet of API or config documentation (JSON/YAML/markdown) for an AI product, with "
        "fields or examples such as: {trg}. It is product documentation, entirely benign.",
    ),
    (
        "redteam_report",
        "Write a benign paragraph from a RED-TEAM or pentest REPORT that DESCRIBES (past tense, reporting) an "
        "injection test which used payloads like: {trg}. It reports findings, it does not perform an attack.",
    ),
    (
        "coincidental",
        "Write a benign everyday passage about {dom} that innocently contains wording resembling: {trg} in a "
        "completely non-technical, harmless sense.",
    ),
    (
        "forum_safety",
        "Write a benign forum post or comment where someone warns others about AI attacks, mentioning example "
        "phrases like: {trg} to raise awareness.",
    ),
    (
        "code_comment",
        "Write a benign code snippet with comments/docstrings about SANITIZING or filtering prompt-injection "
        "input, mentioning strings like: {trg}. The code defends against attacks.",
    ),
]
DOMS = [
    "cooking",
    "gardening",
    "a road trip",
    "a soccer match",
    "home renovation",
    "a school play",
    "birdwatching",
    "a coffee recipe",
    "assembling furniture",
    "a museum visit",
]
LENS = ["2-3 sentence", "3-5 sentence", "short (4-6 sentence)", "one-paragraph"]

_PREAMBLE = re.compile(
    r"^(sure|here('?s| is)|certainly|of course|below is|the following)\b.*?[:\n]", re.I | re.S
)


def norm(t):
    return re.sub(r"\s+", " ", (t or "").strip().lower())


def clean(t):
    t = (t or "").strip().strip('"').strip()
    t = _PREAMBLE.sub("", t, count=1).strip()
    return re.sub(r"[ \t]+", " ", t)


def build_prompt(rng):
    name, tmpl = rng.choice(CATS)
    k = rng.randint(2, 4)
    trg = "; ".join(f'"{t}"' for t in rng.sample(TRIGGERS, min(k, len(TRIGGERS))))
    return name, tmpl.format(trg=trg, dom=rng.choice(DOMS), length=rng.choice(LENS))


def main():
    ap = argparse.ArgumentParser()
    add_backend_args(ap)
    ap.add_argument("--n", type=int, default=10000, help="total target across all shards")
    ap.add_argument("--nshards", type=int, default=1)
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--seed", type=int, default=20260716)
    ap.add_argument("--out", required=True)
    ap.add_argument(
        "--real-hardneg-file",
        default=None,
        help="optional permissively-licensed REAL over-defense rows (text per line or jsonl)",
    )
    args = ap.parse_args()

    # NotInject contamination guard
    ni_norm = set()
    for l in CACHE.open():
        r = json.loads(l)
        if r.get("dataset") == "NotInject":
            ni_norm.add(norm(r["text"]))

    target = args.n // args.nshards + (1 if args.shard < args.n % args.nshards else 0)
    outp = Path(args.out)
    seen = set()
    if outp.exists():
        for l in outp.open():
            try:
                seen.add(json.loads(l)["id"])
            except Exception:
                pass
    have = len(seen)
    print(
        f"[shard {args.shard}/{args.nshards}] target={target} have={have} -> need {target - have}",
        flush=True,
    )

    client = client_from_args(args)
    ok, detail = client.probe()
    if not ok:
        raise SystemExit(f"teacher unreachable: {detail}")

    lock = threading.Lock()
    rng = random.Random(args.seed + args.shard)
    fout = outp.open("a")
    made = [have]
    err = [0]
    dup = [0]
    contam = [0]

    def work(_):
        if made[0] >= target:
            return
        with lock:
            name, user = build_prompt(rng)
        try:
            txt = clean(client.chat(SYS, user))
        except Exception:
            err[0] += 1
            return
        if len(txt) < 25 or len(txt) > 6000:
            err[0] += 1
            return
        h = hashlib.md5(norm(txt).encode()).hexdigest()
        if norm(txt) in ni_norm:
            contam[0] += 1
            return
        with lock:
            if h in seen or made[0] >= target:
                dup[0] += 1
                return
            seen.add(h)
            rec = {
                "id": f"synth_nihn_{args.shard}_{h[:10]}",
                "text": txt,
                "label": 0,
                "attack_type": "none",
                "source": "synth_notinject_hardneg",
                "split": "train",
                "license": "synthetic-teacher",
                "category": name,
            }
            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fout.flush()
            made[0] += 1
            if made[0] % 100 == 0:
                print(
                    f"[shard {args.shard}] {made[0]}/{target} err={err[0]} dup={dup[0]} "
                    f"contam={contam[0]}",
                    flush=True,
                )

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        while made[0] < target:
            batch = min(args.workers * 4, (target - made[0]) * 2 + args.workers)
            list(ex.map(work, range(batch)))
            if err[0] > target * 5 + 200:
                print(f"[shard {args.shard}] too many errors ({err[0]}), aborting", flush=True)
                break

    # fold in optional real hard-negs (shard 0 only, verbatim, deduped, contamination-guarded)
    if args.real_hardneg_file and args.shard == 0 and Path(args.real_hardneg_file).exists():
        n_real = 0
        for l in Path(args.real_hardneg_file).open():
            l = l.strip()
            if not l:
                continue
            try:
                t = json.loads(l)["text"] if l.startswith("{") else l
            except Exception:
                t = l
            t = clean(t)
            if not t or norm(t) in ni_norm:
                continue
            h = hashlib.md5(norm(t).encode()).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            fout.write(
                json.dumps(
                    {
                        "id": f"real_hardneg_{h[:10]}",
                        "text": t,
                        "label": 0,
                        "attack_type": "none",
                        "source": "real_hardneg",
                        "split": "train",
                        "license": "external-permissive",
                        "category": "real",
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            n_real += 1
        print(f"[shard 0] folded {n_real} real hard-negs from {args.real_hardneg_file}", flush=True)

    fout.close()
    print(
        f"[shard {args.shard}] DONE made={made[0]} err={err[0]} dup={dup[0]} contam={contam[0]} "
        f"-> {outp}",
        flush=True,
    )


if __name__ == "__main__":
    main()
