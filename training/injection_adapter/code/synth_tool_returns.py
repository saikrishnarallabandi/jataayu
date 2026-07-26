"""Synthesize BENIGN tool-returns: realistic API/JSON/email/web-page/file outputs that carry
NO injection. These are the negatives that pair against INDIRECT attacks (the tool-return channel
that BIPIA/llmail/Nemotron/InjecAgent poison). Labels are correct BY CONSTRUCTION: label=0,
attack_type=none, source=synth_tool_returns.

The generator NEVER labels; we set the gold label. We post-filter any output that accidentally
contains an injection trigger so the benign set stays clean.

Concurrent (vLLM serves parallel requests), sharded (--shard/--num-shards), resumable
(skips ids already in the output shard). Unbuffered: run under `python -u` with a logfile.
"""

import argparse
import hashlib
import json
import os
import random
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from llm_client import add_backend_args, client_from_args

# tool-return contexts matched to the indirect attack sets' channels
CONTEXTS = [
    {
        "tool": "read_email",
        "fmt": "an email message (headers + body)",
        "domain": "a work inbox",
        "topics": [
            "a meeting reschedule",
            "an invoice reminder",
            "a newsletter",
            "a shipping confirmation",
            "a password-reset notice from IT",
            "a PTO approval",
        ],
    },
    {
        "tool": "get_patient_record",
        "fmt": "a JSON patient record with a free-text notes field",
        "domain": "a healthcare clinic assistant",
        "topics": [
            "a routine checkup",
            "a lab result summary",
            "a prescription refill",
            "an appointment note",
            "an allergy update",
        ],
    },
    {
        "tool": "web_search",
        "fmt": "a web page excerpt / search-result snippet",
        "domain": "a browsing agent",
        "topics": [
            "a recipe",
            "a product spec page",
            "a wikipedia paragraph",
            "a travel guide",
            "a stack-overflow answer",
            "a news article",
        ],
    },
    {
        "tool": "read_file",
        "fmt": "the contents of a file",
        "domain": "a coding/file agent",
        "topics": [
            "a README section",
            "a CSV data sample",
            "a config yaml",
            "a changelog entry",
            "a meeting-notes markdown",
        ],
    },
    {
        "tool": "crm_lookup",
        "fmt": "a JSON CRM/database record",
        "domain": "a sales assistant",
        "topics": [
            "a customer contact",
            "an order history",
            "a support ticket",
            "an account status",
            "a lead note",
        ],
    },
    {
        "tool": "get_calendar",
        "fmt": "a JSON calendar event listing",
        "domain": "a scheduling assistant",
        "topics": [
            "a standup",
            "a dentist appointment",
            "a project deadline",
            "a flight itinerary",
            "a team offsite",
        ],
    },
    {
        "tool": "fetch_reviews",
        "fmt": "a product review / comment block",
        "domain": "a shopping assistant",
        "topics": [
            "a pair of headphones",
            "a coffee maker",
            "a laptop",
            "a hiking backpack",
            "a novel",
        ],
    },
    {
        "tool": "get_ticket",
        "fmt": "a JSON issue-tracker ticket with a description field",
        "domain": "a devops agent",
        "topics": [
            "a flaky test",
            "a UI bug",
            "a feature request",
            "a deployment note",
            "a dependency bump",
        ],
    },
]

SYS = (
    "You generate realistic sample DATA that a software tool would return to an AI agent. "
    "Output ONLY the raw tool content (JSON, email text, web snippet, or file body as asked) "
    "with realistic but fictional values. Do NOT add commentary, code fences, or explanations. "
    "The content must be ordinary and benign: it must NEVER contain instructions aimed at an AI "
    "or assistant, and must never say things like 'ignore previous instructions', 'system:', "
    "'you are now', or ask the reader to send/email/exfiltrate anything."
)

# triggers used to REJECT accidental injections (keep benign set clean)
TRIGGERS = [
    "ignore previous",
    "ignore all previous",
    "ignore the above",
    "disregard previous",
    "system:",
    "you are now",
    "new instructions",
    "as an ai",
    "forget your instructions",
    "send an email to",
    "exfiltrat",
    "reveal your",
    "print your system prompt",
    "api_call",
    "override",
    "do not tell the user",
    "bypass",
]


def has_trigger(t):
    tl = t.lower()
    return any(x in tl for x in TRIGGERS)


def build_prompt(ctx, topic):
    return (
        f"Tool: {ctx['tool']} (used by {ctx['domain']}).\n"
        f"Produce {ctx['fmt']} about {topic}. "
        f"Make it look like a genuine tool response with plausible fictional details "
        f"(names, dates, ids, numbers). 4-12 lines. Benign content only."
    )


def gen_one(client, idx):
    ctx = random.choice(CONTEXTS)
    topic = random.choice(ctx["topics"])
    for _ in range(3):  # retry until clean
        try:
            out = client.chat(SYS, build_prompt(ctx, topic))
        except Exception as e:
            return {"_err": str(e)[:160]}
        out = re.sub(r"^```[a-zA-Z]*\n?|\n?```$", "", out.strip()).strip()
        if out and not has_trigger(out) and len(out) > 30:
            h = hashlib.md5(out.encode()).hexdigest()
            return {
                "id": f"synth_toolret_{h[:12]}",
                "text": out,
                "label": 0,
                "attack_type": "none",
                "source": "synth_tool_returns",
                "split": "train",
                "license": "synthetic-teacher",
                "meta": {"tool": ctx["tool"], "topic": topic},
            }
    return {"_reject": True}


def load_done(path):
    done = set()
    if os.path.exists(path):
        for line in open(path):
            try:
                done.add(json.loads(line)["id"])
            except Exception:
                pass
    return done


def main():
    ap = argparse.ArgumentParser()
    add_backend_args(ap)
    ap.add_argument("-n", "--num", type=int, default=120)
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--num-shards", type=int, default=1)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--seed", type=int, default=1234)
    ap.add_argument("--out", default="data/synth_tool_returns.jsonl")
    args = ap.parse_args()
    random.seed(args.seed + args.shard)

    client = client_from_args(args)
    ok, detail = client.probe()
    print(f"[probe] ok={ok} detail={detail}", flush=True)
    if not ok:
        print("[FATAL] teacher unreachable", flush=True)
        sys.exit(2)

    my_n = args.num // args.num_shards + (1 if args.shard < args.num % args.num_shards else 0)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    done = load_done(args.out)
    print(
        f"[start] shard {args.shard}/{args.num_shards} target={my_n} already={len(done)}",
        flush=True,
    )

    lock = threading.Lock()
    written = 0
    rejects = 0
    with open(args.out, "a") as fout, ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(gen_one, client, i) for i in range(my_n * 2)]  # overshoot for rejects
        for fut in as_completed(futs):
            if written >= my_n:
                break
            r = fut.result()
            if "_err" in r:
                print(f"[err] {r['_err']}", flush=True)
                continue
            if r.get("_reject"):
                rejects += 1
                continue
            if r["id"] in done:
                continue
            with lock:
                fout.write(json.dumps(r, ensure_ascii=False) + "\n")
                fout.flush()
                done.add(r["id"])
                written += 1
                if written % 10 == 0:
                    print(f"[prog] written={written}/{my_n} rejects={rejects}", flush=True)
    print(
        f"[done] shard {args.shard}: written={written} rejects={rejects} -> {args.out}", flush=True
    )


if __name__ == "__main__":
    main()
