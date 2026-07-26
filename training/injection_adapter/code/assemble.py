"""Layer-1 assembly: load permissive prompt-injection datasets into ONE unified schema.

Unified row schema:
  {id, text, label (0=benign/1=injection), attack_type (direct|indirect|none),
   source, split (train|heldout), license}

Streamed + deduped (normalized-text md5) across the whole pool. Per-source caps balance the mix.
HELDOUT sources are marked split=heldout and MUST be excluded from training selection downstream.

INDIRECT-POSITIVE diversification: llmail is the primary indirect source. CloneGuard and
InjecAgent are NOT available on the HF Hub (InjecAgent is a GitHub benchmark AND this repo's
eval set, so it stays HELDOUT to avoid eval contamination). Nemotron-IPI stays HELDOUT.

BIPIA hook: MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT is GATED. ex_bipia() attempts a load;
if access is granted it folds in real indirect attacks + indirect-BENIGN (the eventual replacement
for the currently 100%-synthetic indirect-benign). Until then it logs and skips cleanly.

EVAL-EXCLUSION GATE: every candidate row is tested against the frozen eval cache
(eval/results/qwen_scores/eval_cache.jsonl) and dropped on a verbatim normalized-text match.
This runs on EVERY build; it is not a one-off cleanup. v0.1 shipped without it and 1,715 of the
4,101 eval rows (41.8%) had leaked into training, inflating the published headline metric.
A missing cache file is fatal, never a skip.

Run:  eval/.venv-hf/bin/python code/assemble.py --out data/layer1_pool_full.jsonl
"""

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata
from pathlib import Path

from datasets import load_dataset

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent  # training/injection_adapter
REPO = ROOT.parent.parent  # jataayu
EVAL_CACHE = REPO / "eval" / "results" / "qwen_scores" / "eval_cache.jsonl"

# DROPPED 2026-07-18 on a license/provenance audit. Do NOT re-add from an older doc: three
# in-repo docs previously asserted three mutually inconsistent licenses for xTRam1 alone.
# Each status below was re-verified against the live HF API, not recalled:
#   xTRam1/safe-guard-prompt-injection   (was 2,559 rows) - UNLICENSED. `license: None`, no
#     license tag, no LICENSE file; upstream chuyishang/safeguard is also unlicensed. No
#     license means no permission granted. Re-add only against a written grant from the author.
#   deepset/prompt-injections            (was 311 rows)   - card declares BOTH `license:
#     apache-2.0` (top level) and `dataset_info.license: cc-by-4.0`. The stricter CC-BY reading
#     carries an attribution clause, which fails this project's "no clauses" bar.
#   darkknight25/Prompt_Injection_Benign_Prompt_Dataset (was 360 rows) - MIT tag present, but
#     self-published (89 downloads / 1 like) and its cited upstream GitHub 404s, so the chain of
#     title cannot be verified. An unverifiable MIT claim is not a cleared license.
DROPPED_UNLICENSED = (
    "xTRam1/safe-guard-prompt-injection",
    "deepset/prompt-injections",
    "darkknight25/Prompt_Injection_Benign_Prompt_Dataset",
)

LICENSES = {
    "microsoft/llmail-inject-challenge": "MIT",
    "hackaprompt/hackaprompt-dataset": "MIT",
    "reshabhs/SPML_Chatbot_Prompt_Injection": "MIT",
    "jackhhao/jailbreak-classification": "Apache-2.0",
    "Lakera/gandalf_ignore_instructions": "MIT",
    "nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1": "CC-BY-4.0",
    "MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT": "gated",
}

# per-source caps (max unique rows kept). Tuned for a ~80-90k balanced full build.
CAPS = {
    "microsoft/llmail-inject-challenge": 32000,  # indirect positives (primary)
    "reshabhs/SPML_Chatbot_Prompt_Injection": 16012,
    "hackaprompt/hackaprompt-dataset": 9000,
    "jackhhao/jailbreak-classification": 1044,
    "Lakera/gandalf_ignore_instructions": 777,
    "nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1": 1000,  # HELDOUT
}


def norm(t):
    return re.sub(r"\s+", " ", (t or "").strip().lower())


def eval_norm(t):
    """Normalization for eval-cache matching. Deliberately stricter than norm() (adds NFKC): it
    must match the form the 41.8% contamination was measured with, or the gate under-blocks.
    Kept separate from norm() because norm() feeds the row-id md5 and must stay stable."""
    t = unicodedata.normalize("NFKC", str(t or "")).lower().strip()
    return re.sub(r"\s+", " ", t)


def load_eval_exclusions(path):
    """Normalized texts of the frozen eval suite. A build without this gate is worse than no
    build -- it looks plausible and silently reproduces the contamination -- so every failure
    mode here (absent file, unreadable row, empty result) is fatal rather than a warning."""
    if not os.path.exists(path):
        raise SystemExit(
            f"FATAL: eval cache not found at {path}\n"
            "Refusing to build: without the eval-exclusion gate this produces a contaminated "
            "training pool that looks correct. Restore the cache or pass --eval-cache."
        )
    ex = set()
    with open(path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError as e:
                raise SystemExit(f"FATAL: {path}:{i} is not valid JSON: {e}")
            if "text" not in r:
                raise SystemExit(f"FATAL: {path}:{i} has no 'text' field; cannot build the gate.")
            n = eval_norm(r["text"])
            if n:
                ex.add(n)
    if not ex:
        raise SystemExit(f"FATAL: {path} yielded 0 exclusion texts; the gate would be a no-op.")
    return ex


def clean(t):
    return re.sub(r"[ \t]+", " ", (t or "").strip())


def ex_llmail(cap):
    ds = load_dataset("microsoft/llmail-inject-challenge", split="Phase1", streaming=True)
    n = 0
    for r in ds:
        subj = clean(r.get("subject"))
        body = clean(r.get("body"))
        if not body or len(body) < 15:
            continue
        text = f"Subject: {subj}\n\n{body}" if subj else body
        yield (text, 1, "indirect")
        n += 1
        if n >= cap:
            break


def ex_hackaprompt(cap):
    ds = load_dataset("hackaprompt/hackaprompt-dataset", split="train", streaming=True)
    n = 0
    for r in ds:
        ui = clean(r.get("user_input"))
        if not ui or len(ui) < 8:
            continue
        yield (ui, 1, "direct")
        n += 1
        if n >= cap:
            break


def ex_spml(cap):
    ds = load_dataset("reshabhs/SPML_Chatbot_Prompt_Injection", split="train", streaming=True)
    n = 0
    for r in ds:
        up = clean(r.get("User Prompt"))
        lab = r.get("Prompt injection")
        if not up or lab is None:
            continue
        try:
            lab = int(lab)
        except (TypeError, ValueError):
            continue
        yield (up, lab, "direct" if lab == 1 else "none")
        n += 1
        if n >= cap:
            break


def ex_jackhhao(cap):
    ds = load_dataset("jackhhao/jailbreak-classification", split="train", streaming=True)
    n = 0
    for r in ds:
        p = clean(r.get("prompt"))
        typ = (r.get("type") or "").lower()
        if not p or typ not in ("benign", "jailbreak"):
            continue
        lab = 1 if typ == "jailbreak" else 0
        yield (p, lab, "direct" if lab == 1 else "none")
        n += 1
        if n >= cap:
            break


def ex_gandalf(cap):
    ds = load_dataset("Lakera/gandalf_ignore_instructions", split="train", streaming=True)
    n = 0
    for r in ds:
        t = clean(r.get("text"))
        if not t:
            continue
        yield (t, 1, "direct")
        n += 1
        if n >= cap:
            break


def ex_nemotron(cap):
    # HELDOUT. Agentic indirect injections; text = injection goal + vector.
    ds = load_dataset(
        "nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1", split="train", streaming=True
    )
    n = 0
    for r in ds:
        inj = r.get("injection")
        vec = r.get("injection_vector")
        try:
            d = inj if isinstance(inj, dict) else json.loads(str(inj).replace("'", '"'))
            goal = d.get("goal")
        except Exception:
            goal = str(inj)[:400] if inj else None
        if not goal:
            continue
        yield (f"[injected via {vec}] {clean(goal)}", 1, "indirect")
        n += 1
        if n >= cap:
            break


def ex_bipia(cap):
    """GATED hook. Yields (text, label, 'indirect') for BOTH attack and benign halves if
    access is granted; otherwise logs and yields nothing. Best-effort schema inference."""
    hf = "MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT"
    try:
        ds = load_dataset(hf, split="train", streaming=True, token=os.environ.get("HF_TOKEN"))
    except Exception as e:
        print(f"[bipia] SKIP (gated/unavailable): {str(e)[:120]}", file=sys.stderr)
        return
    text_fields = ["text", "prompt", "context", "content", "input", "attack"]
    label_fields = ["label", "is_attack", "attack", "malicious", "poisoned"]
    n = 0
    for r in ds:
        tf = next((f for f in text_fields if f in r and r[f]), None)
        lf = next((f for f in label_fields if f in r), None)
        if tf is None or lf is None:
            print(f"[bipia] cannot infer schema, cols={list(r.keys())}", file=sys.stderr)
            return
        try:
            lab = int(r[lf])
        except (TypeError, ValueError):
            lab = 1 if str(r[lf]).lower() in ("1", "true", "attack", "malicious", "yes") else 0
        yield (clean(str(r[tf])), lab, "indirect")
        n += 1
        if n >= cap:
            break


SOURCES = [
    ("microsoft/llmail-inject-challenge", ex_llmail, "train"),
    ("reshabhs/SPML_Chatbot_Prompt_Injection", ex_spml, "train"),
    ("hackaprompt/hackaprompt-dataset", ex_hackaprompt, "train"),
    ("jackhhao/jailbreak-classification", ex_jackhhao, "train"),
    ("Lakera/gandalf_ignore_instructions", ex_gandalf, "train"),
    # xTRam1 / deepset / darkknight25 removed here -- see DROPPED_UNLICENSED at the top.
    ("MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT", ex_bipia, "train"),  # gated hook
    ("nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1", ex_nemotron, "heldout"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/layer1_pool_full.jsonl")
    ap.add_argument("--default-cap", type=int, default=5000)
    ap.add_argument(
        "--eval-cache",
        default=str(EVAL_CACHE),
        help="frozen eval suite; every row matching it verbatim is excluded",
    )
    args = ap.parse_args()

    readded = [n for n, _, _ in SOURCES if n in DROPPED_UNLICENSED]
    if readded:
        raise SystemExit(
            f"FATAL: license-disqualified source(s) back in SOURCES: {', '.join(readded)}\n"
            "See DROPPED_UNLICENSED for the verified status of each. Re-adding one requires a "
            "documented grant, not an edit here."
        )

    excl = load_eval_exclusions(args.eval_cache)
    print(
        f"[gate] eval-exclusion set: {len(excl)} unique texts from {args.eval_cache}",
        file=sys.stderr,
    )

    # The cap is applied to rows the extractor YIELDS, so gated/duplicate rows still consume it.
    # That is intentional: it keeps each source's slice of the mix a fixed draw off the head of
    # the stream rather than letting a heavily-contaminated source backfill deeper into it.
    seen = set()
    rows = []
    stats = {}
    gated = {}
    for name, extractor, split in SOURCES:
        cap = CAPS.get(name, args.default_cap)
        kept = 0
        dropped = 0
        try:
            for text, label, atype in extractor(cap):
                if eval_norm(text) in excl:
                    dropped += 1
                    continue
                h = hashlib.md5(norm(text).encode()).hexdigest()
                if h in seen:
                    continue
                seen.add(h)
                rows.append(
                    {
                        "id": f"{name.split('/')[-1]}_{h[:10]}",
                        "text": text,
                        "label": int(label),
                        "attack_type": atype,
                        "source": name,
                        "split": split,
                        "license": LICENSES.get(name, "UNKNOWN"),
                    }
                )
                kept += 1
        except Exception as e:
            print(f"[WARN] {name}: {type(e).__name__}: {str(e)[:160]}", file=sys.stderr)
        stats[name] = kept
        gated[name] = dropped
        print(
            f"[ok] {name}: kept {kept} (split={split}) | eval-gate dropped {dropped}",
            file=sys.stderr,
        )
        sys.stdout.flush()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"\nWROTE {len(rows)} rows -> {args.out}", file=sys.stderr)
    print("PER-SOURCE:", json.dumps(stats), file=sys.stderr)
    print("EVAL-GATE DROPPED:", json.dumps(gated), file=sys.stderr)
    print(f"EVAL-GATE TOTAL DROPPED: {sum(gated.values())}", file=sys.stderr)


if __name__ == "__main__":
    main()
