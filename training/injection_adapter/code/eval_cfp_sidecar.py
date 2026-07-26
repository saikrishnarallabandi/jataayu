"""Score a counterfactual-pair file with the LIVE v0.1 sidecar and report paired accuracy.

Reporting/validation only -- it exists to answer "does this metric measure the shortcut we say it
measures?" on the shipped model, without a GPU or a training run. Training-time scoring goes
through injscore against the in-memory model; this uses the sidecar's /score, which serves the
same adapter.

Run:  /home/user/envs/jataayu/bin/python code/eval_cfp_sidecar.py \
        --cfp-file data/pilot/counterfactual_pairs.pilot.jsonl
"""

import argparse
import json
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from train_lora import CFP_TAU, cfp_paired_accuracy, flatten_cfp_arms, load_cfp_pairs


def score(url, text, timeout=30):
    req = urllib.request.Request(
        url,
        method="POST",
        headers={"Content-Type": "application/json"},
        data=json.dumps({"text": text}).encode(),
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return float(json.loads(r.read())["p_injection"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--cfp-file",
        default=str(HERE.parent / "data" / "pilot" / "counterfactual_pairs.pilot.jsonl"),
    )
    ap.add_argument("--url", default="http://127.0.0.1:18902/score")
    args = ap.parse_args()

    pairs, stats = load_cfp_pairs(args.cfp_file)
    arms = flatten_cfp_arms(pairs)
    print(f"[load] {args.cfp_file}: {stats}")
    scores = [score(args.url, a["text"]) for a in arms]
    agg, fam, n = cfp_paired_accuracy(pairs, scores, CFP_TAU)

    print(f"\n=== v0.1 paired accuracy @ tau={CFP_TAU}: {agg:.4f} over {n} pairs ===")
    print(
        f"{'family':<12} {'paired_acc':>10} {'n':>4} {'atk_rec':>8} {'ben_fpr':>8} "
        f"{'mean_p_atk':>11} {'mean_p_ben':>11}"
    )
    by_fam = defaultdict(lambda: {"atk": [], "ben": []})
    i = 0
    for p in pairs:  # same flatten order the scores were produced in
        for a in p["arms"]:
            by_fam[p["family"]]["atk" if int(a["label"]) == 1 else "ben"].append(scores[i])
            i += 1
    for f in sorted(fam):
        atk, ben = by_fam[f]["atk"], by_fam[f]["ben"]
        rec = sum(1 for s in atk if s >= CFP_TAU) / len(atk) if atk else float("nan")
        fpr = sum(1 for s in ben if s >= CFP_TAU) / len(ben) if ben else float("nan")
        print(
            f"{f:<12} {fam[f]:>10.4f} {sum(1 for p in pairs if p['family'] == f):>4} "
            f"{rec:>8.3f} {fpr:>8.3f} {sum(atk) / len(atk):>11.4f} {sum(ben) / len(ben):>11.4f}"
        )
    allatk = [s for a, s in zip(arms, scores) if int(a["label"]) == 1]
    allben = [s for a, s in zip(arms, scores) if int(a["label"]) == 0]
    print(
        f"\narm-level: attack recall@{CFP_TAU}={sum(1 for s in allatk if s >= CFP_TAU) / len(allatk):.3f} "
        f"(mean p={sum(allatk) / len(allatk):.4f}) | "
        f"benign FPR@{CFP_TAU}={sum(1 for s in allben if s >= CFP_TAU) / len(allben):.3f} "
        f"(mean p={sum(allben) / len(allben):.4f})"
    )


if __name__ == "__main__":
    main()
