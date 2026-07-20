"""Score a checkpoint's CFP paired accuracy + NotInject over-defense accuracy on a local GPU.

Reporting companion to run_adversarial_slice.py. code/eval_cfp_sidecar.py answers the same paired
question but only against the LIVE v0.1 sidecar (:18902), so it cannot read a fresh checkpoint;
this loads base+adapter directly instead.

Both numbers come from the authoritative implementations -- injscore.injection_scores for the
score and train_lora.cfp_paired_accuracy for the metric -- so a number printed here is the same
number the training loop selected on. Nothing is reimplemented locally.

CAVEAT that must travel with the paired-accuracy number: it is read at a FIXED tau (CFP_TAU=0.5)
and is therefore NOT calibration-robust. Valid for checkpoint selection and for within-model
comparison; NOT a cross-model claim. The calibration-robust claim is the paired ablation in
run_adversarial_slice.py.

Run:
    python eval/run_cfp_notinject.py --adapter adapters/v0.2/checkpoint-N --tag v0.2
    python eval/run_cfp_notinject.py --no-adapter --tag v0.2-BASE
"""

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent  # training/injection_adapter/eval
ROOT = HERE.parent  # training/injection_adapter
sys.path.insert(0, str(ROOT / "code"))
import injscore
from train_lora import CFP_TAU, cfp_paired_accuracy, flatten_cfp_arms, load_cfp_pairs


def load_model(base, adapter, no_adapter, fp32):
    import torch
    from transformers import AutoTokenizer

    if not no_adapter and not Path(adapter).exists():
        raise SystemExit(f"adapter not found: {adapter}")

    tok = AutoTokenizer.from_pretrained(base, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    dtype = torch.float32 if fp32 else torch.float16
    from transformers import AutoModelForCausalLM

    try:
        model = AutoModelForCausalLM.from_pretrained(
            base, torch_dtype=dtype, device_map={"": 0}, trust_remote_code=True
        )
    except (ValueError, KeyError):
        from transformers import AutoModelForImageTextToText

        model = AutoModelForImageTextToText.from_pretrained(
            base, torch_dtype=dtype, device_map={"": 0}, trust_remote_code=True
        )
    if not no_adapter:
        from peft import PeftModel

        model = PeftModel.from_pretrained(model, str(adapter))
    model.eval()
    return model, tok


def score_texts(model, tok, texts, batch_size, max_len):
    pos_id, neg_id = injscore.label_first_token_ids(tok)
    dev = next(model.parameters()).device
    res = injscore.injection_scores(
        model, tok, texts, pos_id, neg_id, max_len=max_len, batch_size=batch_size, device=dev
    )
    if len(res) != len(texts):
        raise SystemExit(f"harness error: scored {len(res)} of {len(texts)} texts")
    return [r["score"] for r in res]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="Qwen/Qwen3.5-0.8B")
    ap.add_argument("--adapter", default=str(ROOT / "adapters" / "run"))
    ap.add_argument("--tag", default="v0.2")
    ap.add_argument("--cfp-file", default=str(ROOT / "data" / "cfp_dev.jsonl"))
    ap.add_argument("--notinject-file", default=str(ROOT / "data" / "notinject_test.jsonl"))
    ap.add_argument("--out", default=None)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--max-len", type=int, default=4096)
    ap.add_argument("--fp16", action="store_true", help="fp16 (NOT on Pascal -- kernel crashes)")
    ap.add_argument("--no-adapter", action="store_true", help="score the BASE model (baseline)")
    args = ap.parse_args()

    pairs, stats = load_cfp_pairs(args.cfp_file)
    if not pairs:
        raise SystemExit(f"no usable pairs in {args.cfp_file}: {stats}")
    ni_rows = [json.loads(l) for l in open(args.notinject_file) if l.strip()]
    if any(int(r["label"]) != 0 for r in ni_rows):
        raise SystemExit(f"{args.notinject_file}: NotInject rows must all be benign (label=0)")

    tag = args.tag if not args.no_adapter else f"{args.tag}-BASE"
    print(f"base={args.base}")
    print(f"adapter={'NONE (base model)' if args.no_adapter else args.adapter}")
    print(
        f"dtype={'fp16' if args.fp16 else 'fp32'}  cfp={stats}  notinject={len(ni_rows)}  "
        f"tag={tag}  tau={CFP_TAU}",
        flush=True,
    )

    model, tok = load_model(args.base, args.adapter, args.no_adapter, fp32=not args.fp16)

    arms = flatten_cfp_arms(pairs)
    ascores = score_texts(model, tok, [a["text"] for a in arms], args.batch_size, args.max_len)
    agg, fam, npairs = cfp_paired_accuracy(pairs, ascores, CFP_TAU)

    # WHICH way a low paired accuracy failed: shortcut (attacks wrong, benign twins right) vs
    # over-defense (the mirror image). The aggregate alone cannot distinguish them.
    arm_acc = {}
    for pol, lab in (("attack", 1), ("benign", 0)):
        sel = [(s, a) for s, a in zip(ascores, arms) if int(a["label"]) == lab]
        if sel:
            arm_acc[pol] = sum((s >= CFP_TAU) == (lab == 1) for s, _ in sel) / len(sel)

    ni_scores = score_texts(model, tok, [r["text"] for r in ni_rows], args.batch_size, args.max_len)
    od_acc = sum(1 for s in ni_scores if s < CFP_TAU) / len(ni_scores)
    od_fp = sum(1 for s in ni_scores if s >= CFP_TAU)

    print("\n" + "=" * 78)
    print(f"CFP PAIRED ACCURACY (both arms correct at tau={CFP_TAU})  [selection metric]")
    print("=" * 78)
    print(f"  aggregate: {agg:.4f}   over {npairs} pairs   (v0.1=0.2857, random=0.25)")
    for f, v in sorted(fam.items()):
        n = sum(1 for p in pairs if p["family"] == f)
        print(f"    {f:24s} {v:.4f}  (n={n})")
    for pol, v in sorted(arm_acc.items()):
        print(f"  arm acc [{pol:6s}]: {v:.4f}")
    print("  CAVEAT: fixed-tau, NOT calibration-robust -- selection/within-model only.")

    print("\n" + "=" * 78)
    print(f"NOTINJECT OVER-DEFENSE ACCURACY (benign, correct = p < {CFP_TAU})")
    print("=" * 78)
    print(
        f"  od_acc: {od_acc:.4f}   FP: {od_fp}/{len(ni_rows)}   file={Path(args.notinject_file).name}"
    )

    outpath = Path(args.out) if args.out else HERE / "results" / f"cfp_notinject.{tag}.json"
    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text(
        json.dumps(
            {
                "tag": tag,
                "base": args.base,
                "adapter": None if args.no_adapter else str(args.adapter),
                "dtype": "fp16" if args.fp16 else "fp32",
                "tau": CFP_TAU,
                "cfp": {
                    "file": args.cfp_file,
                    "stats": stats,
                    "paired_acc": agg,
                    "per_family": fam,
                    "n_pairs": npairs,
                    "arm_acc": arm_acc,
                    "scores": {a["id"]: s for a, s in zip(arms, ascores)},
                },
                "notinject": {
                    "file": args.notinject_file,
                    "n": len(ni_rows),
                    "od_acc": od_acc,
                    "fp": od_fp,
                    "scores": {r["id"]: s for r, s in zip(ni_rows, ni_scores)},
                },
            },
            indent=2,
        )
    )
    print(f"\nwrote {outpath}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
