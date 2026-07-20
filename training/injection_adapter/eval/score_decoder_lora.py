"""Score a trained injection-detector LoRA on the FROZEN 4101-row eval cache, emitting the
continuous injection score per row in the record format eval/qwen_injection/aggregate.py consumes:

    {"id": <cache id>, "score": <P(INJECTION) in (0,1), higher = more injection>}

so the fine-tuned adapter drops straight into the leaderboard (same global-tau ROC-interpolated
Recall@1%FPR + NotInject over-defense pipeline) as its own row, apples-to-apples with the
off-the-shelf Qwen judge rows. The score is the two-class softmax P(INJECTION) from the first
generated token -- computed by the SAME code (code/injscore.py) the training target used.

Resumable: skips ids already scored in the output file.

Launch:
  python eval/score_decoder_lora.py --base Qwen/Qwen3.5-0.8B \
     --adapter adapters/0.8b-sample --tag 0.8b-finetuned-sample
Then aggregate on the leaderboard machine:
  python eval/qwen_injection/aggregate.py 4b-instruct 0.8b-instruct 0.8b-finetuned-sample
"""

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent  # training/injection_adapter/eval
ROOT = HERE.parent  # training/injection_adapter
REPO = ROOT.parents[1]  # jataayu repo root
sys.path.insert(0, str(ROOT / "code"))
import injscore

DEFAULT_CACHE = REPO / "eval" / "results" / "qwen_scores" / "eval_cache.jsonl"
DEFAULT_OUTDIR = REPO / "eval" / "results" / "qwen_scores"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="Qwen/Qwen3.5-0.8B")
    ap.add_argument(
        "--adapter",
        default=str(ROOT / "adapters" / "run"),
        help="path to the trained LoRA adapter dir",
    )
    ap.add_argument("--tag", default="4b-finetuned", help="leaderboard row name / output filename")
    ap.add_argument("--cache", default=str(DEFAULT_CACHE))
    ap.add_argument(
        "--out", default=None, help="override output path (default <outdir>/<tag>.jsonl)"
    )
    ap.add_argument("--outdir", default=str(DEFAULT_OUTDIR))
    ap.add_argument("--max-len", type=int, default=4096)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--bf16", action="store_true", help="bf16 (Ampere+); default fp16")
    ap.add_argument(
        "--fp32",
        action="store_true",
        help="full fp32 -- REQUIRED on Pascal (1080 Ti): Qwen3.5 linear-attn fp16 kernel crashes",
    )
    ap.add_argument(
        "--no-adapter",
        action="store_true",
        help="score the BASE model only (sanity baseline, no LoRA)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="load tokenizer, print scoring format + sample prompts; no model, no write",
    )
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(args.cache) if l.strip()]
    outpath = Path(args.out) if args.out else Path(args.outdir) / f"{args.tag}.jsonl"

    from transformers import AutoTokenizer

    tok = AutoTokenizer.from_pretrained(args.base, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    pos_id, neg_id = injscore.label_first_token_ids(tok)

    if args.dry_run:
        print(f"[dry-run] base={args.base} adapter={args.adapter} tag={args.tag}")
        print(f"[dry-run] cache={args.cache} rows={len(rows)} -> out={outpath}")
        print(
            f"[dry-run] verdict first-token ids: INJECTION={pos_id} ({tok.decode([pos_id])!r}) "
            f"BENIGN={neg_id} ({tok.decode([neg_id])!r})"
        )
        print(f"[dry-run] score = softmax([logit_{pos_id}, logit_{neg_id}])[0] = P(INJECTION)")
        print("[dry-run] output record schema: {'id': <str>, 'score': <float in (0,1)>}")
        for r in rows[:2]:
            print(f"\n--- cache row id={r['id']} label={r['label']} dataset={r['dataset']} ---")
            print("PROMPT (tail 240):", repr(injscore.build_prompt(tok, r["text"])[-240:]))
        print("\n[dry-run] OK -- no model loaded, nothing written.")
        return

    import torch
    from transformers import AutoModelForCausalLM

    dtype = torch.float32 if args.fp32 else (torch.bfloat16 if args.bf16 else torch.float16)
    try:
        model = AutoModelForCausalLM.from_pretrained(
            args.base, torch_dtype=dtype, device_map={"": 0}, trust_remote_code=True
        )
    except (ValueError, KeyError):
        from transformers import AutoModelForImageTextToText

        model = AutoModelForImageTextToText.from_pretrained(
            args.base, torch_dtype=dtype, device_map={"": 0}, trust_remote_code=True
        )
    if not args.no_adapter:
        from peft import PeftModel

        model = PeftModel.from_pretrained(model, args.adapter)
    model.eval()
    dev = next(model.parameters()).device

    done = set()
    if outpath.exists():
        for l in outpath.open():
            try:
                done.add(json.loads(l)["id"])
            except Exception:
                pass
    todo = [r for r in rows if r["id"] not in done]
    print(
        f"[{args.tag}] {len(rows)} total, {len(done)} done, {len(todo)} to score "
        f"| base={args.base} adapter={'NONE' if args.no_adapter else args.adapter}",
        flush=True,
    )

    outpath.parent.mkdir(parents=True, exist_ok=True)
    fout = outpath.open("a")
    B = args.batch_size
    for i in range(0, len(todo), B):
        chunk = todo[i : i + B]
        res = injscore.injection_scores(
            model,
            tok,
            [r["text"] for r in chunk],
            pos_id,
            neg_id,
            max_len=args.max_len,
            batch_size=B,
            device=dev,
        )
        for r, x in zip(chunk, res):
            fout.write(json.dumps({"id": r["id"], "score": x["score"]}) + "\n")
        fout.flush()
        if (i // B) % 10 == 0:
            print(f"[{args.tag}] {min(i + B, len(todo))}/{len(todo)}", flush=True)
    fout.close()
    print(f"[{args.tag}] DONE -> {outpath}", flush=True)


if __name__ == "__main__":
    main()
