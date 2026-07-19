"""LoRA/QLoRA SFT of Qwen3.5 for BINARY prompt-injection detection.

The model is trained as a JUDGE that emits a single decision word as its FIRST generated
token -- INJECTION (attack) or BENIGN -- under the SAME fixed judge framing as the
off-the-shelf leaderboard (eval/qwen_injection/score_instruct.py, see code/injscore.py).
Completion-only loss trains ONLY the decision word. At inference the detection score is the
CONTINUOUS two-class softmax P(INJECTION) from the first-token logits -- the continuous head
the leaderboard's "honest read" prescribed to replace the coarse 0-100 integer output.

fp16 plain-LoRA by default (Pascal GPUs like the 1080 Ti have unreliable bnb 4-bit and no bf16
tensor cores); bf16 (--bf16) on Ampere+; 4-bit QLoRA (--qlora) as a fallback for tight VRAM on
Ampere+. Reads a balanced train set in the unified schema written by code/build_sample.py
(fields: id,text,label,attack_type,source,split,license). Rows tagged split=heldout are dropped
defensively -- they must never be trained on. A small stratified slice is held out FROM TRAIN as
an in-training val set for the wandb task-quality callback ONLY; the real evaluation is
eval/score_decoder_lora.py on the frozen 4101-row eval cache.

ALTERNATIVE HEAD (considered, not the default): AutoModelForSequenceClassification with a single
regression logit gives a native continuous score and sidesteps token bookkeeping. We keep the
logprob-token head because (a) it preserves the exact generative judge framing that already scores
at encoder level off-the-shelf -- a strong warm-start prior -- while a seq-cls head on a decoder is
randomly initialised and needs more data; and (b) it stays byte-for-byte comparable to the
off-the-shelf judge row on the leaderboard. Revisit --head seqcls only if the token head
underperforms at 1% FPR.

Launch (detached, unbuffered, logged, wandb) -- per project directives:
  setsid nohup python -u code/train_lora.py --base Qwen/Qwen3.5-0.8B \
     --train-file data/sample_v0.jsonl --run-name 0.8b-injection-sample \
     > logs/train_0.8b_sample.log 2>&1 < /dev/null &
"""
import argparse
import json
import os
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent  # training/injection_adapter
import sys
sys.path.insert(0, str(HERE))
import injscore


def load_rows(train_file):
    rows = [json.loads(l) for l in open(train_file) if l.strip()]
    kept = [r for r in rows if r.get("split") != "heldout"]
    dropped = len(rows) - len(kept)
    return kept, dropped


def stratified_val(rows, val_frac, seed, val_cap):
    """Hold out a small stratified slice FROM TRAIN. Used only for the cheap HF eval-loss loop
    (to trigger step-level evaluation); checkpoint SELECTION is on the external dev slice. The
    val size is capped BEFORE removal so we never strip more from train than we actually use."""
    rng = random.Random(seed)
    pos = [r for r in rows if int(r["label"]) == 1]
    neg = [r for r in rows if int(r["label"]) == 0]
    rng.shuffle(pos); rng.shuffle(neg)
    nvp = min(len(pos) - 1, max(1, int(len(pos) * val_frac)))
    nvn = min(len(neg) - 1, max(1, int(len(neg) * val_frac)))
    if val_cap and nvp + nvn > val_cap:  # cap first, split the budget across classes
        nvp = max(1, int(val_cap * nvp / (nvp + nvn)))
        nvn = max(1, val_cap - nvp)
    val = pos[:nvp] + neg[:nvn]
    train = pos[nvp:] + neg[nvn:]
    rng.shuffle(val); rng.shuffle(train)
    return train, val


CFP_TAU = 0.5   # the operating point paired accuracy (and its OD-acc report) is read at


def cfp_family(row):
    """Family = the first segment of `class` (authority:system_colon:attack -> authority).
    Aggregate paired accuracy can hide one family collapsing, so every number is also cut by this."""
    c = (row.get("class") or "").strip()
    return c.split(":")[0] if c else "unknown"


def load_cfp_pairs(path):
    """Group a counterfactual-pair dev file by pair_id -> [{pair_id, family, arms}].

    A pair is any number of arms sharing a pair_id (2 today; an exfil third arm is coming), so
    nothing here assumes two. The self-balancing property of paired accuracy holds only when a
    group carries BOTH polarities -- one arm alone is just per-row accuracy wearing a pair's name,
    and would reintroduce exactly the one-sided pressure this metric exists to remove. Such groups
    are dropped and counted rather than scored.

    Returns (pairs, stats). File order is preserved within and across groups so the fast subset and
    the score->arm alignment are deterministic."""
    rows = [json.loads(l) for l in open(path) if l.strip()]
    groups = {}
    for r in rows:
        pid = r.get("pair_id")
        if not pid:
            continue
        groups.setdefault(pid, []).append(r)
    pairs, degenerate = [], []
    for pid, arms in groups.items():
        labels = {int(a["label"]) for a in arms}
        if not ({0, 1} <= labels):
            degenerate.append(pid)
            continue
        fams = {cfp_family(a) for a in arms}
        # arms of a pair share a surface marker, so a split family means a malformed pair upstream;
        # surface it as its own bucket instead of silently attributing it to one family.
        pairs.append({"pair_id": pid, "family": fams.pop() if len(fams) == 1 else "mixed",
                      "arms": arms})
    stats = {"n_rows": len(rows), "n_pairs": len(pairs), "n_degenerate": len(degenerate),
             "no_pair_id": sum(1 for r in rows if not r.get("pair_id")),
             "arm_counts": sorted({len(p["arms"]) for p in pairs})}
    return pairs, stats


def fast_cfp_subset(pairs, cap, seed):
    """Fixed subset of WHOLE pairs for the in-loop metric -- mirrors fast_dev_subset's contract
    (deterministic under --seed, capped by ROW count), but a pair is never split across the cut:
    half a pair scores like an unpaired row and destroys the metric's self-balancing property."""
    if not cap:
        return list(pairs)
    rng = random.Random(seed)
    shuffled = list(pairs)
    rng.shuffle(shuffled)
    sub, used = [], 0
    for p in shuffled:
        if used + len(p["arms"]) > cap:
            continue
        sub.append(p); used += len(p["arms"])
    return sub or list(pairs[:1])


def flatten_cfp_arms(pairs):
    """Flat arm list; `scores` passed to cfp_paired_accuracy must align with THIS order."""
    return [a for p in pairs for a in p["arms"]]


def cfp_paired_accuracy(pairs, scores, tau=CFP_TAU):
    """Fraction of pairs where EVERY arm is correct at `tau` (attack p>=tau, benign p<tau).

    One number that punishes both failure modes: a `trigger => benign` shortcut model gets the
    benign twins right and the attacks wrong; an over-defending model gets the attacks right and
    the twins wrong. Either way the pair fails, so both score ~0 -- only reading intent scores.

    `scores` aligns with flatten_cfp_arms(pairs). Returns (aggregate, per_family, n_pairs);
    aggregate is None when there are no scorable pairs."""
    flat = flatten_cfp_arms(pairs)
    if len(scores) != len(flat):
        raise ValueError(f"cfp scores misaligned: {len(scores)} scores vs {len(flat)} arms")
    per_family, ok, i = {}, 0, 0
    for p in pairs:
        arm_scores = scores[i:i + len(p["arms"])]
        i += len(p["arms"])
        good = all((s >= tau) == (int(a["label"]) == 1) for a, s in zip(p["arms"], arm_scores))
        ok += bool(good)
        f = per_family.setdefault(p["family"], {"ok": 0, "n": 0})
        f["ok"] += bool(good); f["n"] += 1
    if not pairs:
        return None, {}, 0
    fam_acc = {k: v["ok"] / v["n"] for k, v in per_family.items()}
    return ok / len(pairs), fam_acc, len(pairs)


def select_metric(cfp_pairs, od_dev_rows, dev_rows):
    """The checkpoint-SELECTION key, highest priority first.

    Paired accuracy wins whenever a counterfactual-pair dev set is given: it is the only metric here
    that penalizes the `trigger => benign` shortcut AND over-defense with one number. The other two
    actively reward the shortcut (recall@1%FPR pools the trigger-benign proxy into its FPR budget;
    eval_dev_constrained gates on OD-acc >= floor), which is how v0.1 shipped the authority blind
    spot -- docs/finding-finetuning-induces-authority-blindspot.md. Below cfp the pre-existing
    ladder is untouched: this script trained the released v0.1 and must stay reproducible."""
    if cfp_pairs:
        return "eval_cfp_paired_acc"
    if od_dev_rows:
        return "eval_dev_constrained"
    return "eval_dev_recall" if dev_rows else "eval_roc_auc"


def fast_dev_subset(dev_rows, cap, seed):
    """Fixed class-balanced subset of the dev slice for the in-loop early-stop metric. The negative
    half is drawn WITHOUT filtering kind, so it keeps the same in-dist-benign vs over-defense-proxy
    mix as the full slice -> the proxy FP count stays meaningful at fine cadence."""
    rng = random.Random(seed)
    pos = [r for r in dev_rows if int(r["label"]) == 1]
    neg = [r for r in dev_rows if int(r["label"]) == 0]
    rng.shuffle(pos); rng.shuffle(neg)
    if not cap or cap >= len(dev_rows):
        sub = pos + neg
    else:
        half = cap // 2
        sub = pos[:min(half, len(pos))] + neg[:min(cap - half, len(neg))]
    rng.shuffle(sub)
    return sub


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="Qwen/Qwen3.5-0.8B",
                    help="HF id of the INSTRUCT base (bare name; -Instruct is not a public id)")
    ap.add_argument("--train-file", default=str(ROOT / "data" / "train_full.jsonl"))
    ap.add_argument("--out", default=str(ROOT / "adapters" / "run"))
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--bs", type=int, default=4)
    ap.add_argument("--grad-accum", type=int, default=4)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--max-len", type=int, default=1024)
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--lora-alpha", type=int, default=32)
    ap.add_argument("--lora-dropout", type=float, default=0.05)
    ap.add_argument("--val-frac", type=float, default=0.06)
    ap.add_argument("--val-cap", type=int, default=128,
                    help="cap for the in-train val slice used by the HF eval-loss loop")
    ap.add_argument("--dev-file", default=None,
                    help="held-out DEV slice (disjoint from the reported eval_cache) for "
                         "checkpoint SELECTION; metric = recall@1%FPR maximized (see build_dev_slice.py)")
    ap.add_argument("--fast-dev-cap", type=int, default=500,
                    help="in-loop early-stop metric runs on a fixed class-balanced subset of this "
                         "size (fine cadence stays cheap); full dev + test cache are report-only")
    ap.add_argument("--cfp-dev-file", default=None,
                    help="held-out COUNTERFACTUAL-PAIR dev set (JSONL; rows sharing pair_id are one "
                         "pair). When given, SELECTION is eval_cfp_paired_acc = fraction of pairs "
                         "with EVERY arm correct at tau=0.5, maximized; the --od-acc-floor gate is "
                         "demoted to reporting (paired acc already penalizes over-defense)")
    ap.add_argument("--od-dev-file", default=None,
                    help="NotInject-DEV rows (disjoint from NotInject-test). Without --cfp-dev-file: "
                         "the CONSTRAINED selection metric (max recall SUBJECT TO OD-acc >= floor). "
                         "With it: REPORTING only -- OD-acc is logged every eval, never gated on")
    ap.add_argument("--od-acc-floor", type=float, default=0.97,
                    help="min NotInject-dev over-defense accuracy the selected checkpoint must meet "
                         "(IGNORED under --cfp-dev-file: this floor rewards calling trigger-dense "
                         "text benign and is a proximate cause of the v0.1 authority blind spot)")
    ap.add_argument("--eval-steps", type=int, default=50,
                    help="eval+save cadence in optimizer steps (fine resolution to catch overfit); "
                         "0 -> derive from --eval-frac")
    ap.add_argument("--eval-frac", type=float, default=0.1,
                    help="fallback eval cadence as a fraction of total steps when --eval-steps=0")
    ap.add_argument("--early-stop-patience", type=int, default=5)
    ap.add_argument("--early-stop-threshold", type=float, default=0.002)
    ap.add_argument("--save-total-limit", type=int, default=2,
                    help="checkpoints kept on disk; set high to retain the full frontier for analysis")
    ap.add_argument("--no-early-stop", action="store_true",
                    help="disable early stopping (e.g. frontier-reproduction runs that must reach a fixed step)")
    ap.add_argument("--seed", type=int, default=20260715)
    ap.add_argument("--grad-ckpt", action="store_true")
    ap.add_argument("--bf16", action="store_true", help="bf16 (Ampere+)")
    ap.add_argument("--fp32", action="store_true",
                    help="full fp32 -- REQUIRED on Pascal (1080 Ti): Qwen3.5's linear-attention "
                         "Triton kernel crashes in fp16 (LLVM 'unsupported f16 rounding') on sm_61")
    ap.add_argument("--qlora", action="store_true", help="4-bit QLoRA fallback (Ampere+ only)")
    ap.add_argument("--wandb-project", default="jataayu-injection-adapter")
    ap.add_argument("--run-name", default="qwen3.5-injection-lora")
    ap.add_argument("--dry-run", action="store_true",
                    help="load tokenizer, print formatted examples + target + scoring format; no train")
    args = ap.parse_args()

    rows, dropped = load_rows(args.train_file)
    train_rows, val_rows = stratified_val(rows, args.val_frac, args.seed, args.val_cap)
    npos = sum(1 for r in train_rows if int(r["label"]) == 1)
    print(f"[data] {args.train_file}: {len(rows)} usable (dropped {dropped} heldout) | "
          f"train={len(train_rows)} (pos={npos} neg={len(train_rows)-npos}) val={len(val_rows)}",
          flush=True)

    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(args.base, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    pos_id, neg_id = injscore.label_first_token_ids(tok)

    def to_example(r):
        return {"prompt": injscore.build_prompt(tok, r["text"]),
                "completion": injscore.completion_for(r["label"], tok.eos_token)}

    if args.dry_run:
        print(f"\n[dry-run] base={args.base} | fp16={not args.bf16} bf16={args.bf16} qlora={args.qlora}")
        print(f"[dry-run] verdict first-token ids: INJECTION={pos_id} ({tok.decode([pos_id])!r}) "
              f"BENIGN={neg_id} ({tok.decode([neg_id])!r})")
        print(f"[dry-run] score at inference = softmax([logit_{pos_id}, logit_{neg_id}])[0] "
              f"= P(INJECTION) in (0,1)")
        for r in train_rows[:2] + val_rows[:1]:
            ex = to_example(r)
            print("\n--- formatted example (label=%s src=%s) ---" % (r["label"], r.get("source")))
            print("PROMPT (tail 300):", repr(ex["prompt"][-300:]))
            print("COMPLETION (target):", repr(ex["completion"]))
        # confirm the prompt's final token is the verdict slot (completion follows cleanly)
        p_ids = tok(to_example(train_rows[0])["prompt"], add_special_tokens=False).input_ids
        c_ids = tok(to_example(train_rows[0])["prompt"] + injscore.POS_LABEL,
                    add_special_tokens=False).input_ids
        print(f"\n[dry-run] prompt tokens={len(p_ids)}; first completion token id={c_ids[len(p_ids)]} "
              f"(expect {pos_id})")
        import math
        spe = max(1, math.ceil(math.ceil(len(train_rows) / args.bs) / args.grad_accum))
        tot = max(1, round(spe * args.epochs))
        es = args.eval_steps if args.eval_steps > 0 else max(1, round(tot * args.eval_frac))
        if args.dev_file:
            dr = [json.loads(l) for l in open(args.dev_file) if l.strip()]
            fd = fast_dev_subset(dr, args.fast_dev_cap, args.seed)
            fp = sum(1 for r in fd if int(r["label"]) == 1)
            px = sum(1 for r in fd if r.get("kind") == "overdefense_proxy")
            print(f"[dry-run] dev slice {len(dr)} -> FAST-DEV {len(fd)} (pos={fp} neg={len(fd)-fp}, "
                  f"proxy={px}) -> select on eval_dev_recall (recall@1%FPR), maximize, "
                  f"early-stop patience {args.early_stop_patience} threshold {args.early_stop_threshold}")
            print("[dry-run] wandb series per eval: dev/recall_at_1fpr, dev/overdefense_fp_count, "
                  "train loss (HF)")
        else:
            print("[dry-run] no --dev-file -> select on eval_roc_auc")
        if args.cfp_dev_file:
            cp, cstats = load_cfp_pairs(args.cfp_dev_file)
            fc = fast_cfp_subset(cp, args.fast_dev_cap, args.seed)
            import collections as _c
            fams = dict(_c.Counter(p["family"] for p in fc))
            print(f"[dry-run] cfp dev {cstats} -> FAST-CFP {len(fc)} pairs "
                  f"({len(flatten_cfp_arms(fc))} arms) families={fams}")
            print(f"[dry-run] OVERRIDES the above: select on eval_cfp_paired_acc (every arm correct "
                  f"at tau={CFP_TAU}), maximize; --od-acc-floor DEMOTED to reporting")
            print("[dry-run] wandb series per eval: dev/cfp_paired_acc, dev/cfp_paired_acc.<family>, "
                  "dev/cfp_arm_acc.{attack,benign}, dev/notinject_od_acc@0.5")
        print(f"[dry-run] schedule: bs={args.bs} ga={args.grad_accum} steps/epoch={spe} "
              f"total~{tot} eval+save every {es} steps (~{tot // es} evals)")
        print("[dry-run] OK -- no model loaded, no training run.")
        return

    import torch
    from transformers import AutoModelForCausalLM, BitsAndBytesConfig
    from peft import LoraConfig, prepare_model_for_kbit_training
    from trl import SFTTrainer, SFTConfig
    from datasets import Dataset

    os.environ.setdefault("WANDB_PROJECT", args.wandb_project)
    compute_dtype = torch.float32 if args.fp32 else (torch.bfloat16 if args.bf16 else torch.float16)

    load_kwargs = dict(trust_remote_code=True)
    if args.qlora:
        load_kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=compute_dtype, bnb_4bit_use_double_quant=True)
        load_kwargs["device_map"] = {"": 0}
    else:
        load_kwargs["dtype"] = compute_dtype
        load_kwargs["device_map"] = {"": 0}

    # Qwen3.5 ships as a multimodal Qwen3_5ForConditionalGeneration checkpoint; we feed TEXT only.
    # AutoModelForCausalLM resolves the text-generation interface in transformers >=5.3; fall back
    # to the image-text-to-text class if the causal head is not registered for this arch.
    try:
        model = AutoModelForCausalLM.from_pretrained(args.base, **load_kwargs)
    except (ValueError, KeyError) as e:
        print(f"[warn] AutoModelForCausalLM failed ({type(e).__name__}); trying AutoModelForImageTextToText")
        from transformers import AutoModelForImageTextToText
        model = AutoModelForImageTextToText.from_pretrained(args.base, **load_kwargs)

    if args.qlora:
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=args.grad_ckpt)
    model.config.use_cache = False

    lora = LoraConfig(r=args.lora_r, lora_alpha=args.lora_alpha, lora_dropout=args.lora_dropout,
                      bias="none", task_type="CAUSAL_LM",
                      target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                      "gate_proj", "up_proj", "down_proj"])

    train_ds = Dataset.from_list([to_example(r) for r in train_rows])
    val_ds = Dataset.from_list([to_example(r) for r in val_rows])

    # step-level eval/save cadence = eval_frac of the total optimizer steps, so early stopping has
    # resolution to stop WITHIN the epoch ceiling (per-epoch eval is too coarse for a 2-epoch run).
    import math
    steps_per_epoch = max(1, math.ceil(math.ceil(len(train_rows) / args.bs) / args.grad_accum))
    total_steps = max(1, round(steps_per_epoch * args.epochs))
    eval_steps = args.eval_steps if args.eval_steps > 0 else max(1, round(total_steps * args.eval_frac))

    dev_rows = None
    if args.dev_file:
        full_dev = [json.loads(l) for l in open(args.dev_file) if l.strip()]
        # in-loop metric runs on a FIXED class-balanced FAST subset so 50-step evals stay cheap;
        # the full dev slice + the 4101-row test cache are used for final reporting only.
        dev_rows = fast_dev_subset(full_dev, args.fast_dev_cap, args.seed)
    od_dev_rows = None
    if args.od_dev_file:
        od_dev_rows = [json.loads(l) for l in open(args.od_dev_file) if l.strip()]
    cfp_pairs = None
    if args.cfp_dev_file:
        full_cfp, cfp_stats = load_cfp_pairs(args.cfp_dev_file)
        # fail HERE, not at the first eval of a multi-hour GPU run: an unusable pair file would
        # leave eval_cfp_paired_acc absent and load_best/EarlyStopping would KeyError mid-train.
        if not full_cfp:
            raise SystemExit(f"[fatal] --cfp-dev-file {args.cfp_dev_file}: no usable pairs "
                             f"({cfp_stats}) -- a pair needs >=1 attack and >=1 benign arm")
        cfp_pairs = fast_cfp_subset(full_cfp, args.fast_dev_cap, args.seed)
        print(f"[data] cfp dev {args.cfp_dev_file}: {cfp_stats} -> FAST-CFP {len(cfp_pairs)} pairs "
              f"({len(flatten_cfp_arms(cfp_pairs))} arms)", flush=True)
    best_metric = select_metric(cfp_pairs, od_dev_rows, dev_rows)
    nproxy = sum(1 for r in (dev_rows or []) if r.get("kind") == "overdefense_proxy")
    gate = "REPORTING-ONLY (demoted)" if cfp_pairs else args.od_acc_floor
    print(f"[schedule] steps/epoch={steps_per_epoch} total~{total_steps} eval_steps={eval_steps} "
          f"select_on={best_metric} fast_dev={len(dev_rows) if dev_rows else 0} "
          f"(overdefense_proxy={nproxy}) od_dev={len(od_dev_rows) if od_dev_rows else 0} "
          f"od_acc_floor={gate}", flush=True)

    cfg = SFTConfig(
        output_dir=args.out, num_train_epochs=args.epochs,
        per_device_train_batch_size=args.bs, gradient_accumulation_steps=args.grad_accum,
        per_device_eval_batch_size=max(1, args.bs), learning_rate=args.lr,
        lr_scheduler_type="cosine", warmup_ratio=0.03, logging_steps=5,
        eval_strategy="steps", eval_steps=eval_steps,
        save_strategy="steps", save_steps=eval_steps, save_total_limit=args.save_total_limit,
        load_best_model_at_end=True, metric_for_best_model=best_metric, greater_is_better=True,
        bf16=args.bf16, fp16=(not args.bf16 and not args.fp32),
        gradient_checkpointing=args.grad_ckpt,
        max_length=args.max_len, completion_only_loss=True, packing=False,
        report_to="wandb", run_name=args.run_name, seed=args.seed)

    trainer = SFTTrainer(model=model, args=cfg, train_dataset=train_ds, eval_dataset=val_ds,
                         processing_class=tok, peft_config=lora)

    # Metric callback FIRST (injects eval_dev_recall into the metrics dict), then EarlyStopping so
    # it reads the injected key. Selection/stop is on the disjoint dev slice; NotInject stays fully
    # external (scored post-hoc) -- early stopping does not optimize over-defense directly.
    trainer.add_callback(_InjEvalCallback(trainer, tok, val_rows, dev_rows,
                                          pos_id, neg_id, args.max_len,
                                          od_dev_rows=od_dev_rows, od_acc_floor=args.od_acc_floor,
                                          cfp_pairs=cfp_pairs))
    if not args.no_early_stop:
        from transformers import EarlyStoppingCallback
        trainer.add_callback(EarlyStoppingCallback(
            early_stopping_patience=args.early_stop_patience,
            early_stopping_threshold=args.early_stop_threshold))

    trainer.train()
    trainer.save_model(args.out)          # load_best_model_at_end=True -> saves the BEST checkpoint
    tok.save_pretrained(args.out)
    bm = getattr(trainer.state, "best_metric", None)
    print(f"[done] adapter saved to {args.out} | best {best_metric}={bm} "
          f"best_ckpt={getattr(trainer.state, 'best_model_checkpoint', None)} "
          f"stopped_at_step={trainer.state.global_step}", flush=True)


from transformers import TrainerCallback


def _recall_at_fpr(benign, pos, budget=0.01):
    """Recall (TPR) at `budget` FPR, ROC-interpolated -- same reading as the leaderboard's
    aggregate.recall_at_fpr_interp, so the dev selection metric matches the reported metric."""
    if not benign or not pos:
        return None
    import numpy as np
    from sklearn.metrics import roc_curve
    y = np.array([0] * len(benign) + [1] * len(pos))
    s = np.array(list(benign) + list(pos), float)
    fpr, tpr, _ = roc_curve(y, s)
    return float(np.interp(budget, fpr, tpr))


class _InjEvalCallback(TrainerCallback):
    """At each step-level evaluation, score with the continuous first-token head and log task
    quality to wandb (val token-acc/AUC + a generations table). If a DEV slice is given, ALSO score
    it and inject `eval_dev_recall` = recall@1%FPR into the metrics dict -- the SELECTION metric
    (maximized, load_best_model_at_end, early-stopping read it). The dev benign pool includes the
    trigger-bearing over-defense proxy, so over-defense pressure is folded into the number.

    If a COUNTERFACTUAL-PAIR dev set is given it takes over selection: inject `eval_cfp_paired_acc`
    = fraction of pairs with every arm correct at tau=0.5. Both of the older dev metrics reward
    calling trigger-dense text benign (recall@1%FPR via the trigger-benign proxy in its FPR pool,
    and the OD-acc floor outright), i.e. they search for the `trigger => benign` shortcut that
    v0.1 shipped -- see docs/finding-finetuning-induces-authority-blindspot.md. Paired accuracy
    fails BOTH arms of that trade, so the OD floor is demoted to a logged number here.

    Mutating the passed `metrics` dict in place makes eval_dev_recall visible to load-best and to
    EarlyStoppingCallback; this callback is registered BEFORE EarlyStopping so the key exists when
    EarlyStopping reads it. NotInject itself stays external and is scored post-hoc."""
    def __init__(self, trainer, tok, val_rows, dev_rows, pos_id, neg_id, max_len,
                 od_dev_rows=None, od_acc_floor=0.97, cfp_pairs=None):
        self.trainer = trainer; self.tok = tok; self.val_rows = val_rows; self.dev_rows = dev_rows
        self.pos_id = pos_id; self.neg_id = neg_id; self.max_len = max_len
        self.od_dev_rows = od_dev_rows; self.od_acc_floor = od_acc_floor
        self.cfp_pairs = cfp_pairs

    def _score(self, rows, bs):
        model = self.trainer.model
        dev = next(model.parameters()).device
        was_training = model.training
        res = injscore.injection_scores(model, self.tok, [r["text"] for r in rows],
                                        self.pos_id, self.neg_id, max_len=self.max_len,
                                        batch_size=bs, device=dev)
        if was_training:
            model.train()
        return [x["score"] for x in res]

    def on_evaluate(self, args, state, control, **kwargs):
        import numpy as np
        metrics = kwargs.get("metrics")
        # in-train val: token-acc + AUC (monitoring)
        vscores = self._score(self.val_rows, 16)
        vlabels = [int(r["label"]) for r in self.val_rows]
        log = {"val/token_acc": float(np.mean([(s >= 0.5) == y for s, y in zip(vscores, vlabels)]))}
        if len(set(vlabels)) == 2:
            from sklearn.metrics import roc_auc_score
            auc = float(roc_auc_score(vlabels, vscores))
            log["val/auc"] = auc
            if metrics is not None:
                metrics["eval_roc_auc"] = auc
        # DEV slice: recall@1%FPR = the SELECTION metric (benign pool includes the over-defense
        # proxy, so flagging trigger-benign raises FPR -> raises tau -> costs recall = penalty).
        if self.dev_rows:
            dscores = self._score(self.dev_rows, 16)
            rows = self.dev_rows
            benign = [s for s, r in zip(dscores, rows) if int(r["label"]) == 0]
            pos = [s for s, r in zip(dscores, rows) if int(r["label"]) == 1]
            rec = _recall_at_fpr(benign, pos, 0.01)
            if rec is not None:
                log["dev/recall_at_1fpr"] = rec
                if metrics is not None:
                    metrics["eval_dev_recall"] = rec
            # SEPARATE over-defense visibility series (NOT the selection metric): FP COUNT on the
            # trigger-benign proxy at tau = the 1%-FPR point of the IN-DIST benign only -- mirrors
            # how NotInject FP is computed post-hoc, so a rising count is the overfit-into-over-
            # defense signature even while dev-recall plateaus.
            indist = [s for s, r in zip(dscores, rows)
                      if int(r["label"]) == 0 and r.get("kind") != "overdefense_proxy"]
            proxy = [s for s, r in zip(dscores, rows) if r.get("kind") == "overdefense_proxy"]
            if indist and proxy:
                tau = float(np.quantile(indist, 0.99))
                log["dev/overdefense_fp_count"] = int(np.sum(np.array(proxy) >= tau))
                log["dev/overdefense_n_proxy"] = len(proxy)
            # CONSTRAINED selection: max recall SUBJECT TO real-NotInject-dev OD-acc >= floor.
            # Encoded as a single maximized scalar with a lexicographic split: any checkpoint that
            # MEETS the constraint (>=1.0+recall) outranks any that violates it (<1.0=od_acc); among
            # violators, the one closest to feasible (highest od_acc) ranks highest. Threshold tau is
            # the 1%-FPR point of the dev in-dist benign -- the same operating point recall is read at.
            if self.od_dev_rows is not None and indist and rec is not None and not self.cfp_pairs:
                tau = float(np.quantile(indist, 0.99))
                od_scores = self._score(self.od_dev_rows, 16)
                od_acc = float(np.mean(np.array(od_scores) < tau))
                od_fp = int(np.sum(np.array(od_scores) >= tau))
                constrained = (1.0 + rec) if od_acc >= self.od_acc_floor else od_acc
                log["dev/notinject_dev_od_acc"] = od_acc
                log["dev/notinject_dev_fp"] = od_fp
                log["dev/constrained_metric"] = constrained
                if metrics is not None:
                    metrics["eval_dev_constrained"] = constrained
        # COUNTERFACTUAL PAIRS: the selection metric when --cfp-dev-file is given. Scored through
        # injscore like everything else, so training-time and eval-time scoring cannot drift.
        if self.cfp_pairs:
            arms = flatten_cfp_arms(self.cfp_pairs)
            ascores = self._score(arms, 16)
            agg, fam, npairs = cfp_paired_accuracy(self.cfp_pairs, ascores, CFP_TAU)
            log["dev/cfp_paired_acc"] = agg
            log["dev/cfp_n_pairs"] = npairs
            for f, v in sorted(fam.items()):          # aggregate can hide one family at zero
                log[f"dev/cfp_paired_acc.{f}"] = v
            # per-arm accuracy, split by polarity: says WHICH way a low paired acc failed --
            # shortcut (attacks wrong, twins right) vs over-defense (the mirror image).
            for pol, lab in (("attack", 1), ("benign", 0)):
                sel = [(s, a) for s, a in zip(ascores, arms) if int(a["label"]) == lab]
                if sel:
                    log[f"dev/cfp_arm_acc.{pol}"] = float(
                        np.mean([(s >= CFP_TAU) == (lab == 1) for s, _ in sel]))
            if metrics is not None:
                metrics["eval_cfp_paired_acc"] = agg
        # NotInject OD-acc: REPORTING ONLY under paired selection (never gated on) -- read at the
        # same tau paired accuracy uses, so the over-defense cost of v0.2 is visible every eval
        # rather than discovered after the run.
        if self.cfp_pairs and self.od_dev_rows:
            od_scores = self._score(self.od_dev_rows, 16)
            log["dev/notinject_od_acc@0.5"] = float(np.mean(np.array(od_scores) < CFP_TAU))
            log["dev/notinject_fp@0.5"] = int(np.sum(np.array(od_scores) >= CFP_TAU))
        try:
            import wandb
            if wandb.run is not None:
                tbl = wandb.Table(columns=["label", "score", "pred", "text"])
                for r, s in list(zip(self.val_rows, vscores))[:32]:
                    tbl.add_data(int(r["label"]), round(s, 4), int(s >= 0.5), r["text"][:400])
                wandb.log({**log, "val/generations": tbl}, step=state.global_step)
            else:
                self.trainer.log(log)
        except Exception:
            self.trainer.log(log)
        print(f"[eval@step{state.global_step}] " +
              " ".join(f"{k}={v:.4f}" for k, v in log.items()), flush=True)


if __name__ == "__main__":
    main()
