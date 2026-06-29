#!/usr/bin/env python3
"""
SFT warmup (StruQ) for jataayu Layer 2 — full fp16 LoRA.

Teaches the model, given a structured [INSTRUCTION]/[DATA] prompt whose DATA channel contains an
injected attack, to produce the GOLD completion of the legitimate task (ignoring the injection).
Prompt-completion format -> loss on the completion only. Run before train_dpo.py.

    python train_sft.py --base Qwen/Qwen2.5-3B-Instruct --data data/sft.jsonl --out exp/sft
"""
import argparse
from pathlib import Path

import torch
from datasets import load_dataset
from peft import LoraConfig
from transformers import AutoModelForCausalLM, AutoTokenizer
from trl import SFTConfig, SFTTrainer


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="Qwen/Qwen2.5-3B-Instruct")
    ap.add_argument("--data", default="data/sft.jsonl")
    ap.add_argument("--out", default="exp/sft")
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--lora_r", type=int, default=32)
    ap.add_argument("--max_steps", type=int, default=-1)
    args = ap.parse_args()

    ds = load_dataset("json", data_files=str(Path(args.data)), split="train")
    tok = AutoTokenizer.from_pretrained(args.base, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        args.base, dtype=torch.float16, device_map="auto", trust_remote_code=True,
    )

    peft_cfg = LoraConfig(
        r=args.lora_r, lora_alpha=args.lora_r * 2, lora_dropout=0.05,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        bias="none", task_type="CAUSAL_LM",
    )
    cfg = SFTConfig(
        output_dir=args.out,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=2,
        gradient_accumulation_steps=8,
        learning_rate=args.lr,
        max_length=1024,
        fp16=True, bf16=False,
        logging_steps=10, save_strategy="no",
        max_steps=args.max_steps,
        report_to=["wandb"], run_name="secalign-sft", seed=42,
    )
    trainer = SFTTrainer(model=model, args=cfg, train_dataset=ds,
                         processing_class=tok, peft_config=peft_cfg)
    trainer.train()
    # Merge the SFT LoRA into the base so DPO can train a fresh adapter on top.
    merged = trainer.model.merge_and_unload()
    merged.save_pretrained(args.out + "-merged")
    tok.save_pretrained(args.out + "-merged")
    print(f"saved merged SFT model -> {args.out}-merged")


if __name__ == "__main__":
    main()
