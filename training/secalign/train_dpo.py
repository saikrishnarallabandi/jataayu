#!/usr/bin/env python3
"""
SecAlign-style DPO fine-tune for jataayu Layer 2 (ready-to-launch).

QLoRA + fp16 DPO over the structured-channel preference pairs from prep_data.py. Logs to wandb.
This is a multi-hour GPU job — launch on dgx-pavan or a vast.ai RTX 4090, not inline.

    python prep_data.py
    python train_dpo.py --config config.yaml

Deps: transformers, trl, peft, datasets, bitsandbytes, wandb. (Imported lazily so the file can be
read/linted without the training stack installed.)
"""
import argparse
from pathlib import Path


def load_config(path: str) -> dict:
    import yaml
    return yaml.safe_load(Path(path).read_text())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args()
    cfg = load_config(args.config)

    import torch
    from datasets import load_dataset
    from peft import LoraConfig
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from trl import DPOConfig, DPOTrainer

    data_file = Path(__file__).parent / cfg["data_file"]
    if not data_file.exists():
        raise SystemExit(f"missing {data_file} — run prep_data.py first")
    ds = load_dataset("json", data_files=str(data_file), split="train")

    quant = BitsAndBytesConfig(
        load_in_4bit=cfg.get("load_in_4bit", True),
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,  # fp16 — house rule for DPO stability
        bnb_4bit_use_double_quant=True,
    )
    tok = AutoTokenizer.from_pretrained(cfg["base_model"], trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        cfg["base_model"], quantization_config=quant, torch_dtype=torch.float16,
        device_map="auto", trust_remote_code=True,
    )

    peft_cfg = LoraConfig(
        r=cfg["lora_r"], lora_alpha=cfg["lora_alpha"], lora_dropout=cfg["lora_dropout"],
        target_modules=cfg["lora_target_modules"], bias="none", task_type="CAUSAL_LM",
    )

    dpo_cfg = DPOConfig(
        output_dir=cfg["output_dir"],
        beta=cfg["beta"],
        learning_rate=cfg["learning_rate"],
        num_train_epochs=cfg["num_train_epochs"],
        per_device_train_batch_size=cfg["per_device_train_batch_size"],
        gradient_accumulation_steps=cfg["gradient_accumulation_steps"],
        max_length=cfg["max_length"],
        max_prompt_length=cfg["max_prompt_length"],
        fp16=cfg.get("fp16", True),
        bf16=cfg.get("bf16", False),
        logging_steps=cfg["logging_steps"],
        save_steps=cfg["save_steps"],
        seed=cfg["seed"],
        report_to=["wandb"],
        run_name="secalign-dpo",
    )

    trainer = DPOTrainer(
        model=model, args=dpo_cfg, train_dataset=ds,
        processing_class=tok, peft_config=peft_cfg,
    )
    trainer.train()
    trainer.save_model(cfg["output_dir"])
    print(f"saved adapter -> {cfg['output_dir']}")


if __name__ == "__main__":
    main()
