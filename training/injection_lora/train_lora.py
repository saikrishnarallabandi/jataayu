"""LoRA SFT for injection detection on Qwen3-8B. bf16, completion-only loss.
For TRL 1.7 / transformers 5. Run inside nvcr.io/nvidia/pytorch on dgx (GB10). wandb."""
import argparse
from pathlib import Path
import torch
import torch.nn as _nn
if not hasattr(_nn.Module, "set_submodule"):
    def _set_submodule(self, target, module):
        atoms = target.split("."); mod = self
        for a in atoms[:-1]: mod = getattr(mod, a)
        setattr(mod, atoms[-1], module)
    _nn.Module.set_submodule = _set_submodule
from datasets import load_dataset
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import LoraConfig, prepare_model_for_kbit_training
from trl import SFTTrainer, SFTConfig

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="Qwen/Qwen3-8B")
    ap.add_argument("--data-dir", default=str(Path(__file__).parent / "data"))
    ap.add_argument("--out", default=str(Path(__file__).parent / "adapter"))
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--bs", type=int, default=16)
    ap.add_argument("--grad-accum", type=int, default=2)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--max-len", type=int, default=512)
    ap.add_argument("--run-name", default="qwen3-8b-injection-lora")
    ap.add_argument("--grad-ckpt", action="store_true")
    ap.add_argument("--qlora", action="store_true", help="4-bit QLoRA (consumer GPU)")
    args = ap.parse_args()

    tok = AutoTokenizer.from_pretrained(args.base, trust_remote_code=True)
    if tok.pad_token is None: tok.pad_token = tok.eos_token

    # prompt/completion format -> TRL masks the prompt when completion_only_loss=True
    ds = load_dataset("json", data_files={"train": f"{args.data_dir}/train.jsonl",
                                          "validation": f"{args.data_dir}/val.jsonl"})
    ds = ds.remove_columns([c for c in ds["train"].column_names if c not in ("prompt","completion")])

    if args.qlora:
        bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
        model = AutoModelForCausalLM.from_pretrained(args.base, quantization_config=bnb,
            device_map={"": 0}, trust_remote_code=True)
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=args.grad_ckpt)
    else:
        model = AutoModelForCausalLM.from_pretrained(args.base, dtype=torch.bfloat16,
            trust_remote_code=True, device_map="auto")
    model.config.use_cache = False

    lora = LoraConfig(r=16, lora_alpha=32, lora_dropout=0.05, bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj","k_proj","v_proj","o_proj","gate_proj","up_proj","down_proj"])

    cfg = SFTConfig(
        output_dir=args.out, num_train_epochs=args.epochs,
        per_device_train_batch_size=args.bs, gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr, lr_scheduler_type="cosine", warmup_ratio=0.03,
        logging_steps=10, eval_strategy="steps", eval_steps=100, save_steps=200,
        save_total_limit=2, bf16=True, gradient_checkpointing=args.grad_ckpt,
        max_length=args.max_len, completion_only_loss=True, packing=False,
        report_to="wandb", run_name=args.run_name)

    trainer = SFTTrainer(model=model, args=cfg, train_dataset=ds["train"],
        eval_dataset=ds["validation"], peft_config=lora)
    trainer.train()
    trainer.save_model(args.out)
    tok.save_pretrained(args.out)
    print(f"[done] adapter saved to {args.out}")

if __name__ == "__main__":
    main()
