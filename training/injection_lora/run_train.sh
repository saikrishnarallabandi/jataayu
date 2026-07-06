#!/bin/bash
cd ~/injection_lora
pkill -9 -f train_lora.py 2>/dev/null
sleep 3
rm -f train.log
export WANDB_API_KEY=$(cat ~/.wandb_key)
export WANDB_MODE=online
# plain bf16 LoRA (no bitsandbytes). bs2 grad_accum8 for 24GB.
setsid nohup python3 -u train_lora.py --grad-ckpt --epochs 1 --bs 2 --grad-accum 8 \
  --max-len 512 --run-name qwen3-8b-inj-lora-bf16 > train.log 2>&1 < /dev/null &
echo "launched PID $!"
