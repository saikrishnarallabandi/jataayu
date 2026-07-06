#!/bin/bash
cd ~/injection_lora
pkill -9 -f eval_lora.py 2>/dev/null
sleep 3
rm -f eval.log heldout_results.json
setsid nohup python3 -u eval_lora.py \
  --datasets deepset/prompt-injections jackhhao/jailbreak-classification \
  --out heldout_results.json > eval.log 2>&1 < /dev/null &
echo "eval launched PID $!"
