#!/bin/bash
cd /home/user/projects/jataayu/eval
PY=/home/user/miniconda3/envs/suchilm/bin/python
export CUDA_VISIBLE_DEVICES=0
run(){ echo "### $2 ($1)"; $PY -u qwen_injection/score_encoder.py --model "$1" --tag "$2" --batch-size 16; }
run protectai/deberta-v3-base-prompt-injection-v2  enc-protectai-v2
run deepset/deberta-v3-base-injection              enc-deepset
run meta-llama/Llama-Prompt-Guard-2-86M            enc-promptguard2-86m
run meta-llama/Llama-Prompt-Guard-2-22M            enc-promptguard2-22m
echo "ALL ENCODERS DONE"
