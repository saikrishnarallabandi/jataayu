#!/bin/bash
cd /home/user/projects/jataayu/eval
PY=/home/user/miniconda3/envs/suchilm/bin/python
export CUDA_VISIBLE_DEVICES=0
$PY -u qwen_injection/score_encoder.py --model meta-llama/Llama-Prompt-Guard-2-86M --tag enc-promptguard2-86m --batch-size 16
$PY -u qwen_injection/score_encoder.py --model meta-llama/Llama-Prompt-Guard-2-22M --tag enc-promptguard2-22m --batch-size 16
echo "PG2 DONE"
