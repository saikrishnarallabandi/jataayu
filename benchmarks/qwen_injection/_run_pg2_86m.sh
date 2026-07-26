#!/bin/bash
cd /home/user/projects/jataayu/eval
export CUDA_VISIBLE_DEVICES=0
/home/user/miniconda3/envs/suchilm/bin/python -u qwen_injection/score_encoder.py \
    --model meta-llama/Llama-Prompt-Guard-2-86M --tag enc-promptguard2-86m --batch-size 8
echo "86M SCRIPT DONE rc=$?"
