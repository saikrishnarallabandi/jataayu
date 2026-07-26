#!/bin/bash
# Run the larger BASE variants once 0.8b-base finishes and the local GPU frees.
# 2B fp16 ~4.5GB should fit after ollama unloads; 4B fp16 ~8GB likely OOMs on the
# shared Pascal cards (the attempt + traceback documents the skip). 9B is not
# attempted (fp16 ~18GB > a single 11GB card).
cd /home/user/projects/jataayu/eval
PY=/home/user/miniconda3/envs/suchilm/bin/python
L=results/qwen_scores
while pgrep -f "score_base.py --model Qwen/Qwen3.5-0.8B-Base" >/dev/null; do sleep 30; done
sleep 90   # let ollama unload the finished instruct models
pick_gpu(){ nvidia-smi --query-gpu=index,memory.free --format=csv,noheader,nounits | sort -t, -k2 -rn | head -1 | cut -d, -f1 | tr -d ' '; }

for spec in "Qwen/Qwen3.5-2B-Base:2b-base" "Qwen/Qwen3.5-4B-Base:4b-base"; do
  mid="${spec%%:*}"; tag="${spec##*:}"
  g=$(pick_gpu)
  echo "### $tag on GPU$g ($(nvidia-smi --query-gpu=memory.free --format=csv,noheader -i $g))" >> "$L/$tag.log"
  CUDA_VISIBLE_DEVICES=$g $PY -u qwen_injection/score_base.py --model "$mid" --tag "$tag" >> "$L/$tag.log" 2>&1
done
echo "BASE CHAIN DONE"
