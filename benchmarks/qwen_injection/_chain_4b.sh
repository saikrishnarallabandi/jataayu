#!/bin/bash
cd /home/user/projects/jataayu/eval
source .venv-hf/bin/activate
# tara ollama serves one model at a time; wait for the 9b scorer to finish first
while pgrep -f "score_instruct.py --model qwen3.5:9b" >/dev/null; do sleep 30; done
python3 -u qwen_injection/score_instruct.py --model qwen3.5:4b --endpoint http://localhost:11437 --tag 4b-instruct --workers 8
