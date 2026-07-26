#!/usr/bin/env bash
# Re-score all prompt/few-shot variants on orchestrator's ollama (qwen3.5:4b, GPU0).
# Sequential so the single loaded model isn't contended on the shared 6GB card.
set -u
cd /home/user/projects/jataayu
EP="http://localhost:11434"
M="qwen3.5:4b"
W=6
S="python3 -u benchmarks/qwen_injection/score_variant.py --model $M --endpoint $EP --workers $W"

echo "=== chain start $(date -u +%FT%TZ) ==="
# base done (4b-base-orchestrator). Decisive-first ordering; all runs resume from partials.
$S --variant p2   --fewshot 0 --tag 4b-p2
$S --variant p2   --fewshot 4 --tag 4b-p2-fs4
$S --variant p2   --fewshot 2 --tag 4b-p2-fs2
$S --variant p2   --fewshot 8 --tag 4b-p2-fs8
$S --variant p1   --fewshot 0 --tag 4b-p1
echo "=== chain done $(date -u +%FT%TZ) ==="
