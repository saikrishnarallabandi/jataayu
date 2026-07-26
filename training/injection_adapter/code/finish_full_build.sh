#!/bin/bash
# Wait for all scaled synthesis shards to finish, then build + validate the full train set.
# Design (by-channel 60/40 indirect, 50/50 label, uses ALL 28,801 real attacks -> ~57.6k set):
#   indirect_pos=10323 (llmail) | direct_pos=18478 | tool_returns=24238 (indirect-benign)
#   layer1_benign=1563 + hard_negs=3000 (direct-benign)
cd /home/user/projects/jataayu/training/injection_adapter
PY=../../eval/.venv-hf/bin/python
LOG=logs/finish_full_build.log
echo "[finish] waiting for synth shards to complete..." > $LOG
while pgrep -f "synth_.*_full" >/dev/null; do
  sleep 30
done
echo "[finish] synthesis done. counts:" >> $LOG
wc -l data/synth_tool_returns_full.shard*.jsonl data/synth_hard_negatives_full.shard*.jsonl >> $LOG 2>&1
echo "[finish] building full train set..." >> $LOG
$PY -u code/build_sample.py \
  --pool data/layer1_pool_full.jsonl \
  --tool-returns "data/synth_tool_returns_full.shard*.jsonl" \
  --hard-negs "data/synth_hard_negatives_full.shard*.jsonl" \
  --out data/train_full.jsonl --no-auto-balance \
  --n-indirect-pos 10323 --n-direct-pos 18478 \
  --n-tool-returns 24238 --n-layer1-benign 1563 --n-hard-negs 3000 \
  >> $LOG 2>&1
echo "[finish] BUILD_DONE" >> $LOG
