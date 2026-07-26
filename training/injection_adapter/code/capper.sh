#!/bin/bash
cd /home/user/projects/jataayu/training/injection_adapter
while true; do
  tr=$(cat data/synth_tool_returns_full.shard*.jsonl 2>/dev/null | wc -l)
  hn=$(cat data/synth_hard_negatives_full.shard*.jsonl 2>/dev/null | wc -l)
  echo "$(date +%H:%M:%S) TR=$tr HN=$hn" >> logs/capper.log
  [ "$tr" -ge 40000 ] && pkill -f "[s]ynth_tool_returns.py"
  [ "$hn" -ge 15000 ] && pkill -f "[s]ynth_hard_negatives.py"
  pgrep -f "synth_.*_full" >/dev/null || { echo "all synth done" >> logs/capper.log; break; }
  sleep 15
done
