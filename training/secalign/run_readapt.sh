#!/bin/bash
# Re-adapted GCG: attack the hardened model with seeds it did NOT adversarially train on
# (naive + bare), at a bigger budget. The "Attacker Moves Second" test.
cd "$(dirname "$0")"
export HF_HOME="${HF_HOME:-$HOME/.cache/huggingface}"
P="${GCG_PYTHON:-python}"
R=results_readapt.txt
echo "=== RE-ADAPTED GCG (different seed + bigger budget) $(date -u) ===" > $R

echo ">>> SANITY: re-adapted (naive seed) on ORIGINAL — must break" | tee -a $R
$P gcg_attack.py --model exp/sft-merged --adapter exp/dpo --seed_style naive \
  --n 2 --steps 250 --suffix_len 28 --search_width 256 --topk 128 2>>readapt_err.log \
  | tee -a $R | grep -E "GCG ASR"

echo ">>> RE-ADAPTED naive-seed on HARDENED (untrained escape)" | tee -a $R
$P gcg_attack.py --model exp/sft_adv-merged --adapter exp/dpo_adv --seed_style naive \
  --n 6 --steps 250 --suffix_len 28 --search_width 256 --topk 128 2>>readapt_err.log \
  | tee -a $R | grep -E "GCG ASR"

echo ">>> RE-ADAPTED bare-seed on HARDENED (pure GCG, no injection text)" | tee -a $R
$P gcg_attack.py --model exp/sft_adv-merged --adapter exp/dpo_adv --seed_style bare \
  --n 4 --steps 250 --suffix_len 28 --search_width 256 --topk 128 2>>readapt_err.log \
  | tee -a $R | grep -E "GCG ASR"

echo "=== DONE $(date -u) ===" >> $R
cat $R
