#!/usr/bin/env bash
# Phase B hosted-model sweep — gpt-5.4-mini (OpenAI) + claude-sonnet-5 (Anthropic),
# paired baseline+jataayu, native tool calling. Resumable (skips complete out-files).
# Runs after the qwen sweep; hosted APIs so no GPU contention.
#   nohup bash eval/agentdojo/sweep_hosted.sh > runs/agentdojo/sweep_hosted.log 2>&1 &
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
PY="${PY:-$REPO/eval/.venv/bin/python}"
MIN_STATUS="${MIN_STATUS:-HIGH}"
ATTACK="${ATTACK:-important_instructions}"
SUITES="${SUITES:-workspace banking travel slack}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DISCORD_TARGET="user:100000000000000001"

# model specs: "provider:model_id:tag"
MODELS="${MODELS:-openai:gpt-5.4-mini:gpt54mini anthropic:claude-sonnet-5:claudesonnet5}"

cd "$REPO" || exit 1
notify() { gateway message send --channel discord --target "$DISCORD_TARGET" --message "$1" 2>/dev/null || true; }

notify "[jataayu] Phase B HOSTED sweep started (min-status $MIN_STATUS): models = $MODELS, suites = $SUITES, paired baseline+jataayu."

for spec in $MODELS; do
  provider="${spec%%:*}"; rest="${spec#*:}"; model_id="${rest%%:*}"; tag="${rest#*:}"
  for suite in $SUITES; do
    OUT="$REPO/eval/results/agentdojo_${suite}_${tag}_sweep.json"
    if [ -f "$OUT" ] && ! grep -q '"note".*[Pp]artial' "$OUT" 2>/dev/null; then
      echo "[skip] $tag/$suite already complete"; continue
    fi
    LOGDIR="$REPO/runs/agentdojo/hosted_${STAMP}_${tag}_${suite}"
    echo "==== $tag / $suite ($(date -u +%H:%M:%SZ)) ===="
    "$PY" eval/agentdojo/run_agentdojo.py \
      --model "$provider" --model-id "$model_id" \
      --suite "$suite" --attack "$ATTACK" \
      --user-tasks user_task_0 user_task_1 user_task_2 user_task_3 user_task_4 \
      --injection-tasks injection_task_0 injection_task_1 injection_task_2 injection_task_3 \
      --variants baseline jataayu --min-status "$MIN_STATUS" \
      --logdir "$LOGDIR" --out "$OUT"
    RC=$?
    if [ $RC -ne 0 ] || [ ! -f "$OUT" ]; then
      echo "[fail] $tag/$suite rc=$RC"; notify "[jataayu] Phase B hosted: $tag/$suite FAILED (rc=$RC). Continuing."; continue
    fi
    MSG=$("$PY" - "$OUT" "$tag" "$suite" <<'PY'
import json, sys
d=json.load(open(sys.argv[1])); tag=sys.argv[2]; s=sys.argv[3]
b=next((r for r in d["results"] if r["defense"]=="none"), {})
j=next((r for r in d["results"] if r["defense"]=="jataayu"), {})
print(f"[jataayu] {tag}/{s}: baseline ASR={b.get('attack_success_rate',-1):.2f} util_atk={b.get('utility_under_attack',-1):.2f}"
      f" -> jataayu ASR={j.get('attack_success_rate',-1):.2f} util_atk={j.get('utility_under_attack',-1):.2f}"
      f" (clean {b.get('utility_no_attack',-1):.2f}/{j.get('utility_no_attack',-1):.2f})")
PY
)
    echo "$MSG"; notify "$MSG"
  done
done

notify "[jataayu] Phase B HOSTED sweep done ($MIN_STATUS): $MODELS x $SUITES. Results: eval/results/agentdojo_<suite>_<tag>_sweep.json."
echo "==== hosted sweep complete $(date -u +%H:%M:%SZ) ===="
