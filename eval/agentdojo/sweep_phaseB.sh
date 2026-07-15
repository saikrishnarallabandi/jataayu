#!/usr/bin/env bash
# Phase B AgentDojo model sweep — qwen3.6:35b-a3b, paired baseline+jataayu.
# Resumable: skips a suite whose out-file already exists and is non-partial.
# Single request stream (dgx-pavan GB10 is shared) — suites run sequentially.
#   nohup bash eval/agentdojo/sweep_phaseB.sh > runs/agentdojo/sweep_phaseB.log 2>&1 &
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
PY="${PY:-$REPO/eval/.venv/bin/python}"
MODEL_ID="${MODEL_ID:-qwen3.6:35b-a3b}"
BASE_URL="${BASE_URL:-http://127.0.0.1:11436/v1}"
MIN_STATUS="${MIN_STATUS:-HIGH}"
ATTACK="${ATTACK:-important_instructions}"
# workspace already complete (agentdojo_workspace_qwen35b_sweep.json); redo banking clean, add travel+slack.
SUITES="${SUITES:-banking travel slack}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DISCORD_TARGET="user:100000000000000001"

cd "$REPO" || exit 1
NOTIFY_CLI="${NOTIFY_CLI:-}"   # message-gateway CLI on PATH (optional); empty = skip notifications
notify() { [ -n "$NOTIFY_CLI" ] || return 0; "$NOTIFY_CLI" message send --channel discord --target "$DISCORD_TARGET" --message "$1" 2>/dev/null || true; }

endpoint_ok() {
  curl -s --max-time 20 "$BASE_URL/chat/completions" -H 'Content-Type: application/json' \
    -d "{\"model\":\"$MODEL_ID\",\"messages\":[{\"role\":\"user\",\"content\":\"ok\"}],\"max_tokens\":4}" \
    >/dev/null 2>&1
}

notify "[jataayu] Phase B sweep started ($MODEL_ID, min-status $MIN_STATUS): suites = $SUITES, paired baseline+jataayu."

for suite in $SUITES; do
  OUT="$REPO/eval/results/agentdojo_${suite}_qwen35b_sweep.json"
  if [ -f "$OUT" ] && ! grep -q '"note".*[Pp]artial' "$OUT" 2>/dev/null; then
    echo "[skip] $suite already complete -> $OUT"
    continue
  fi
  if ! endpoint_ok; then
    echo "[warn] endpoint $BASE_URL not responding before $suite; waiting 60s"
    sleep 60
    endpoint_ok || { echo "[abort] endpoint down"; notify "[jataayu] Phase B ABORTED before $suite: endpoint $BASE_URL down."; exit 1; }
  fi
  LOGDIR="$REPO/runs/agentdojo/sweep_${STAMP}_${suite}"
  echo "==== $suite ($(date -u +%H:%M:%SZ)) ===="
  "$PY" eval/agentdojo/run_agentdojo.py \
    --model local --model-id "$MODEL_ID" --local-base-url "$BASE_URL" \
    --suite "$suite" --attack "$ATTACK" \
    --user-tasks user_task_0 user_task_1 user_task_2 user_task_3 user_task_4 \
    --injection-tasks injection_task_0 injection_task_1 injection_task_2 injection_task_3 \
    --variants baseline jataayu \
    --min-status "$MIN_STATUS" \
    --logdir "$LOGDIR" --out "$OUT"
  RC=$?
  if [ $RC -ne 0 ] || [ ! -f "$OUT" ]; then
    echo "[fail] $suite rc=$RC"
    notify "[jataayu] Phase B: $suite FAILED (rc=$RC). Continuing to next suite."
    continue
  fi
  MSG=$("$PY" - "$OUT" "$suite" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); s = sys.argv[2]
b = next((r for r in d["results"] if r["defense"]=="none"), {})
j = next((r for r in d["results"] if r["defense"]=="jataayu"), {})
print(f"[jataayu] {s}: baseline ASR={b.get('attack_success_rate',-1):.2f} util(atk)={b.get('utility_under_attack',-1):.2f}"
      f" -> jataayu ASR={j.get('attack_success_rate',-1):.2f} util(atk)={j.get('utility_under_attack',-1):.2f}"
      f" (clean util {b.get('utility_no_attack',-1):.2f}/{j.get('utility_no_attack',-1):.2f})")
PY
)
  echo "$MSG"; notify "$MSG"
done

notify "[jataayu] Phase B sweep done ($MIN_STATUS): $SUITES. Results in eval/results/agentdojo_<suite>_qwen35b_sweep.json."
echo "==== sweep complete $(date -u +%H:%M:%SZ) ===="
