#!/usr/bin/env bash
# Unattended AgentDojo run against a local (tailnet) model + WhatsApp report.
# Designed to be nohup'd:  nohup bash eval/agentdojo/run_and_report.sh > logfile 2>&1 &
set -uo pipefail

# Derive the repo root from this script's location; override any path via env.
REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
PY="${PY:-python3}"                 # a python with the agentdojo deps installed
NOTIFY_CLI="${NOTIFY_CLI:-}"        # message-gateway CLI on PATH (optional; for notifications)
WA_TARGET="${WA_TARGET:-}"          # notification target; empty = skip notifications
OUT="${OUT:-$REPO/eval/results/agentdojo_workspace_local.json}"

MODEL_ID="${MODEL_ID:-qwen3.6:35b-a3b}"
BASE_URL="${BASE_URL:-http://127.0.0.1:11436/v1}"
SAFE_MODEL_ID="${MODEL_ID//[^A-Za-z0-9_.-]/_}"
LOGDIR="${LOGDIR:-$REPO/runs/agentdojo/${SAFE_MODEL_ID}_$(date -u +%Y%m%dT%H%M%SZ)}"

cd "$REPO" || exit 1

send() { [ -n "$WA_TARGET" ] && [ -n "$NOTIFY_CLI" ] || return 0; "$NOTIFY_CLI" message send --channel whatsapp --target "$WA_TARGET" --message "$1" 2>/dev/null; }

send "[jataayu] AgentDojo local run started on ${MODEL_ID} (workspace/important_instructions, baseline vs jataayu). Will report numbers when done."

"$PY" eval/agentdojo/run_agentdojo.py \
  --model local --model-id "$MODEL_ID" --local-base-url "$BASE_URL" \
  --suite workspace --attack important_instructions \
  --user-tasks user_task_0 user_task_1 user_task_2 user_task_3 user_task_4 \
  --injection-tasks injection_task_0 injection_task_1 injection_task_2 injection_task_3 \
  --variants baseline jataayu \
  --logdir "$LOGDIR" \
  --out "$OUT"
RC=$?

if [ $RC -ne 0 ] || [ ! -f "$OUT" ]; then
  send "[jataayu] AgentDojo local run FAILED (rc=$RC) on ${MODEL_ID}. Check logs on LOCAL_HOST. No numbers produced."
  exit 1
fi

MSG=$("$PY" - "$OUT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
lines = [f"[jataayu] AgentDojo done ({d['model']}={d.get('user_tasks','?')} tasks, {d['suite']}/{d['attack']}):"]
for r in d["results"]:
    lines.append(
        f"{r['defense']}: util(no-atk)={r['utility_no_attack']:.2f} "
        f"util(atk)={r['utility_under_attack']:.2f} ASR={r['attack_success_rate']:.2f} "
        f"(n_atk={r['n_attack_cases']})"
    )
base = next((r for r in d["results"] if r["defense"]=="none"), None)
jat  = next((r for r in d["results"] if r["defense"]=="jataayu"), None)
if base and jat:
    lines.append(f"ASR delta: {base['attack_success_rate']:.2f} -> {jat['attack_success_rate']:.2f} with jataayu.")
print("\n".join(lines))
PY
)
send "$MSG"
echo "$MSG"
