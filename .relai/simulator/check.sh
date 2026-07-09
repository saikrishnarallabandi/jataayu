#!/usr/bin/env bash
set -euo pipefail

# RELAI managed requirements:
# - validate the simulator-local venv, not ROOT_DIR/.venv
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SIM_DIR="$ROOT_DIR/.relai/simulator"
VENV_DIR="$SIM_DIR/.venv"

relai_simulator_python_path() {
  local venv_dir="$1"
  if [ -x "$venv_dir/bin/python" ]; then
    printf '%s\n' "$venv_dir/bin/python"
  elif [ -x "$venv_dir/Scripts/python.exe" ]; then
    printf '%s\n' "$venv_dir/Scripts/python.exe"
  else
    printf '%s\n' "$venv_dir/bin/python"
  fi
}

VENV_PYTHON="$(relai_simulator_python_path "$VENV_DIR")"

if [ ! -x "$VENV_PYTHON" ]; then
  echo "Simulator virtualenv is missing. Run .relai/simulator/install.sh" >&2
  exit 1
fi

PYTHONPATH="$SIM_DIR/src${PYTHONPATH:+:$PYTHONPATH}" \
"$VENV_PYTHON" - "$VENV_DIR" "$VENV_PYTHON" <<'PY'
import importlib
from pathlib import Path
import sys

venv_dir = Path(sys.argv[1]).resolve()
launched_executable = Path(sys.argv[2])
prefix = Path(sys.prefix).resolve()
base_prefix = Path(getattr(sys, "base_prefix", sys.prefix)).resolve()


def venv_root_for_launch_path(path: Path) -> Path:
    return path.absolute().parent.parent.resolve()


actual_launch_venv_dir = venv_root_for_launch_path(launched_executable)

if actual_launch_venv_dir != venv_dir:
    raise SystemExit(
        "Simulator Python must come from the simulator venv.\n"
        f"Expected venv dir: {venv_dir}\n"
        f"Actual executable: {sys.executable!r}\n"
        f"Actual launch path: {str(launched_executable)!r}\n"
        f"Actual launch path venv dir: {actual_launch_venv_dir}"
    )

if prefix != venv_dir:
    raise SystemExit(
        "Simulator sys.prefix must point at the simulator venv.\n"
        f"Expected venv dir: {venv_dir}\n"
        f"Actual sys.prefix: {sys.prefix!r}"
    )

if base_prefix == venv_dir:
    raise SystemExit(
        "Simulator base interpreter unexpectedly resolves to the simulator venv.\n"
        f"Expected a distinct base interpreter for venv dir: {venv_dir}\n"
        f"Actual sys.base_prefix: {getattr(sys, 'base_prefix', sys.prefix)!r}"
    )

for module_name in ["relai", "relai_simulator"]:
    importlib.import_module(module_name)
PY
