#!/usr/bin/env bash
set -euo pipefail

# RELAI managed requirements:
# - use .relai/simulator/.venv as the simulator-local environment
# - do not require ROOT_DIR/.venv
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SIM_DIR="$ROOT_DIR/.relai/simulator"
VENV_DIR="$SIM_DIR/.venv"
export UV_CACHE_DIR="$SIM_DIR/.uv-cache"

require_command() {
  local command_name="$1"
  local message="${2:-$command_name is required but not installed.}"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "$message" >&2
    exit 1
  fi
}

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

require_relai_simulator_python() {
  local python_bin="$1"
  if [ ! -x "$python_bin" ]; then
    echo "RELAI simulator Python was not found at $python_bin." >&2
    exit 1
  fi
  "$python_bin" - <<'PY'
import platform
import sys

if sys.version_info < (3, 11):
    raise SystemExit(
        "RELAI simulator requires Python 3.11 or newer, but the simulator venv is "
        f"running Python {platform.python_version()} at {sys.executable}. "
        "Install uv or make a separate Python 3.11+ interpreter available, then rerun relai init."
    )
PY
}


# BEGIN RELAI CLI SDK INSTALL - do not edit
read_relai_config_value() {
  if [ -z "${RELAI_CONFIG_PYTHON:-}" ] || [ ! -x "$RELAI_CONFIG_PYTHON" ]; then
    echo "RELAI simulator config reader requires a validated simulator venv Python." >&2
    exit 1
  fi
  "$RELAI_CONFIG_PYTHON" - "$ROOT_DIR/.relai/config.toml" "$1" "$2" <<'PY'
import sys
import tomllib

path, section, key = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "rb") as file:
    config = tomllib.load(file)
value = config.get(section, {}).get(key)
if not value:
    raise SystemExit(f"missing {section}.{key} in {path}")
print(value)
PY
}

read_optional_relai_config_value() {
  if [ -z "${RELAI_CONFIG_PYTHON:-}" ] || [ ! -x "$RELAI_CONFIG_PYTHON" ]; then
    echo "RELAI simulator config reader requires a validated simulator venv Python." >&2
    exit 1
  fi
  "$RELAI_CONFIG_PYTHON" - "$ROOT_DIR/.relai/config.toml" "$1" "$2" <<'PY'
import sys
import tomllib

path, section, key = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "rb") as file:
    config = tomllib.load(file)
value = config.get(section, {}).get(key, "")
print(value or "")
PY
}

resolve_relai_sdk_spec() {
  RELAI_SDK_LOCAL_PATH="${RELAI_SDK_LOCAL_PATH:-$(read_optional_relai_config_value local relai_sdk_path)}"
  if [ -n "$RELAI_SDK_LOCAL_PATH" ]; then
    if [ -f "$RELAI_SDK_LOCAL_PATH/package.json" ] && [ ! -f "$RELAI_SDK_LOCAL_PATH/pyproject.toml" ]; then
      :
    elif [ ! -f "$RELAI_SDK_LOCAL_PATH/pyproject.toml" ]; then
      echo "local RELAI Python SDK pyproject.toml not found at $RELAI_SDK_LOCAL_PATH/pyproject.toml" >&2
      exit 1
    elif [ ! -f "$RELAI_SDK_LOCAL_PATH/src/relai/__init__.py" ]; then
      echo "local RELAI Python SDK package not found at $RELAI_SDK_LOCAL_PATH/src/relai" >&2
      exit 1
    else
      echo "$RELAI_SDK_LOCAL_PATH"
      return
    fi
  fi

  local metadata
  local sdk_version
  metadata="$(resolve_relai_sdk_metadata)"
  sdk_version="$(resolve_relai_sdk_version "$metadata")"
  if [ -n "$sdk_version" ]; then
    echo "relai==$sdk_version"
    return
  fi

  local download_url
  download_url="$(printf '%s' "$metadata" | jq -r '.download_url // empty')"
  if [ -n "$download_url" ]; then
    printf '%s\n' "$download_url"
    return
  fi

  echo "RELAI SDK metadata must include version or download_url." >&2
  exit 1
}

resolve_relai_sdk_metadata() {
  require_command curl
  require_command jq
  RELAI_API_URL="$(read_relai_config_value api url)"
  RELAI_API_KEY="$(read_relai_config_value api key)"
  RELAI_CLI_VERSION="0.1.29"
  curl -fsSL \
    -H "Authorization: Token ${RELAI_API_KEY}" \
    -H "X-RELAI-CLI-Version: ${RELAI_CLI_VERSION}" \
    "${RELAI_API_URL%/}/sdk-url?cli_version=${RELAI_CLI_VERSION}"
}

resolve_relai_sdk_version() {
  local metadata="${1:-}"
  local version
  if [ -z "$metadata" ]; then
    metadata="$(resolve_relai_sdk_metadata)"
  fi
  version="$(printf '%s' "$metadata" | jq -r '.version // empty')"
  printf '%s\n' "$version"
}

resolve_relai_sdk_index_url() {
  RELAI_API_URL="$(read_relai_config_value api url)"
  printf '%s/sdk/simple/\n' "${RELAI_API_URL%/}"
}

relai_sdk_spec_is_local() {
  [ -n "${RELAI_SDK_LOCAL_PATH:-$(read_optional_relai_config_value local relai_sdk_path)}" ]
}

current_relai_sdk_version() {
  local python_bin="$1"
  if [ ! -x "$python_bin" ]; then
    return
  fi
  "$python_bin" - <<'PY'
from importlib.metadata import PackageNotFoundError, version

try:
    print(version("relai"))
except PackageNotFoundError:
    pass
PY
}

configure_relai_sdk_index_auth() {
  RELAI_API_KEY="$(read_relai_config_value api key)"
  export UV_INDEX_RELAI_USERNAME="${UV_INDEX_RELAI_USERNAME:-__token__}"
  export UV_INDEX_RELAI_PASSWORD="$RELAI_API_KEY"
  export POETRY_HTTP_BASIC_RELAI_USERNAME="${POETRY_HTTP_BASIC_RELAI_USERNAME:-__token__}"
  export POETRY_HTTP_BASIC_RELAI_PASSWORD="${POETRY_HTTP_BASIC_RELAI_PASSWORD:-$RELAI_API_KEY}"
}

resolve_relai_typescript_sdk_registry_url() {
  RELAI_API_URL="$(read_relai_config_value api url)"
  printf '%s/npm/\n' "${RELAI_API_URL%/}"
}

relai_typescript_sdk_local_path_configured() {
  [ -n "${RELAI_SDK_LOCAL_PATH:-$(read_optional_relai_config_value local relai_sdk_path)}" ]
}

resolve_relai_typescript_sdk_local_path() {
  RELAI_SDK_LOCAL_PATH="${RELAI_SDK_LOCAL_PATH:-$(read_optional_relai_config_value local relai_sdk_path)}"
  if [ -z "$RELAI_SDK_LOCAL_PATH" ]; then
    return 1
  fi
  if [ ! -f "$RELAI_SDK_LOCAL_PATH/package.json" ]; then
    echo "local RELAI TypeScript SDK package.json not found at $RELAI_SDK_LOCAL_PATH/package.json" >&2
    exit 1
  fi
  "$RELAI_CONFIG_PYTHON" - "$RELAI_SDK_LOCAL_PATH/package.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as file:
    package = json.load(file)
if package.get("name") != "@relai-ai/relai":
    raise SystemExit(f"local RELAI TypeScript SDK package.json name must be @relai-ai/relai: {path}")
PY
  ensure_relai_typescript_sdk_local_build "$RELAI_SDK_LOCAL_PATH"
  printf '%s\n' "$RELAI_SDK_LOCAL_PATH"
}

ensure_relai_typescript_sdk_local_build() {
  local sdk_dir="$1"
  require_command npm
  (
    cd "$sdk_dir"
    if [ ! -d "node_modules" ]; then
      if [ -f "package-lock.json" ]; then
        npm ci
      else
        npm install
      fi
    fi
    if [ ! -f "dist/index.js" ]; then
      npm run build
    fi
  )
  if [ ! -f "$sdk_dir/dist/index.js" ]; then
    echo "local RELAI TypeScript SDK build output not found at $sdk_dir/dist/index.js" >&2
    exit 1
  fi
}

resolve_existing_relai_typescript_sdk_file_dependency() {
  local project_dir="${1:-$ROOT_DIR}"
  if [ ! -f "$project_dir/package.json" ]; then
    return 1
  fi
  "$RELAI_CONFIG_PYTHON" - "$project_dir/package.json" "$project_dir" <<'PY'
import json
import os
import sys

package_json_path = sys.argv[1]
project_dir = sys.argv[2]
with open(package_json_path, "r", encoding="utf-8") as file:
    package = json.load(file)
spec = (package.get("dependencies") or {}).get("@relai-ai/relai") or (
    package.get("devDependencies") or {}
).get("@relai-ai/relai")
if not spec or not spec.startswith("file:"):
    raise SystemExit(1)
sdk_dir = os.path.abspath(os.path.join(project_dir, spec[len("file:") :]))
sdk_package_json_path = os.path.join(sdk_dir, "package.json")
if not os.path.exists(sdk_package_json_path):
    raise SystemExit(1)
with open(sdk_package_json_path, "r", encoding="utf-8") as file:
    sdk_package = json.load(file)
if sdk_package.get("name") != "@relai-ai/relai":
    raise SystemExit(1)
print(sdk_dir)
PY
}

relai_npm_auth_scope() {
  local registry_url="${1%/}/"
  case "$registry_url" in
    https://*) registry_url="${registry_url#https://}" ;;
    http://*) registry_url="${registry_url#http://}" ;;
  esac
  printf '//%s\n' "$registry_url"
}

configure_relai_typescript_sdk_registry_auth() {
  local project_dir="${1:-$ROOT_DIR}"
  local npmrc_path="$project_dir/.npmrc"
  local registry_url
  local auth_scope
  local tmp_path
  local start_marker="# BEGIN RELAI TYPESCRIPT SDK REGISTRY - managed by relai"
  local end_marker="# END RELAI TYPESCRIPT SDK REGISTRY - managed by relai"
  RELAI_API_KEY="$(read_relai_config_value api key)"
  registry_url="$(resolve_relai_typescript_sdk_registry_url)"
  auth_scope="$(relai_npm_auth_scope "$registry_url")"
  tmp_path="${npmrc_path}.relai-tmp"

  if [ -f "$npmrc_path" ]; then
    awk -v start="$start_marker" -v end="$end_marker" '
      $0 == start { skip = 1; next }
      $0 == end { skip = 0; next }
      skip != 1 { print }
    ' "$npmrc_path" > "$tmp_path"
  else
    : > "$tmp_path"
  fi

  {
    printf '%s\n' "$start_marker"
    printf '@relai-ai:registry=%s\n' "$registry_url"
    printf '%s:_authToken=%s\n' "$auth_scope" "$RELAI_API_KEY"
    printf '%s:always-auth=true\n' "$auth_scope"
    printf '%s\n' "$end_marker"
  } >> "$tmp_path"
  mv "$tmp_path" "$npmrc_path"
}

detect_relai_typescript_package_manager() {
  local project_dir="${1:-$ROOT_DIR}"
  if [ -f "$project_dir/bun.lockb" ] || [ -f "$project_dir/bun.lock" ]; then
    printf 'bun\n'
  elif [ -f "$project_dir/pnpm-lock.yaml" ]; then
    printf 'pnpm\n'
  elif [ -f "$project_dir/yarn.lock" ]; then
    printf 'yarn\n'
  else
    printf 'npm\n'
  fi
}

install_relai_typescript_sdk() {
  local project_dir="${1:-$ROOT_DIR}"
  local manager
  local sdk_spec="@relai-ai/relai"
  local existing_file_sdk_path
  if [ ! -f "$project_dir/package.json" ]; then
    echo "RELAI TypeScript SDK install requires package.json in $project_dir." >&2
    exit 1
  fi
  if relai_typescript_sdk_local_path_configured; then
    sdk_spec="$(resolve_relai_typescript_sdk_local_path)"
  elif existing_file_sdk_path="$(resolve_existing_relai_typescript_sdk_file_dependency "$project_dir")"; then
    ensure_relai_typescript_sdk_local_build "$existing_file_sdk_path"
    sdk_spec="$existing_file_sdk_path"
  else
    configure_relai_typescript_sdk_registry_auth "$project_dir"
  fi
  manager="${RELAI_TYPESCRIPT_PACKAGE_MANAGER:-$(detect_relai_typescript_package_manager "$project_dir")}"
  (
    cd "$project_dir"
    case "$manager" in
      bun)
        require_command bun
        bun add "$sdk_spec"
        ;;
      pnpm)
        require_command pnpm
        pnpm add "$sdk_spec"
        ;;
      yarn)
        require_command yarn
        yarn add "$sdk_spec"
        ;;
      npm)
        require_command npm
        npm install --save "$sdk_spec"
        ;;
      *)
        echo "Unsupported TypeScript package manager '$manager'. Expected npm, pnpm, yarn, or bun." >&2
        exit 1
        ;;
    esac
  )
}

relai_sdk_index_url_with_credentials() {
  local url="$1"
  local key="$2"
  case "$url" in
    https://*) printf 'https://__token__:%s@%s\n' "$key" "${url#https://}" ;;
    http://*) printf 'http://__token__:%s@%s\n' "$key" "${url#http://}" ;;
    *) printf '%s\n' "$url" ;;
  esac
}

mark_relai_sdk_uv_index_explicit() {
  local python_bin="$1"
  "$python_bin" - "$SIM_DIR/pyproject.toml" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
lines = path.read_text().splitlines(keepends=True)
index = 0
while index < len(lines):
    if lines[index].strip() != "[[tool.uv.index]]":
        index += 1
        continue
    block_start = index
    index += 1
    while index < len(lines) and not lines[index].lstrip().startswith("["):
        index += 1
    block_end = index
    block = lines[block_start:block_end]
    if not any(line.strip() in {'name = "relai"', "name = 'relai'"} for line in block):
        continue
    for line_index in range(block_start + 1, block_end):
        if lines[line_index].strip().startswith("explicit"):
            lines[line_index] = "explicit = true\n"
            path.write_text("".join(lines))
            raise SystemExit(0)
    insert_at = block_end
    while insert_at > block_start + 1 and lines[insert_at - 1].strip() == "":
        insert_at -= 1
    lines.insert(insert_at, "explicit = true\n")
    path.write_text("".join(lines))
    raise SystemExit(0)

raise SystemExit("RELAI uv index not found in pyproject.toml")
PY
}

install_relai_sdk_with_uv_index() {
  local python_bin="$1"
  local sdk_version="$2"
  local sdk_index_url="$3"
  local installed_version
  uv add --frozen "relai==$sdk_version" --index "relai=$sdk_index_url"
  mark_relai_sdk_uv_index_explicit "$python_bin"
  installed_version="$(current_relai_sdk_version "$python_bin")"
  if [ "$installed_version" = "$sdk_version" ]; then
    echo "RELAI SDK $sdk_version is already installed; skipping SDK install."
    return
  fi
  uv sync --python "$python_bin" --no-install-project
}

install_relai_sdk() {
  local python_bin="$1"
  local manager="$2"
  local sdk_spec
  local sdk_version
  local installed_version
  local sdk_index_url
  sdk_spec="$(resolve_relai_sdk_spec)"
  if relai_sdk_spec_is_local; then
    if [ "$manager" = "uv" ]; then
      uv add "$sdk_spec"
    else
      "$python_bin" -m pip install "$sdk_spec"
    fi
    return
  fi

  case "$sdk_spec" in
    http://*|https://*)
      if [ "$manager" = "uv" ]; then
        uv pip install --python "$python_bin" "$sdk_spec"
      else
        "$python_bin" -m pip install "$sdk_spec"
      fi
      return
      ;;
  esac

  sdk_version="${sdk_spec#relai==}"
  configure_relai_sdk_index_auth
  sdk_index_url="$(resolve_relai_sdk_index_url)"
  if [ "$manager" = "uv" ]; then
    install_relai_sdk_with_uv_index "$python_bin" "$sdk_version" "$sdk_index_url"
  elif [ "$manager" = "poetry" ]; then
    installed_version="$(current_relai_sdk_version "$python_bin")"
    if [ "$installed_version" = "$sdk_version" ]; then
      echo "RELAI SDK $sdk_version is already installed; skipping SDK install."
      return
    fi
    poetry source remove relai >/dev/null 2>&1 || true
    poetry source add --priority explicit relai "$sdk_index_url"
    poetry add "relai==$sdk_version" --source relai
  else
    installed_version="$(current_relai_sdk_version "$python_bin")"
    if [ "$installed_version" = "$sdk_version" ]; then
      echo "RELAI SDK $sdk_version is already installed; skipping SDK install."
      return
    fi
    "$python_bin" -m pip install --extra-index-url "$(relai_sdk_index_url_with_credentials "$sdk_index_url" "$RELAI_API_KEY")" "relai==$sdk_version"
  fi
}

# END RELAI CLI SDK INSTALL

cd "$SIM_DIR"

require_command uv

VENV_PYTHON="$(relai_simulator_python_path "$VENV_DIR")"

if [ -x "$VENV_PYTHON" ] && ! "$VENV_PYTHON" - <<'PY' >/dev/null 2>&1
import sys
PY
then
  rm -rf "$VENV_DIR"
  VENV_PYTHON="$(relai_simulator_python_path "$VENV_DIR")"
fi

if [ ! -x "$VENV_PYTHON" ]; then
  uv venv "$VENV_DIR"
  VENV_PYTHON="$(relai_simulator_python_path "$VENV_DIR")"
fi
require_relai_simulator_python "$VENV_PYTHON"
export RELAI_CONFIG_PYTHON="$VENV_PYTHON"

# BEGIN RELAI CLI SDK INSTALL - do not edit
install_relai_sdk "$VENV_PYTHON" uv
# END RELAI CLI SDK INSTALL
# BEGIN PROJECT DEPENDENCY INSTALL
uv pip install --python "$VENV_PYTHON" -e "$ROOT_DIR[relai]"
# END PROJECT DEPENDENCY INSTALL
uv pip install --python "$VENV_PYTHON" -e "$SIM_DIR"
