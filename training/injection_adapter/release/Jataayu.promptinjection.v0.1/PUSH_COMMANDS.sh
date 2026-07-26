#!/usr/bin/env bash
# Staged HuggingFace push for the Jataayu prompt-injection adapter v0.1.
# Repo: srallaba/Jataayu.promptinjection.v0.1  (model repo)
# Uploads ONLY the release files: README.md, adapter_config.json,
# adapter_model.safetensors, chat_template.jinja.
# Deliberately EXCLUDES training state (optimizer.pt, rng_state.pth,
# scheduler.pt) and the large tokenizer files (base model ships its own).
set -euo pipefail

REPO="srallaba/Jataayu.promptinjection.v0.1"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 0) confirm auth + write scope (no push)
hf auth whoami

# 1) create the model repo (idempotent)
hf repo create "$REPO" --repo-type model -y

# 2) upload only the four release artifacts
hf upload "$REPO" "$DIR/README.md"                 README.md                 --repo-type model
hf upload "$REPO" "$DIR/adapter_config.json"       adapter_config.json       --repo-type model
hf upload "$REPO" "$DIR/adapter_model.safetensors" adapter_model.safetensors --repo-type model
hf upload "$REPO" "$DIR/chat_template.jinja"       chat_template.jinja       --repo-type model

echo "Uploaded. Live at: https://huggingface.co/$REPO"
