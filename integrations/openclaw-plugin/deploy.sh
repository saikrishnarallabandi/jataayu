#!/usr/bin/env bash
# Deploy this plugin to the live gateway. Use THIS -- never a bare `cp` in one direction.
#
# Why: the deployed copy at ~/.openclaw/plugins/jataayu/index.js has twice drifted AHEAD of
# this repo (decline-on-block + LLM rewrite on 2026-07-11 12:43; the dm-guard activate() call
# later the same day). A well-meaning re-deploy from the repo silently un-wires dm-guard --
# no error, the outbound guard just stops deduping. This script refuses to clobber a newer
# deployed copy instead of overwriting it blind.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)/index.js"
DST="$HOME/.openclaw/plugins/jataayu/index.js"

if [[ -f "$DST" ]] && ! diff -q "$SRC" "$DST" >/dev/null; then
  if [[ "$DST" -nt "$SRC" ]]; then
    echo "REFUSING: the DEPLOYED copy is newer than this repo copy."
    echo "It probably carries a fix that was never committed. Reconcile first:"
    echo "  diff $SRC $DST"
    echo "  cp $DST $SRC && git -C $(dirname "$SRC")/../.. commit"
    exit 1
  fi
  cp "$DST" "$DST.bak-$(date -u +%Y%m%dT%H%M%SZ)"
fi
node --check "$SRC"
cp "$SRC" "$DST"
echo "deployed -> $DST"
echo "now: openclaw gateway restart"
