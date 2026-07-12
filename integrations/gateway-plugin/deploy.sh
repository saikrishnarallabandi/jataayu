#!/usr/bin/env bash
# Deploy the Jataayu gateway plugin -- index.js, the manifest, tests, package metadata, AND modules/.
# Use THIS -- never a bare `cp` in one direction.
#
# WHY THE WHOLE DIRECTORY:
# The guard modules (group-guard, group-capture, dm-guard) used to live as SIBLING plugin dirs
# under ~/.gateway/plugins/ and were required across directories. They existed NOWHERE in this
# repo, and this script only ever copied index.js -- so a clean redeploy or a fresh machine
# would have silently lost the group-pin security gate, the outbound guard, and the group
# capture. They are now modules INSIDE this plugin (modules/<name>/index.js), required as
# ./modules/<name>/index.js. One plugin, one deploy unit, tests in the repo.
#
# WHY THEY ARE ACTIVATED FROM jataayu RATHER THAN REGISTERED AS THEIR OWN PLUGINS:
# the gateway will NOT load a hooks-only plugin -- it registers no tools, so it never lands in
# the loaded set (this is what produced "plugin not found: dm-guard" on every boot). Jataayu is
# a real registered plugin and already owns message_sending, so it is the coherent host. Each
# module is wrapped so a fault in it can never take Jataayu -- or comms -- down.
#
# WHY THE CLOBBER GUARD:
# the deployed copy drifted AHEAD of this repo three separate times on 2026-07-11
# (decline-on-block, the dm-guard wiring, the group-guard/group-capture wiring). Each time it
# was one careless `cp` away from being reverted with no error and no log line.
#
# ./deploy.sh --verify  -- check only: is the live plugin the plugin this repo says it is?
# A copy nobody checks is a copy that lies. project_ascent/plugins/verify.sh deliberately does NOT
# cover jataayu (it lives here, and duplicating it would create the second source of truth that
# script exists to prevent) -- it says "verify it there", and until now there was no there. This is
# it. project_ascent/scripts/health.py calls this every 30 min, so drift has a 30-minute lifetime.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
DST="$HOME/.gateway/plugins/jataayu"

if [[ "${1:-}" == "--verify" ]]; then
  drift=0
  if [[ ! -d "$DST" ]]; then
    echo "MISSING LIVE  jataayu -- not deployed to $DST"
    exit 1
  fi
  check() {  # repo file -> live file
    local rel="$1"
    if [[ ! -f "$DST/$rel" ]]; then echo "MISSING LIVE  jataayu/$rel"; drift=1; return; fi
    if ! diff -q "$SRC/$rel" "$DST/$rel" >/dev/null 2>&1; then
      echo "DRIFT         jataayu/$rel -- live differs from repo"; drift=1
    fi
  }
  check index.js
  [[ -f "$SRC/gateway.plugin.json" ]] && check gateway.plugin.json
  [[ -f "$SRC/package.json" ]] && check package.json
  for f in "$SRC"/modules/*/index.js; do
    check "modules/$(basename "$(dirname "$f")")/index.js"
  done
  if [[ "$drift" -eq 0 ]]; then
    echo "clean -- the live jataayu plugin matches this repo."
    exit 0
  fi
  echo
  echo "JATAAYU PLUGIN DRIFT. The live guard is not what this repo says it is."
  echo "  repo -> live:  $SRC/deploy.sh"
  exit 1
fi

if [[ -f "$DST/index.js" ]] && ! diff -q "$SRC/index.js" "$DST/index.js" >/dev/null 2>&1; then
  if [[ "$DST/index.js" -nt "$SRC/index.js" ]]; then
    echo "REFUSING: the DEPLOYED index.js is NEWER than this repo copy."
    echo "It probably carries an uncommitted fix. Reconcile first:"
    echo "  diff $SRC/index.js $DST/index.js"
    echo "  cp $DST/index.js $SRC/index.js && git -C $SRC commit -am 'sync deployed'"
    exit 1
  fi
fi

# Nothing ships unless the guards' own tests pass.
for m in group-guard dm-guard; do
  if [[ -f "$SRC/modules/$m/test.js" ]]; then
    printf 'testing %-14s' "$m"
    (cd "$SRC/modules/$m" && node test.js >/dev/null 2>&1) \
      && echo "ok" \
      || { echo "FAILED -- not deploying"; exit 1; }
  fi
done
if [[ -f "$SRC/outbound-recover.test.js" ]]; then
  printf 'testing %-14s' "outbound-recover"
  (cd "$SRC" && node outbound-recover.test.js >/dev/null 2>&1) \
    && echo "ok" \
    || { echo "FAILED -- not deploying"; exit 1; }
fi
node --check "$SRC/index.js"
for f in "$SRC"/modules/*/index.js; do node --check "$f"; done
echo "syntax ok"

mkdir -p "$DST"
[[ -f "$DST/index.js" ]] && cp "$DST/index.js" "$DST/index.js.bak-$(date -u +%Y%m%dT%H%M%SZ)"
cp "$SRC/index.js" "$DST/index.js"
[[ -f "$SRC/gateway.plugin.json" ]] && cp "$SRC/gateway.plugin.json" "$DST/gateway.plugin.json"
[[ -f "$SRC/package.json" ]] && cp "$SRC/package.json" "$DST/package.json"
[[ -f "$SRC/outbound-recover.test.js" ]] && cp "$SRC/outbound-recover.test.js" "$DST/outbound-recover.test.js"
rm -rf "$DST/modules"
cp -r "$SRC/modules" "$DST/modules"

echo "deployed -> $DST (index.js + manifest + package/test + $(ls "$DST/modules" | wc -l) modules)"
echo
echo "now:  gateway gateway restart"
echo "then confirm all four hooks are live:"
echo "  journalctl --user -u gateway-gateway -n 300 | grep -E 'jataayu|group-guard|group-capture|dm-guard'"
