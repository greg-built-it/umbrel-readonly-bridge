#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 BRIDGE_CONTEXT PROXY_CONTEXT" >&2
  exit 64
fi

BRIDGE_CONTEXT="$(cd "$1" && pwd)"
PROXY_CONTEXT="$(cd "$2" && pwd)"
RUNNER="${BRIDGE_CONTEXT}/tests/e2e/run_image_e2e.sh"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

copy_context() {
  local source="$1"
  local target="$2"
  mkdir -p "$target"
  tar \
    --exclude=.git \
    --exclude=.venv \
    --exclude=.pytest_cache \
    --exclude='__pycache__' \
    -C "$source" -cf - . | tar -C "$target" -xf -
}

expect_e2e_failure() {
  local label="$1"
  local bridge="$2"
  local proxy="$3"
  local log_file="${TMP_ROOT}/${label}.log"

  set +e
  CI=true "$RUNNER" "$bridge" "$proxy" "negative-${label}" >"$log_file" 2>&1
  local rc=$?
  set -e

  if [[ $rc -eq 0 ]]; then
    echo "negative control unexpectedly passed: ${label}" >&2
    return 1
  fi
  echo "NEGATIVE_CONTROL_OK label=${label} exit=${rc}"
}

copy_context "$BRIDGE_CONTEXT" "${TMP_ROOT}/bridge-missing-main"
copy_context "$PROXY_CONTEXT" "${TMP_ROOT}/proxy-missing-main"
rm "${TMP_ROOT}/proxy-missing-main/src/openclaw_docker_proxy/__main__.py"
expect_e2e_failure \
  "missing-main" \
  "${TMP_ROOT}/bridge-missing-main" \
  "${TMP_ROOT}/proxy-missing-main"

copy_context "$BRIDGE_CONTEXT" "${TMP_ROOT}/bridge-wrong-method"
copy_context "$PROXY_CONTEXT" "${TMP_ROOT}/proxy-wrong-method"
python3 - "${TMP_ROOT}/bridge-wrong-method/src/umbrel_ro_bridge/openclaw_client.py" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
old = '"POST", "/v1/container_status", {"container": alias}'
new = '"GET", "/v1/container_status", {"container": alias}'
assert text.count(old) == 1, "expected status request pattern exactly once"
path.write_text(text.replace(old, new))
PY
expect_e2e_failure \
  "wrong-method" \
  "${TMP_ROOT}/bridge-wrong-method" \
  "${TMP_ROOT}/proxy-wrong-method"

copy_context "$BRIDGE_CONTEXT" "${TMP_ROOT}/bridge-wrong-route"
copy_context "$PROXY_CONTEXT" "${TMP_ROOT}/proxy-wrong-route"
python3 - "${TMP_ROOT}/bridge-wrong-route/src/umbrel_ro_bridge/openclaw_client.py" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
old = '"POST", "/v1/logs", {"container": alias, "tail": tail}'
new = '"POST", "/v1/container_logs", {"container": alias, "tail": tail}'
assert text.count(old) == 1, "expected logs request pattern exactly once"
path.write_text(text.replace(old, new))
PY
expect_e2e_failure \
  "wrong-route" \
  "${TMP_ROOT}/bridge-wrong-route" \
  "${TMP_ROOT}/proxy-wrong-route"

echo "NEGATIVE_CONTROLS_RESULT=pass"
