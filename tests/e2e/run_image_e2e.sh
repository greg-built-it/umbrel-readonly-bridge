#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 BRIDGE_CONTEXT PROXY_CONTEXT [RUN_SUFFIX]" >&2
  exit 64
fi

if [[ "${CI:-}" != "true" && "${ALLOW_DOCKER_E2E:-}" != "1" ]]; then
  echo "refusing Docker E2E outside CI; set ALLOW_DOCKER_E2E=1 only on an isolated test host" >&2
  exit 65
fi

BRIDGE_CONTEXT="$(cd "$1" && pwd)"
PROXY_CONTEXT="$(cd "$2" && pwd)"
RUN_SUFFIX="${3:-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$}"
RUN_SUFFIX="${RUN_SUFFIX//[^a-zA-Z0-9_.-]/-}"

BRIDGE_IMAGE="umbrel-readonly-bridge:e2e-${RUN_SUFFIX}"
PROXY_IMAGE="openclaw-docker-proxy:e2e-${RUN_SUFFIX}"
PROXY_CONTAINER="umbrel-ro-e2e-proxy-${RUN_SUFFIX}"
BRIDGE_CONTAINER="umbrel-ro-e2e-bridge-${RUN_SUFFIX}"
BRIDGE_SMOKE_CONTAINER="umbrel-ro-e2e-bridge-smoke-${RUN_SUFFIX}"
SOCKET_VOLUME="umbrel-ro-e2e-socket-${RUN_SUFFIX}"
DATA_VOLUME="umbrel-ro-e2e-data-${RUN_SUFFIX}"
TOKEN_VOLUME="umbrel-ro-e2e-token-${RUN_SUFFIX}"
GATEWAY_CONTAINER="openclaw_gateway_1"
APP_PROXY_CONTAINER="openclaw_app_proxy_1"
CHECK_SCRIPT="${BRIDGE_CONTEXT}/tests/e2e/image_client_check.py"

cleanup() {
  docker rm -f \
    "$BRIDGE_CONTAINER" "$BRIDGE_SMOKE_CONTAINER" "$PROXY_CONTAINER" \
    "$GATEWAY_CONTAINER" "$APP_PROXY_CONTAINER" >/dev/null 2>&1 || true
  docker volume rm -f \
    "$SOCKET_VOLUME" "$DATA_VOLUME" "$TOKEN_VOLUME" >/dev/null 2>&1 || true
  echo "E2E_CLEANUP complete suffix=${RUN_SUFFIX}"
}
trap cleanup EXIT

[[ -f "$CHECK_SCRIPT" ]] || { echo "missing E2E checker: $CHECK_SCRIPT" >&2; exit 66; }

cleanup
trap cleanup EXIT

echo "E2E_BUILD bridge=${BRIDGE_IMAGE} proxy=${PROXY_IMAGE}"
docker build --tag "$PROXY_IMAGE" "$PROXY_CONTEXT"
docker build --tag "$BRIDGE_IMAGE" "$BRIDGE_CONTEXT"

docker volume create "$SOCKET_VOLUME" >/dev/null
docker volume create "$DATA_VOLUME" >/dev/null
docker volume create "$TOKEN_VOLUME" >/dev/null
docker run --rm \
  --network none \
  --read-only \
  --mount "type=volume,src=${TOKEN_VOLUME},dst=/token" \
  alpine:3.20 \
  sh -c 'umask 077; printf "%s\n" e2e-only > /token/bridge-token'

docker run --detach \
  --name "$GATEWAY_CONTAINER" \
  --env E2E_PRIVATE_ENV=hidden-env-value \
  --label e2e.private=hidden-label-value \
  --mount "type=volume,src=${DATA_VOLUME},dst=/hidden-mount,readonly" \
  alpine:3.20 \
  sh -c 'printf "%s\n" gateway-e2e-ready; exec sleep 300' >/dev/null

docker run --detach \
  --name "$APP_PROXY_CONTAINER" \
  --env E2E_PRIVATE_ENV=hidden-env-value \
  --label e2e.private=hidden-label-value \
  --mount "type=volume,src=${DATA_VOLUME},dst=/hidden-mount,readonly" \
  alpine:3.20 \
  sh -c 'printf "%s\n" app-proxy-e2e-ready; exec sleep 300' >/dev/null

docker run --detach \
  --name "$PROXY_CONTAINER" \
  --network none \
  --read-only \
  --tmpfs /tmp:noexec,nosuid,size=10m \
  --env PROXY_SOCKET=/run/proxy/docker-proxy.sock \
  --env DOCKER_API_VERSION=v1.47 \
  --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock,readonly \
  --mount "type=volume,src=${SOCKET_VOLUME},dst=/run/proxy" \
  --health-cmd 'python -m openclaw_docker_proxy.healthcheck' \
  --health-interval 1s \
  --health-timeout 3s \
  --health-retries 30 \
  --health-start-period 1s \
  "$PROXY_IMAGE" >/dev/null

for _ in $(seq 1 60); do
  proxy_state="$(docker inspect --format '{{.State.Status}}' "$PROXY_CONTAINER" 2>/dev/null || true)"
  proxy_health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$PROXY_CONTAINER" 2>/dev/null || true)"
  if [[ "$proxy_health" == "healthy" ]]; then
    break
  fi
  if [[ "$proxy_state" == "exited" || "$proxy_state" == "dead" ]]; then
    echo "proxy exited before becoming healthy" >&2
    docker logs "$PROXY_CONTAINER" >&2 || true
    exit 1
  fi
  sleep 1
done

proxy_health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$PROXY_CONTAINER")"
[[ "$proxy_health" == "healthy" ]] || {
  echo "proxy did not become healthy: ${proxy_health}" >&2
  docker logs "$PROXY_CONTAINER" >&2 || true
  exit 1
}
docker exec "$PROXY_CONTAINER" sh -c 'test -S /run/proxy/docker-proxy.sock'

echo "E2E_BRIDGE_DEFAULT_ENTRYPOINT_START"
docker run --detach \
  --name "$BRIDGE_SMOKE_CONTAINER" \
  --network none \
  --read-only \
  --tmpfs /tmp:noexec,nosuid,size=10m \
  --mount "type=volume,src=${TOKEN_VOLUME},dst=/run/secrets,readonly" \
  "$BRIDGE_IMAGE" >/dev/null

bridge_ready=false
for _ in $(seq 1 60); do
  bridge_state="$(docker inspect --format '{{.State.Status}}' "$BRIDGE_SMOKE_CONTAINER" 2>/dev/null || true)"
  if docker exec "$BRIDGE_SMOKE_CONTAINER" python -c \
    'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=2).read() == b"ok"' \
    >/dev/null 2>&1; then
    bridge_ready=true
    break
  fi
  if [[ "$bridge_state" == "exited" || "$bridge_state" == "dead" ]]; then
    echo "bridge default entrypoint exited before becoming ready" >&2
    docker logs "$BRIDGE_SMOKE_CONTAINER" >&2 || true
    exit 1
  fi
  sleep 1
done

[[ "$bridge_ready" == "true" ]] || {
  echo "bridge default entrypoint did not become ready" >&2
  docker logs "$BRIDGE_SMOKE_CONTAINER" >&2 || true
  exit 1
}
docker stop --time 10 "$BRIDGE_SMOKE_CONTAINER" >/dev/null
[[ "$(docker inspect --format '{{.State.Status}}' "$BRIDGE_SMOKE_CONTAINER")" == "exited" ]]
docker rm "$BRIDGE_SMOKE_CONTAINER" >/dev/null
echo "E2E_BRIDGE_DEFAULT_ENTRYPOINT=pass"

docker run --detach \
  --name "$BRIDGE_CONTAINER" \
  --network none \
  --env PROXY_SOCKET=/run/proxy/docker-proxy.sock \
  --mount "type=volume,src=${SOCKET_VOLUME},dst=/run/proxy,readonly" \
  --mount "type=bind,src=${CHECK_SCRIPT},dst=/e2e/image_client_check.py,readonly" \
  --entrypoint sh \
  "$BRIDGE_IMAGE" \
  -c 'exec sleep 300' >/dev/null

echo "E2E_STACK_RUNNING"
docker ps \
  --filter "name=${GATEWAY_CONTAINER}" \
  --filter "name=${APP_PROXY_CONTAINER}" \
  --filter "name=${PROXY_CONTAINER}" \
  --filter "name=${BRIDGE_CONTAINER}" \
  --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'

docker exec "$BRIDGE_CONTAINER" python /e2e/image_client_check.py

echo "E2E_PROXY_HEALTH=${proxy_health}"
echo "E2E_SOCKET_CREATED=true"
echo "E2E_RESULT=pass"
