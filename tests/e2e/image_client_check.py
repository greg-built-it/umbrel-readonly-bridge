#!/usr/bin/env python3
"""Exercise all OpenClaw client functions from the built Bridge image."""

import asyncio
import json
from typing import Any

from umbrel_ro_bridge import openclaw_client


STATUS_KEYS = {
    "container",
    "created_at",
    "docker_name",
    "image",
    "restart_count",
    "state",
}
STATE_KEYS = {
    "error",
    "exit_code",
    "finished_at",
    "health_status",
    "oom_killed",
    "running",
    "started_at",
    "status",
}
LOG_KEYS = {
    "container",
    "docker_name",
    "line_count",
    "lines",
    "size_bytes",
    "tail_requested",
    "truncated",
}
RESOURCE_KEYS = {"read_at", "containers"}
RESOURCE_CONTAINER_KEYS = {
    "container",
    "cpu_percent",
    "docker_name",
    "memory_limit_bytes",
    "memory_percent",
    "memory_usage_bytes",
    "memory_working_set_bytes",
    "memory_working_set_percent",
    "network_input_bytes",
    "network_output_bytes",
}
FORBIDDEN_KEYS = {
    "config",
    "env",
    "environment",
    "graphdriver",
    "hostconfig",
    "labels",
    "mounts",
    "networksettings",
}
FORBIDDEN_VALUES = {"hidden-env-value", "hidden-label-value", "hidden-mount-value"}


def decode(result: dict[str, Any], operation: str) -> dict[str, Any]:
    assert result.get("ok") is True, f"{operation} failed: {result}"
    data = result.get("data")
    assert isinstance(data, str), f"{operation} returned non-string data"
    parsed = json.loads(data)
    assert isinstance(parsed, dict), f"{operation} returned non-object JSON"
    return parsed


def walk(value: Any):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield str(key), nested
            yield from walk(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from walk(nested)


def assert_private_fields_absent(payload: dict[str, Any]) -> None:
    for key, _ in walk(payload):
        assert key.lower() not in FORBIDDEN_KEYS, f"forbidden key exposed: {key}"
    serialized = json.dumps(payload, sort_keys=True).lower()
    for marker in FORBIDDEN_VALUES:
        assert marker not in serialized, f"private test marker exposed: {marker}"


async def main() -> None:
    gateway_status = decode(
        await openclaw_client.container_status("gateway"), "gateway status"
    )
    app_proxy_status = decode(
        await openclaw_client.container_status("app_proxy"), "app_proxy status"
    )
    gateway_logs = decode(
        await openclaw_client.container_logs("gateway", tail=100), "gateway logs"
    )
    app_proxy_logs = decode(
        await openclaw_client.container_logs("app_proxy", tail=100),
        "app_proxy logs",
    )
    resources = decode(await openclaw_client.resource_status(), "resource status")

    assert set(gateway_status) == STATUS_KEYS
    assert set(app_proxy_status) == STATUS_KEYS
    assert set(gateway_status["state"]) == STATE_KEYS
    assert set(app_proxy_status["state"]) == STATE_KEYS
    assert gateway_status["container"] == "gateway"
    assert app_proxy_status["container"] == "app_proxy"
    assert gateway_status["state"]["running"] is True
    assert app_proxy_status["state"]["running"] is True

    assert set(gateway_logs) == LOG_KEYS
    assert set(app_proxy_logs) == LOG_KEYS
    assert gateway_logs["tail_requested"] == 100
    assert app_proxy_logs["tail_requested"] == 100
    assert any("gateway-e2e-ready" in line for line in gateway_logs["lines"])
    assert any("app-proxy-e2e-ready" in line for line in app_proxy_logs["lines"])

    assert set(resources) == RESOURCE_KEYS
    assert len(resources["containers"]) == 2
    assert {item["container"] for item in resources["containers"]} == {
        "gateway",
        "app_proxy",
    }
    for item in resources["containers"]:
        assert set(item) == RESOURCE_CONTAINER_KEYS

    for payload in (
        gateway_status,
        app_proxy_status,
        gateway_logs,
        app_proxy_logs,
        resources,
    ):
        assert_private_fields_absent(payload)

    print(
        json.dumps(
            {
                "ok": True,
                "status_calls": 2,
                "log_calls": 2,
                "resource_calls": 1,
                "gateway_log_lines": gateway_logs["line_count"],
                "app_proxy_log_lines": app_proxy_logs["line_count"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
