"""OpenClaw Docker-Proxy Client für die Umbrel Read-Only Bridge.

Kommuniziert über einen Unix-Socket mit dem minimalen Docker-Proxy,
der ausschließlich die beiden OpenClaw-Container "openclaw_gateway_1"
und "openclaw_app_proxy_1" exponiert.

Alle Antworten werden erneut maskiert, bevor sie an Hermes weitergegeben
werden. Docker-Rohantworten, Stacktraces oder unerwartete Felder werden
niemals durchgereicht.
"""

import asyncio
import json
import os
from typing import Any

import httpx

from umbrel_ro_bridge.secrets_filter import mask_secrets


PROXY_SOCKET = os.environ.get("PROXY_SOCKET", "/run/proxy/docker-proxy.sock")
CONTAINER_ALIASES = {"gateway": "openclaw_gateway_1", "app_proxy": "openclaw_app_proxy_1"}

MAX_BODY_BYTES = 8 * 1024  # 8 KiB für eingehende Proxy-Antworten

# Stable error codes exposed to Hermes
ERROR_CODES: dict[str, dict[str, Any]] = {
    "container_not_found": {"error": "container_not_found", "message": "Container alias not recognized."},
    "proxy_unavailable": {"error": "proxy_unavailable", "message": "Docker proxy is not reachable."},
    "docker_timeout": {"error": "docker_timeout", "message": "Docker proxy request timed out."},
    "docker_unavailable": {"error": "docker_unavailable", "message": "Docker daemon reported an error."},
    "docker_response_too_large": {"error": "docker_response_too_large", "message": "Docker response exceeded size limit."},
    "invalid_docker_response": {"error": "invalid_docker_response", "message": "Docker response could not be parsed."},
}


def _resolve_alias(alias: str) -> str | None:
    return CONTAINER_ALIASES.get(alias)


def _transport() -> httpx.AsyncHTTPTransport:
    return httpx.AsyncHTTPTransport(uds=PROXY_SOCKET)


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=_transport(),
        base_url="http://proxy",
        timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
    )


async def _safe_request(method: str, path: str) -> dict[str, Any]:
    async with _client() as client:
        try:
            async with asyncio.timeout(15):
                response = await client.request(method, path)
                response.raise_for_status()
                chunks = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=8192):
                    if len(chunks) + len(chunk) > MAX_BODY_BYTES:
                        return {"ok": False, **ERROR_CODES["docker_response_too_large"]}
                    chunks.extend(chunk)
                data = json.loads(chunks.decode("utf-8"))
                return {"ok": True, "data": data}
        except httpx.ConnectError:
            return {"ok": False, **ERROR_CODES["proxy_unavailable"]}
        except httpx.TimeoutException:
            return {"ok": False, **ERROR_CODES["docker_timeout"]}
        except httpx.HTTPStatusError as e:
            return {"ok": False, **ERROR_CODES["docker_unavailable"], "status": e.response.status_code}
        except json.JSONDecodeError:
            return {"ok": False, **ERROR_CODES["invalid_docker_response"]}
        except Exception:
            return {"ok": False, **ERROR_CODES["docker_unavailable"]}


async def container_status(alias: str) -> dict[str, Any]:
    container = _resolve_alias(alias)
    if container is None:
        return {"ok": False, **ERROR_CODES["container_not_found"]}
    result = await _safe_request("GET", f"/v1/container_status/{alias}")
    if not result["ok"]:
        return result
    return {"ok": True, "data": mask_secrets(json.dumps(result["data"]))}


async def container_logs(alias: str, tail: int = 100) -> dict[str, Any]:
    container = _resolve_alias(alias)
    if container is None:
        return {"ok": False, **ERROR_CODES["container_not_found"]}
    result = await _safe_request("GET", f"/v1/container_logs/{alias}?tail={tail}")
    if not result["ok"]:
        return result
    return {"ok": True, "data": mask_secrets(json.dumps(result["data"]))}


async def resource_status() -> dict[str, Any]:
    result = await _safe_request("GET", "/v1/resource_status")
    if not result["ok"]:
        return result
    return {"ok": True, "data": mask_secrets(json.dumps(result["data"]))}
