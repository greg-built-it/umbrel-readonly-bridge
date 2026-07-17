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

MAX_BODY_BYTES = 512 * 1024
MAX_ERROR_BODY_BYTES = 64 * 1024
PROXY_TOTAL_TIMEOUT_SECONDS = 20.0
PRESERVED_PROXY_ERROR_STATUSES = frozenset({400, 403, 404, 413, 415, 422})

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


async def _safe_request(method: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    async with _client() as client:
        try:
            async with asyncio.timeout(PROXY_TOTAL_TIMEOUT_SECONDS):
                async with client.stream(method, path, json=payload) as response:
                    limit = MAX_BODY_BYTES if response.status_code < 400 else MAX_ERROR_BODY_BYTES
                    chunks = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        if len(chunks) + len(chunk) > limit:
                            return {"ok": False, **ERROR_CODES["docker_response_too_large"]}
                        chunks.extend(chunk)
                    data = json.loads(chunks.decode("utf-8"))
                    if response.status_code < 400:
                        return {"ok": True, "data": data}
                    if response.status_code in PRESERVED_PROXY_ERROR_STATUSES and isinstance(data, dict):
                        error = data.get("error")
                        if isinstance(error, dict):
                            code = error.get("code")
                            message = error.get("message")
                            if isinstance(code, str) and isinstance(message, str):
                                return {
                                    "ok": False,
                                    "error": code,
                                    "message": message,
                                    "status": response.status_code,
                                }
                    return {"ok": False, **ERROR_CODES["docker_unavailable"]}
        except httpx.ConnectError:
            return {"ok": False, **ERROR_CODES["proxy_unavailable"]}
        except (httpx.TimeoutException, TimeoutError):
            return {"ok": False, **ERROR_CODES["docker_timeout"]}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {"ok": False, **ERROR_CODES["invalid_docker_response"]}
        except Exception:
            return {"ok": False, **ERROR_CODES["docker_unavailable"]}


async def docker_info() -> dict[str, Any]:
    result = await _safe_request("POST", "/v1/docker_info", {})
    if not result["ok"]:
        return result
    return {"ok": True, "data": result["data"]}


async def local_images() -> dict[str, Any]:
    result = await _safe_request("POST", "/v1/local_images", {})
    if not result["ok"]:
        return result
    return {"ok": True, "data": result["data"]}


async def image_config(image: str) -> dict[str, Any]:
    result = await _safe_request("POST", "/v1/image_config", {"image": image})
    if not result["ok"]:
        return result
    return {"ok": True, "data": result["data"]}


async def container_inspect(alias: str) -> dict[str, Any]:
    container = _resolve_alias(alias)
    if container is None:
        return {"ok": False, **ERROR_CODES["container_not_found"]}
    result = await _safe_request("POST", "/v1/container_inspect", {"container": alias})
    if not result["ok"]:
        return result
    return {"ok": True, "data": result["data"]}


async def container_status(alias: str) -> dict[str, Any]:
    container = _resolve_alias(alias)
    if container is None:
        return {"ok": False, **ERROR_CODES["container_not_found"]}
    result = await _safe_request(
        "POST", "/v1/container_status", {"container": alias}
    )
    if not result["ok"]:
        return result
    return {"ok": True, "data": mask_secrets(json.dumps(result["data"]))}


async def container_logs(alias: str, tail: int = 100) -> dict[str, Any]:
    container = _resolve_alias(alias)
    if container is None:
        return {"ok": False, **ERROR_CODES["container_not_found"]}
    result = await _safe_request(
        "POST", "/v1/logs", {"container": alias, "tail": tail}
    )
    if not result["ok"]:
        return result
    return {"ok": True, "data": mask_secrets(json.dumps(result["data"]))}


async def resource_status() -> dict[str, Any]:
    result = await _safe_request("POST", "/v1/resource_status", {})
    if not result["ok"]:
        return result
    return {"ok": True, "data": mask_secrets(json.dumps(result["data"]))}
