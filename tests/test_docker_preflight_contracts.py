import json
from unittest.mock import patch

import httpx
import pytest

from umbrel_ro_bridge import openclaw_client


class FakeResponse:
    def __init__(self, status_code: int, chunks: list[bytes]):
        self.status_code = status_code
        self._chunks = chunks

    async def aiter_bytes(self, chunk_size=None):
        for chunk in self._chunks:
            yield chunk


class StreamContext:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, *args):
        return False


class FakeClient:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def stream(self, method, path, json=None):
        self.calls.append((method, path, json))
        if self.error:
            raise self.error
        return StreamContext(self.response)


@pytest.mark.asyncio
async def test_safe_request_streams_success_within_bridge_budget():
    payload = {"images": [{"id": "a" * 64}] * 100}
    encoded = json.dumps(payload).encode()
    client = FakeClient(FakeResponse(200, [encoded[:9000], encoded[9000:]]))

    with patch.object(openclaw_client, "_client", return_value=client):
        result = await openclaw_client._safe_request("POST", "/v1/local_images", {})

    assert result == {"ok": True, "data": payload}
    assert client.calls == [("POST", "/v1/local_images", {})]


@pytest.mark.asyncio
async def test_safe_request_rejects_success_over_bridge_budget(monkeypatch):
    monkeypatch.setattr(openclaw_client, "MAX_BODY_BYTES", 8)
    client = FakeClient(FakeResponse(200, [b'{"long":', b'"value"}']))

    with patch.object(openclaw_client, "_client", return_value=client):
        result = await openclaw_client._safe_request("POST", "/v1/test", {})

    assert result["ok"] is False
    assert result["error"] == "docker_response_too_large"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "code"),
    [(403, "image_not_allowed"), (404, "image_not_found"), (404, "container_not_found")],
)
async def test_safe_request_preserves_known_structured_proxy_errors(status, code):
    body = json.dumps({"error": {"code": code, "message": "safe message"}}).encode()
    client = FakeClient(FakeResponse(status, [body]))

    with patch.object(openclaw_client, "_client", return_value=client):
        result = await openclaw_client._safe_request("POST", "/v1/test", {})

    assert result == {
        "ok": False,
        "error": code,
        "message": "safe message",
        "status": status,
    }


@pytest.mark.asyncio
async def test_safe_request_reduces_unknown_proxy_error():
    body = json.dumps({"error": {"code": "internal_detail", "message": "do not expose"}}).encode()
    client = FakeClient(FakeResponse(500, [body]))

    with patch.object(openclaw_client, "_client", return_value=client):
        result = await openclaw_client._safe_request("POST", "/v1/test", {})

    assert result["ok"] is False
    assert result["error"] == "docker_unavailable"
    assert "do not expose" not in result["message"]


@pytest.mark.asyncio
async def test_safe_request_maps_connect_and_total_timeout():
    with patch.object(
        openclaw_client,
        "_client",
        return_value=FakeClient(error=httpx.ConnectError("offline")),
    ):
        unavailable = await openclaw_client._safe_request("POST", "/v1/test", {})

    with patch.object(
        openclaw_client,
        "_client",
        return_value=FakeClient(error=TimeoutError()),
    ):
        timed_out = await openclaw_client._safe_request("POST", "/v1/test", {})

    assert unavailable["error"] == "proxy_unavailable"
    assert timed_out["error"] == "docker_timeout"


def test_bridge_budget_exceeds_proxy_route_budget():
    assert openclaw_client.PROXY_TOTAL_TIMEOUT_SECONDS == 20.0
    assert openclaw_client.MAX_BODY_BYTES == 512 * 1024
