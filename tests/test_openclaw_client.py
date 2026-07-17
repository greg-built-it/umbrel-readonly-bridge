import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from umbrel_ro_bridge import openclaw_client


@pytest.mark.asyncio
async def test_resolve_alias_gateway():
    assert openclaw_client._resolve_alias("gateway") == "openclaw_gateway_1"


@pytest.mark.asyncio
async def test_resolve_alias_app_proxy():
    assert openclaw_client._resolve_alias("app_proxy") == "openclaw_app_proxy_1"


@pytest.mark.asyncio
async def test_resolve_alias_invalid():
    assert openclaw_client._resolve_alias("unknown") is None


@pytest.mark.asyncio
async def test_container_status_unknown_alias():
    result = await openclaw_client.container_status("unknown")
    assert result["ok"] is False
    assert result["error"] == "container_not_found"


@pytest.mark.asyncio
async def test_container_logs_unknown_alias():
    result = await openclaw_client.container_logs("unknown")
    assert result["ok"] is False
    assert result["error"] == "container_not_found"


@pytest.mark.asyncio
async def test_container_status_proxy_unavailable():
    with patch("umbrel_ro_bridge.openclaw_client._client") as mock_client:
        instance = AsyncMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        instance.stream = MagicMock(side_effect=Exception("connect failed"))
        mock_client.return_value = instance
        result = await openclaw_client.container_status("gateway")
        assert result["ok"] is False
        assert result["error"] == "docker_unavailable"


@pytest.mark.asyncio
async def test_container_status_success():
    async def mock_aiter_bytes(chunk_size=None):
        yield b'{"ok": true}'

    with patch("umbrel_ro_bridge.openclaw_client._client") as mock_client:
        instance = AsyncMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)

        response = MagicMock()
        response.status_code = 200
        response.aiter_bytes = mock_aiter_bytes

        stream_context = MagicMock()
        stream_context.__aenter__ = AsyncMock(return_value=response)
        stream_context.__aexit__ = AsyncMock(return_value=False)
        instance.stream = MagicMock(return_value=stream_context)
        mock_client.return_value = instance
        result = await openclaw_client.container_status("gateway")
        assert result["ok"] is True


@pytest.mark.asyncio
async def test_container_logs_tail_validation_like():
    # tail validation happens in server.py; client just passes it through
    result = await openclaw_client.container_logs("gateway", tail=100)
    assert result["ok"] is False  # proxy unavailable in test env
    assert result["error"] in {"proxy_unavailable", "docker_unavailable"}


@pytest.mark.asyncio
async def test_container_status_posts_proxy_schema():
    with patch(
        "umbrel_ro_bridge.openclaw_client._safe_request",
        new_callable=AsyncMock,
        return_value={"ok": True, "data": {"ok": True}},
    ) as request:
        result = await openclaw_client.container_status("gateway")

    assert result["ok"] is True
    request.assert_awaited_once_with(
        "POST", "/v1/container_status", {"container": "gateway"}
    )


@pytest.mark.asyncio
async def test_container_logs_posts_proxy_schema():
    with patch(
        "umbrel_ro_bridge.openclaw_client._safe_request",
        new_callable=AsyncMock,
        return_value={"ok": True, "data": {"ok": True}},
    ) as request:
        result = await openclaw_client.container_logs("app_proxy", tail=37)

    assert result["ok"] is True
    request.assert_awaited_once_with(
        "POST", "/v1/logs", {"container": "app_proxy", "tail": 37}
    )


@pytest.mark.asyncio
async def test_resource_status_posts_empty_proxy_schema():
    with patch(
        "umbrel_ro_bridge.openclaw_client._safe_request",
        new_callable=AsyncMock,
        return_value={"ok": True, "data": {"ok": True}},
    ) as request:
        result = await openclaw_client.resource_status()

    assert result["ok"] is True
    request.assert_awaited_once_with("POST", "/v1/resource_status", {})
