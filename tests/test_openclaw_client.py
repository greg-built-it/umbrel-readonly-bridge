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
        instance.request = AsyncMock(side_effect=Exception("connect failed"))
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
        response.raise_for_status = MagicMock()
        response.aiter_bytes = mock_aiter_bytes

        instance.request = AsyncMock(return_value=response)
        mock_client.return_value = instance
        result = await openclaw_client.container_status("gateway")
        assert result["ok"] is True


@pytest.mark.asyncio
async def test_container_logs_tail_validation_like():
    # tail validation happens in server.py; client just passes it through
    result = await openclaw_client.container_logs("gateway", tail=100)
    assert result["ok"] is False  # proxy unavailable in test env
    assert result["error"] in {"proxy_unavailable", "docker_unavailable"}
