import asyncio
import threading
import time

import httpx
import pytest
from httpx_sse import aconnect_sse
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

from umbrel_ro_bridge import server as server_module
from umbrel_ro_bridge.server import build_starlette_app

TEST_TOKEN = "test-token-for-unit-tests-only"


@pytest.fixture
def base_url(tmp_path):
    """Startet den Server einmalig auf einem freien Port."""
    import uvicorn

    token_file = tmp_path / "bridge-token"
    token_file.write_text(TEST_TOKEN)
    server_module.TOKEN_FILE = token_file

    app = build_starlette_app(token=TEST_TOKEN)

    host = "127.0.0.1"
    port = 18080

    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    uvicorn_server = uvicorn.Server(config)

    thread = threading.Thread(target=uvicorn_server.run, daemon=True)
    thread.start()

    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with httpx.Client() as client:
                r = client.get(f"http://{host}:{port}/health")
                if r.status_code == 200:
                    break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError("Server did not start")

    yield f"http://{host}:{port}"

    uvicorn_server.should_exit = True
    thread.join(timeout=2)


async def test_health_anonymous(base_url):
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{base_url}/health")
        assert response.status_code == 200
        assert response.text == "ok"


async def test_sse_missing_token(base_url):
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{base_url}/sse")
        assert response.status_code == 401


async def test_sse_invalid_token(base_url):
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{base_url}/sse", headers={"Authorization": "Bearer wrong"}
        )
        assert response.status_code == 401


async def test_sse_valid_opens_endpoint(base_url):
    headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
    events = []
    async with httpx.AsyncClient() as client:
        async with aconnect_sse(client, "GET", f"{base_url}/sse", headers=headers) as event_source:
            assert event_source.response.status_code == 200
            async for sse in event_source.aiter_sse():
                events.append(sse.event)
                if sse.event == "endpoint":
                    break
    assert "endpoint" in events


async def test_messages_requires_auth(base_url):
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{base_url}/messages/", json={})
        assert response.status_code == 401


async def test_mcp_client_lists_25_tools(base_url):
    headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
    async with sse_client(
        f"{base_url}/sse", headers=headers
    ) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [tool.name for tool in tools.tools]
            assert len(names) == 25
            assert "list_directory" in names
            assert "read_text" in names
            assert "mount_inventory" in names
            assert "archive_inspect" in names
            assert "openclaw_container_inspect" in names
