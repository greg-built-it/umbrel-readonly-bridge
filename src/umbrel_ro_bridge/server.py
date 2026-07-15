#!/usr/bin/env python3
"""
MCP-Server fuer die Umbrel Read-Only Bridge.

Liest das Token ausschliesslich aus /run/secrets/bridge-token.
Kein Env-Fallback; das Token darf nicht im Container-Image, in Logs,
docker inspect oder der Service-Umgebung erscheinen.
"""

import asyncio
import json
import os
import secrets
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import TextContent, Tool
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
import uvicorn

from umbrel_ro_bridge import fs
from umbrel_ro_bridge import openclaw_client
from umbrel_ro_bridge.secrets_filter import mask_secrets


# ---------------------------------------------------------------------------
# Token laden (nur aus Secret-Datei)
# ---------------------------------------------------------------------------

TOKEN_FILE = Path("/run/secrets/bridge-token")


def _load_token() -> str:
    try:
        return TOKEN_FILE.read_text().strip()
    except OSError as e:
        raise RuntimeError(f"Token-Datei nicht lesbar: {e}")


# Lazy initialisierung: das Token wird erst beim Server-Start gelesen,
# damit der Modul-Import auch ohne Secret-Datei funktioniert.
BRIDGE_TOKEN: str | None = None


# ---------------------------------------------------------------------------
# MCP-Server
# ---------------------------------------------------------------------------

app = Server("umbrel-ro-bridge")


def _token_path_guard(path: str) -> None:
    lowered = path.lower()
    if "/run/secrets/bridge-token" in lowered or ".bridge-token" in lowered or "bridge-token" in lowered:
        raise fs.FilesystemError("Zugriff auf Token-Quelle verweigert.")


TOOLS = [
    Tool(name="list_directory", description="Listet Eintraege eines erlaubten Verzeichnisses auf.", inputSchema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}),
    Tool(name="read_text", description="Liest eine Textdatei (max. 5 MiB).", inputSchema={"type": "object", "properties": {"path": {"type": "string"}, "limit": {"type": "integer", "maximum": 5242880}}, "required": ["path"]}),
    Tool(name="read_binary_metadata", description="Liest Metadaten und MIME-Typ einer Datei.", inputSchema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}),
    Tool(name="read_binary_chunk", description="Liest ein begrenztes Byte-Chunks aus einer Datei (max. 64 KiB).", inputSchema={"type": "object", "properties": {"path": {"type": "string"}, "offset": {"type": "integer", "minimum": 0}, "length": {"type": "integer", "minimum": 1, "maximum": 65536}}, "required": ["path", "offset", "length"]}),
    Tool(name="archive_list", description="Listet den Inhalt eines ZIP/TAR-Archivs auf.", inputSchema={"type": "object", "properties": {"path": {"type": "string"}, "max_entries": {"type": "integer", "maximum": 1000}}, "required": ["path"]}),
    Tool(name="sqlite_query", description="Fuehrt eine read-only SQLite-Abfrage aus.", inputSchema={"type": "object", "properties": {"path": {"type": "string"}, "query": {"type": "string"}, "max_rows": {"type": "integer", "maximum": 1000}}, "required": ["path", "query"]}),
    Tool(name="extract_pdf_text", description="Extrahiert Text aus einer PDF-Datei (max. 50 Seiten).", inputSchema={"type": "object", "properties": {"path": {"type": "string"}, "max_pages": {"type": "integer", "maximum": 50}}, "required": ["path"]}),
    Tool(name="sha256", description="Berechnet SHA-256 einer Datei.", inputSchema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}),
    Tool(name="find_files", description="Sucht Dateien unter einem Verzeichnis.", inputSchema={"type": "object", "properties": {"path": {"type": "string"}, "name": {"type": "string"}, "size": {"type": "string"}, "mtime_days": {"type": "integer"}, "maxdepth": {"type": "integer", "maximum": 5}}, "required": ["path"]}),
    Tool(name="grep_text", description="Sucht in einer Textdatei.", inputSchema={"type": "object", "properties": {"path": {"type": "string"}, "pattern": {"type": "string"}, "max_matches": {"type": "integer", "maximum": 1000}}, "required": ["path", "pattern"]}),
    Tool(name="mount_inventory", description="Listet Mounts unter /host/umbrel auf.", inputSchema={"type": "object", "properties": {}}),
    Tool(name="du", description="Ermittelt Groessen von Verzeichnissen.", inputSchema={"type": "object", "properties": {"path": {"type": "string"}, "maxdepth": {"type": "integer", "maximum": 5}}, "required": ["path"]}),
    Tool(name="file_type", description="Gibt Dateityp/Statistik zurueck.", inputSchema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}),
    Tool(name="openclaw_container_status", description="Zeigt Status eines OpenClaw-Containers (gateway oder app_proxy).", inputSchema={"type": "object", "properties": {"container": {"type": "string", "enum": ["gateway", "app_proxy"]}}, "required": ["container"]}),
    Tool(name="openclaw_container_logs", description="Zeigt die letzten Zeilen eines OpenClaw-Containers (gateway oder app_proxy).", inputSchema={"type": "object", "properties": {"container": {"type": "string", "enum": ["gateway", "app_proxy"]}, "tail": {"type": "integer", "minimum": 1, "maximum": 500}}, "required": ["container"]}),
    Tool(name="openclaw_resource_status", description="Zeigt Ressourcenstatus beider OpenClaw-Container.", inputSchema={"type": "object", "properties": {}}),
]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list:
    path = arguments.get("path", "")
    _token_path_guard(path)
    try:
        if name == "list_directory":
            result = fs.list_directory(path)
        elif name == "read_text":
            result = fs.read_text(path, limit=arguments.get("limit", fs.MAX_TEXT_BYTES))
        elif name == "read_binary_metadata":
            result = fs.read_binary_metadata(path)
        elif name == "read_binary_chunk":
            result = fs.read_binary_chunk(path, arguments.get("offset", 0), arguments.get("length", 4096))
        elif name == "archive_list":
            result = fs.archive_list(path, max_entries=arguments.get("max_entries", fs.MAX_ARCHIVE_ENTRIES))
        elif name == "sqlite_query":
            result = fs.sqlite_query(path, arguments["query"], max_rows=arguments.get("max_rows", fs.MAX_SQLITE_ROWS))
        elif name == "extract_pdf_text":
            result = fs.extract_pdf_text(path, max_pages=arguments.get("max_pages", 10))
        elif name == "sha256":
            result = fs.sha256(path)
        elif name == "find_files":
            result = fs.find_files(path, name=arguments.get("name"), size=arguments.get("size"), mtime_days=arguments.get("mtime_days"), maxdepth=arguments.get("maxdepth", 3))
        elif name == "grep_text":
            result = fs.grep_text(path, arguments["pattern"], max_matches=arguments.get("max_matches", fs.MAX_GREP_MATCHES))
        elif name == "mount_inventory":
            result = fs.mount_inventory()
        elif name == "du":
            result = fs.du(path, maxdepth=arguments.get("maxdepth", 2))
        elif name == "file_type":
            result = fs.file_type(path)
        elif name == "openclaw_container_status":
            result = await openclaw_client.container_status(arguments["container"])
        elif name == "openclaw_container_logs":
            tail = arguments.get("tail", 100)
            if not isinstance(tail, int) or isinstance(tail, bool) or tail < 1 or tail > 500:
                raise ValueError("tail muss eine Ganzzahl zwischen 1 und 500 sein")
            result = await openclaw_client.container_logs(arguments["container"], tail=tail)
        elif name == "openclaw_resource_status":
            result = await openclaw_client.resource_status()
        else:
            raise ValueError(f"Unbekanntes Werkzeug: {name}")
        text = json.dumps(result, ensure_ascii=False, default=str)
        text = mask_secrets(text)
        return [TextContent(type="text", text=text)]
    except Exception as e:
        return [TextContent(type="text", text=json.dumps({"error": str(e)}))]


@app.list_tools()
async def list_tools() -> list:
    return TOOLS


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _auth_error(message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=401)


def _bearer_from_scope(scope) -> str | None:
    for name, value in scope.get("headers", []):
        if name.lower() == b"authorization":
            auth = value.decode("latin1")
            parts = auth.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == "bearer":
                return parts[1]
    return None


# ---------------------------------------------------------------------------
# ASGI-App mit Bearer-Token, SSE und Messages
# ---------------------------------------------------------------------------

def build_starlette_app(token: str | None = None):
    """Erzeugt die ASGI-App. Lädt das Token lazy, falls nicht übergeben."""
    if token is None:
        token = _load_token()

    sse = SseServerTransport("/messages/")

    async def _handle_sse(scope, receive, send):
        async with sse.connect_sse(scope, receive, send) as streams:
            await app.run(streams[0], streams[1], app.create_initialization_options())
        response = Response()
        await response(scope, receive, send)

    async def _handle_health(scope, receive, send):
        response = PlainTextResponse("ok", status_code=200)
        await response(scope, receive, send)

    async def _require_auth(scope, receive, send):
        provided = _bearer_from_scope(scope)
        if provided is None or not secrets.compare_digest(provided, token):
            response = _auth_error("Missing or invalid Authorization header")
            await response(scope, receive, send)
            return False
        return True

    async def asgi_app(scope, receive, send):
        if scope["type"] != "http":
            response = Response("Not Found", status_code=404)
            await response(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "")

        if path == "/health":
            await _handle_health(scope, receive, send)
            return

        if path == "/sse" and method == "GET":
            if not await _require_auth(scope, receive, send):
                return
            await _handle_sse(scope, receive, send)
            return

        if path.startswith("/messages/") and method == "POST":
            if not await _require_auth(scope, receive, send):
                return
            await sse.handle_post_message(scope, receive, send)
            return

        response = Response("Not Found", status_code=404)
        await response(scope, receive, send)

    return asgi_app


starlette_app = None  # Wird lazy in main_http() erzeugt, damit der Import
                      # ohne /run/secrets/bridge-token funktioniert.


async def main_http():
    global starlette_app
    if starlette_app is None:
        starlette_app = build_starlette_app()
    host = os.environ.get("BRIDGE_HOST", "0.0.0.0")
    port = int(os.environ.get("BRIDGE_PORT", "8080"))
    config = uvicorn.Config(
        starlette_app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    await server.serve()


def main():
    asyncio.run(main_http())


if __name__ == "__main__":
    main()
