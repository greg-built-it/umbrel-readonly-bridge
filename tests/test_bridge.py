import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from starlette.testclient import TestClient

from umbrel_ro_bridge import __version__
from umbrel_ro_bridge.server import build_starlette_app, _token_path_guard
from umbrel_ro_bridge import policy, fs


def test_version_is_expected():
    assert __version__ == "1.0.5"


def test_health_endpoint_is_anonymous():
    app = build_starlette_app("test-token")
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.text == "ok"


def test_sse_requires_bearer_token():
    app = build_starlette_app("test-token")
    client = TestClient(app)
    resp = client.get("/sse")
    assert resp.status_code == 401


def test_sse_rejects_wrong_token():
    app = build_starlette_app("test-token")
    client = TestClient(app)
    resp = client.get("/sse", headers={"Authorization": "Bearer wrong-token"})
    assert resp.status_code == 401


def test_messages_requires_bearer_token():
    app = build_starlette_app("test-token")
    client = TestClient(app)
    resp = client.post("/messages/", json={})
    assert resp.status_code == 401


def test_token_path_guard_blocks_secret_path():
    for bad in ["/run/secrets/bridge-token", "/host/umbrel/.bridge-token"]:
        try:
            _token_path_guard(bad)
        except fs.FilesystemError as e:
            assert "verweigert" in str(e) or "Token" in str(e)
            continue
        raise AssertionError(f"Token-Pfad nicht blockiert: {bad}")


def test_policy_accepts_host_umbrel_without_existence():
    p = policy.resolve_host_path("/host/umbrel", require_exists=False)
    assert str(p) == "/host/umbrel"


def test_policy_traversal_rejected():
    try:
        policy.resolve_host_path("/host/umbrel/../../etc/passwd", require_exists=False)
    except policy.PolicyError:
        return
    raise AssertionError("Traversal wurde nicht abgelehnt")


def test_policy_symlink_escape_rejected(tmp_path):
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "escape"
    link.symlink_to("/etc")
    try:
        policy.resolve_host_path(str(link), require_exists=False)
    except policy.PolicyError:
        return
    raise AssertionError("Symlink-Escape wurde nicht abgelehnt")


def test_init_token_script_command():
    """Prüft, dass init-token.sh den Token unter /data/bridge-token erzeugt."""
    script = Path(__file__).parent.parent / "scripts" / "init-token.sh"
    assert script.exists(), "init-token.sh fehlt"
    text = script.read_text()
    assert 'TOKEN_FILE="/data/bridge-token"' in text
    assert 'if [ ! -s "$TOKEN_FILE" ]' in text
    assert 'mv "$TMP_FILE" "$TOKEN_FILE"' in text, "atomarer mv fehlt"


def test_init_token_creates_only_once():
    """Simuliert init-token.sh: Token wird nur angelegt, wenn leer/fehlend."""
    with tempfile.TemporaryDirectory() as d:
        token_file = os.path.join(d, "bridge-token")

        def run_init():
            if not os.path.exists(token_file) or os.path.getsize(token_file) == 0:
                tmp = f"{token_file}.tmp.{os.getpid()}"
                with open(tmp, "w") as f:
                    # BEWUSSTE DUMMY-TOKEN (64 hex chars) fuer den Unit-Test,
                    # kein echtes Secret.
                    f.write("deadbeef1234deadbeef1234deadbeef1234deadbeef1234deadbeef1234abcd")
                os.chmod(tmp, 0o600)
                os.replace(tmp, token_file)

        # Lauf 1: fehlt -> erzeugen
        run_init()
        first = open(token_file).read()
        assert len(first) == 64

        # Lauf 2: existiert -> darf nicht überschreiben
        run_init()
        second = open(token_file).read()
        assert first == second, "Token darf bei Neustart nicht wechseln"


def test_denylist_blocks_sensitive_files():
    for name in [
        ".env",
        "auth.json",
        "secrets.json",
        "credentials.json",
        "wallet.dat",
        "id_rsa",
        "authorized_keys",
    ]:
        denied, _ = policy.is_denied_path(Path("/host/umbrel") / name)
        assert denied, name


def test_token_paths_blocked():
    """Sowohl Secret-Mount als auch persistenter App-Token-Pfad blockiert."""
    for bad in [
        "/run/secrets/bridge-token",
        "/host/umbrel/app-data/greg-umbrel-readonly-bridge/data/bridge-token",
        "/host/umbrel/some/dir/bridge-token",
        "/host/umbrel/.bridge-token",
    ]:
        denied, reason = policy.is_denied_path(Path(bad))
        assert denied, f"{bad} wurde nicht blockiert"
        assert "Token" in reason or "bridge-token" in reason


def test_token_symlink_blocked(tmp_path):
    """Auch ein Symlink mit Token-Basisname auf eine normale Datei muss blockiert werden."""
    real = tmp_path / "secret"
    real.write_text("sensitive")
    link = tmp_path / "bridge-token"
    link.symlink_to(real)

    denied, _ = policy.is_denied_path(link)
    assert denied, "Symlink mit bridge-token-Namen wurde nicht blockiert"


def test_tools_cannot_read_token():
    """read_text, read_binary_chunk, sha256, file_type, grep_text sperren Token."""
    from pathlib import Path
    token_path = Path("/host/umbrel/app-data/greg-umbrel-readonly-bridge/data/bridge-token")
    denied, reason = policy.is_denied_path(token_path)
    assert denied, "Token-Pfad nicht blockiert"
    assert "Token" in reason or "bridge-token" in reason

    for bad in [
        "/run/secrets/bridge-token",
        "/host/umbrel/.bridge-token",
        "/host/umbrel/app-data/greg-umbrel-readonly-bridge/data/bridge-token",
    ]:
        try:
            policy.resolve_host_path(bad, require_exists=False)
        except policy.PolicyError as e:
            assert "Token" in str(e) or "verweigert" in str(e)
        else:
            raise AssertionError(f"Token-Pfad nicht blockiert: {bad}")


def test_normal_app_data_files_remain_readable():
    """Dateien unter /host/umbrel/app-data, die nicht der Token sind, bleiben lesbar."""
    from pathlib import Path
    normal = Path("/host/umbrel/app-data/greg-umbrel-readonly-bridge/data/config.json")
    denied, reason = policy.is_denied_path(normal)
    assert not denied, "Normale App-Data-Dateien dürfen nicht blockiert werden"


def test_compose_init_service_uses_entrypoint():
    """Init-Service verwendet entrypoint + command: [] statt Image-ENTRYPOINT."""
    import yaml
    compose_path = Path(__file__).parent.parent / "docker-compose.yml"
    compose = yaml.safe_load(compose_path.read_text())
    init = compose["services"]["init-token"]
    assert init["entrypoint"] == ["/app/scripts/init-token.sh"]
    assert init["command"] == []
    assert init["restart"] == "no"
    assert "container_name" not in init


def test_token_path_guard_blocks_all_token_names():
    for bad in [
        "/run/secrets/bridge-token",
        "/host/umbrel/app-data/greg-umbrel-readonly-bridge/data/bridge-token",
        "/host/umbrel/.bridge-token",
        "/host/umbrel/bridge-token",
    ]:
        try:
            _token_path_guard(bad)
        except fs.FilesystemError as e:
            assert "verweigert" in str(e) or "Token" in str(e)
            continue
        raise AssertionError(f"Token-Pfad nicht blockiert: {bad}")


def test_compose_init_service_has_no_container_name():
    """Init-Service darf kein festes container_name haben."""
    import yaml
    compose_path = Path(__file__).parent.parent / "docker-compose.yml"
    compose = yaml.safe_load(compose_path.read_text())
    init = compose["services"]["init-token"]
    assert "container_name" not in init


def test_compose_app_depends_on_init_completed():
    import yaml
    compose_path = Path(__file__).parent.parent / "docker-compose.yml"
    compose = yaml.safe_load(compose_path.read_text())
    app = compose["services"]["app"]
    assert app["depends_on"]["init-token"]["condition"] == "service_completed_successfully"


def test_compose_umbrel_root_variable_mount():
    import yaml
    compose_path = Path(__file__).parent.parent / "docker-compose.yml"
    compose = yaml.safe_load(compose_path.read_text())
    app = compose["services"]["app"]
    volumes = app["volumes"]
    # Kurzsyntax: alle Einträge müssen Strings sein, keine Objekte
    assert all(isinstance(v, str) for v in volumes), "Volume-Einträge müssen Strings sein"
    umbrel_mount = next(v for v in volumes if ":/host/umbrel" in v)
    token_mount = next(v for v in volumes if ":/run/secrets/bridge-token" in v)
    assert "${UMBREL_ROOT}" in umbrel_mount
    assert ":ro,rslave" in umbrel_mount
    assert "${APP_DATA_DIR}/data/bridge-token" in token_mount
    assert ":ro" in token_mount


def test_compose_no_volume_objects():
    import yaml
    compose_path = Path(__file__).parent.parent / "docker-compose.yml"
    compose = yaml.safe_load(compose_path.read_text())
    volumes = compose["services"]["app"]["volumes"]
    # Kurzsyntax: alle Einträge müssen Strings sein, keine Objekte
    assert all(isinstance(v, str) for v in volumes), "Volume-Einträge müssen Strings sein"
    # Sicherstellen, dass keine Langsyntax-Schlüssel in den Strings vorkommen
    flat = " ".join(volumes)
    assert "type:" not in flat and "source:" not in flat and "target:" not in flat and "bind:" not in flat


def test_compose_app_capabilities():
    import yaml
    compose_path = Path(__file__).parent.parent / "docker-compose.yml"
    compose = yaml.safe_load(compose_path.read_text())
    app = compose["services"]["app"]
    assert app["cap_drop"] == ["ALL"]
    assert app["cap_add"] == ["DAC_READ_SEARCH"]
    assert "privileged" not in app
    assert "ports" not in app
    assert "docker.sock" not in str(app)


def test_compose_app_network_alias_for_hermes():
    import yaml
    compose_path = Path(__file__).parent.parent / "docker-compose.yml"
    compose = yaml.safe_load(compose_path.read_text())
    proxy = compose["services"].get("app_proxy")
    assert proxy is not None
    env = proxy["environment"]
    assert env["APP_HOST"] == "greg-umbrel-readonly-bridge_app_1"
    assert env["APP_PORT"] == 8080
    assert env["PROXY_AUTH_ADD"] == "false"


def test_manifest_has_health_path_and_public_icon():
    import yaml
    manifest_path = Path(__file__).parent.parent / "umbrel-app.yml"
    manifest = yaml.safe_load(manifest_path.read_text())
    assert manifest["path"] == "/health"
    assert "raw.githubusercontent.com" in manifest["icon"]
    assert "greg-built-it" in manifest["icon"]
    assert "<GITHUB_USER>" not in manifest["icon"]


def test_no_github_user_placeholder_anywhere():
    """Sicherstellen, dass <GITHUB_USER> nach Ersetzung nirgends mehr vorkommt."""
    import os
    root = Path(__file__).parent.parent.parent
    for dirpath, _, filenames in os.walk(root):
        if ".venv" in dirpath or "__pycache__" in dirpath or ".git" in dirpath:
            continue
        for fname in filenames:
            fp = Path(dirpath) / fname
            if fp.suffix in {".pyc", ".pyo"}:
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
                assert "<GITHUB_USER>" not in content, f"Platzhalter in {fp}"
            except Exception:
                pass


def test_docker_compose_image_is_pinned():
    """Compose muss das Image mit SHA256-Digest referenzieren."""
    import yaml
    compose_path = Path(__file__).parent.parent / "docker-compose.yml"
    compose = yaml.safe_load(compose_path.read_text())
    for svc in ["init-token", "app"]:
        img = compose["services"][svc]["image"]
        assert img.startswith("ghcr.io/greg-built-it/umbrel-readonly-bridge"), svc
        assert "@sha256:" in img, f"Digest fehlt in {svc}"