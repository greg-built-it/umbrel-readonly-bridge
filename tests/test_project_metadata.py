import tomllib
from pathlib import Path


ROOT = Path(__file__).parent.parent
PROXY_1_0_7_COMMIT = "d31be0cc9ff4e8f8c3ecb1f66fdbb9213d9e2d07"


def test_project_version_is_1_0_7():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())

    assert project["project"]["version"] == "1.0.7"


def test_e2e_pins_proxy_1_0_7_commit():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()

    assert "Checkout Proxy 1.0.7 source" in workflow
    assert f"ref: {PROXY_1_0_7_COMMIT}" in workflow


def test_release_metadata_explicitly_disables_latest_tag():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert workflow.count("docker/metadata-action@") == 1
    metadata_block = workflow.split("docker/metadata-action@", 1)[1].split(
        "- name: Build and push", 1
    )[0]

    assert metadata_block.count("flavor: latest=false") == 1
    configured_tags = [
        line.strip()
        for line in metadata_block.splitlines()
        if line.strip().startswith("type=")
    ]
    assert configured_tags == ["type=semver,pattern={{version}}", "type=sha"]
    latest_lines = [
        line.strip()
        for line in workflow.splitlines()
        if "latest" in line.lower() and "ubuntu-latest" not in line.lower()
    ]
    assert latest_lines == ["flavor: latest=false"]


def test_image_e2e_smokes_bridge_default_entrypoint():
    script = (ROOT / "tests" / "e2e" / "run_image_e2e.sh").read_text()
    smoke = script.split('echo "E2E_BRIDGE_DEFAULT_ENTRYPOINT_START"', 1)[1].split(
        'echo "E2E_BRIDGE_DEFAULT_ENTRYPOINT=pass"', 1
    )[0]

    assert 'docker run --detach' in smoke
    assert '--name "$BRIDGE_SMOKE_CONTAINER"' in smoke
    assert '"$BRIDGE_IMAGE"' in smoke
    assert "--entrypoint" not in smoke
    assert "http://127.0.0.1:8080/health" in smoke
    assert 'docker stop --time 10 "$BRIDGE_SMOKE_CONTAINER"' in smoke


def test_image_e2e_keeps_proxy_default_entrypoint_smoke():
    script = (ROOT / "tests" / "e2e" / "run_image_e2e.sh").read_text()
    smoke = script.split('--name "$PROXY_CONTAINER"', 1)[1].split(
        'docker exec "$PROXY_CONTAINER"', 1
    )[0]

    assert '"$PROXY_IMAGE"' in smoke
    assert "--entrypoint" not in smoke
    assert "openclaw_docker_proxy.healthcheck" in smoke
