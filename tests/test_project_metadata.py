import tomllib
from pathlib import Path


ROOT = Path(__file__).parent.parent
PROXY_FIX_COMMIT = "cb61f80d913a4e556abe2b7d2451bdb1cc07d19c"


def test_project_version_is_1_0_6():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())

    assert project["project"]["version"] == "1.0.6"


def test_e2e_pins_proxy_image_diagnostics_fix_commit():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()

    assert "Checkout Proxy 1.0.6 source" in workflow
    assert f"ref: {PROXY_FIX_COMMIT}" in workflow
