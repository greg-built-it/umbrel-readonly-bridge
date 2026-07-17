import tomllib
from pathlib import Path


ROOT = Path(__file__).parent.parent


def test_project_version_is_1_0_5():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())

    assert project["project"]["version"] == "1.0.5"
