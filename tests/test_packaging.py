from pathlib import Path

import yaml


ROOT = Path(__file__).parent.parent
VERSION = "1.0.7"
BRIDGE_IMAGE = (
    "ghcr.io/greg-built-it/umbrel-readonly-bridge:1.0.7@sha256:"
    "64d68675d941faaab661545fb1bdf64cb0e1457eb6c7e6dcb1f710e00121cca5"
)
PROXY_IMAGE = (
    "ghcr.io/greg-built-it/umbrel-openclaw-docker-proxy:1.0.7@sha256:"
    "3285e8c751aa96d02a774ebe6463b37f88841fd33983a5a97bfeb4026d8ec7c1"
)


def test_manifest_version_and_gallery():
    manifest = yaml.safe_load((ROOT / "umbrel-app.yml").read_text())

    assert manifest["version"] == VERSION
    assert manifest.get("gallery") == [], "gallery muss eine leere Liste sein"
    assert manifest["releaseNotes"].startswith("Version 1.0.7:")


def test_all_compose_volume_entries_are_strings():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())

    for service_name, service in compose["services"].items():
        for index, volume in enumerate(service.get("volumes", [])):
            assert isinstance(volume, str), (
                f"services.{service_name}.volumes[{index}] muss ein String sein"
            )


def test_packaging_has_no_placeholders_and_keeps_pinned_images():
    compose_text = (ROOT / "docker-compose.yml").read_text()
    manifest_text = (ROOT / "umbrel-app.yml").read_text()
    combined = compose_text + manifest_text
    forbidden = ("PLACE" + "HOLDER", "<GITHUB_USER>", "REPLACE_ME", "CHANGEME")

    assert not any(marker in combined for marker in forbidden), "Platzhalter gefunden"

    compose = yaml.safe_load(compose_text)
    assert compose["services"]["init-token"]["image"] == BRIDGE_IMAGE
    assert compose["services"]["app"]["image"] == BRIDGE_IMAGE
    assert compose["services"]["openclaw-docker-proxy"]["image"] == PROXY_IMAGE

    assert ":latest" not in compose_text
    assert ":1.0.5@sha256:" not in compose_text
    assert ":1.0.6@sha256:" not in compose_text
