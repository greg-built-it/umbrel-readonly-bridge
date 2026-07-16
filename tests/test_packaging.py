from pathlib import Path

import yaml


ROOT = Path(__file__).parent.parent


def test_manifest_version_and_gallery():
    manifest = yaml.safe_load((ROOT / "umbrel-app.yml").read_text())

    assert manifest["version"] == "1.0.4"
    assert manifest.get("gallery") == [], "gallery muss eine leere Liste sein"


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
    bridge = (
        "ghcr.io/greg-built-it/umbrel-readonly-bridge:1.0.4@sha256:"
        "12f5d428e49d5a542c85d95b9a422bb461a4f97b73458ddfe6e92d7f73bcff8b"
    )
    proxy = (
        "ghcr.io/greg-built-it/umbrel-openclaw-docker-proxy:1.0.4@sha256:"
        "fc3d860a6291116995a77e0d21286e460751b70b6f5d6b9ea0da34a4c9c83e0d"
    )
    assert compose["services"]["init-token"]["image"] == bridge
    assert compose["services"]["app"]["image"] == bridge
    assert compose["services"]["openclaw-docker-proxy"]["image"] == proxy
