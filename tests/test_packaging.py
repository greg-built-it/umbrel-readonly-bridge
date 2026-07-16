from pathlib import Path

import yaml


ROOT = Path(__file__).parent.parent


def test_manifest_gallery_is_a_list():
    manifest = yaml.safe_load((ROOT / "umbrel-app.yml").read_text())

    assert isinstance(manifest.get("gallery"), list), "gallery muss eine Liste sein"


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
    forbidden = ("PLACEHOLDER", "<GITHUB_USER>", "REPLACE_ME", "CHANGEME")

    assert not any(marker in combined for marker in forbidden), "Platzhalter gefunden"

    compose = yaml.safe_load(compose_text)
    bridge = (
        "ghcr.io/greg-built-it/umbrel-readonly-bridge:1.0.3-2@sha256:"
        "b69746d2e18c16036e5e318e4fb30eb73b721f0ee9250d426b2001337b8b80df"
    )
    proxy = (
        "ghcr.io/greg-built-it/umbrel-openclaw-docker-proxy:1.0.3-2@sha256:"
        "57750b35cd9feba429fe7f9b0d488a7af6e6f405bb35621dad5359d71b7e5d66"
    )
    assert compose["services"]["init-token"]["image"] == bridge
    assert compose["services"]["app"]["image"] == bridge
    assert compose["services"]["openclaw-docker-proxy"]["image"] == proxy
