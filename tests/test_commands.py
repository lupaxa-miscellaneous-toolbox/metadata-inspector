"""Command behaviour, exit codes, and configuration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lupaxa.metadata_inspector.cli import main
from lupaxa.metadata_inspector.config import ConfigError, load_settings
from lupaxa.metadata_inspector.xmp import XmpError, read_xmp
from tests.images import jpeg_bytes, plain_jpeg, png_bytes


def test_scan_json_redacts_gps(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    photo = tmp_path / "holiday.jpg"
    photo.write_bytes(jpeg_bytes())
    assert main(["scan", str(photo), "--json", "--quiet"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["schema_version"] == "1.0"
    findings = document["results"][0]["findings"]
    gps = next(item for item in findings if item["id"] == "exif.gps.coordinates")
    assert gps["value"] == "[redacted]"
    assert "decimal degrees" not in json.dumps(document)


def test_reveal_shows_coordinates(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    photo = tmp_path / "holiday.jpg"
    photo.write_bytes(jpeg_bytes())
    assert main(["explain", str(photo), "--field", "exif.gps.coordinates", "--reveal"]) == 0
    output = capsys.readouterr().out
    assert "decimal degrees" in output
    assert "does not prove" in output.lower()


def test_clean_keeps_the_original_and_verify_passes(tmp_path: Path) -> None:
    photo = tmp_path / "holiday.jpg"
    original = jpeg_bytes()
    photo.write_bytes(original)
    assert main(["clean", str(photo), "--quiet"]) == 0
    cleaned = tmp_path / "holiday-clean.jpg"
    assert cleaned.is_file()
    assert photo.read_bytes() == original
    assert main(["verify", str(photo), str(cleaned), "--quiet"]) == 0
    assert main(["check", str(photo), "--quiet"]) == 3
    assert main(["check", str(cleaned), "--quiet"]) == 0


def test_dry_run_writes_nothing(tmp_path: Path) -> None:
    photo = tmp_path / "holiday.jpg"
    photo.write_bytes(jpeg_bytes())
    assert main(["clean", str(photo), "--dry-run", "--quiet"]) == 0
    assert not (tmp_path / "holiday-clean.jpg").exists()
    assert list(tmp_path.glob(".metadata-inspector-*")) == []


def test_directory_scan_and_compare(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "a.jpg").write_bytes(jpeg_bytes())
    (tmp_path / "b.png").write_bytes(png_bytes())
    (tmp_path / "notes.txt").write_text("not a photograph", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--json", "--quiet"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert len(document["results"]) == 2
    assert main(["compare", str(tmp_path / "a.jpg"), str(tmp_path / "b.png"), "--quiet"]) == 0


def test_report_html_is_self_contained(tmp_path: Path) -> None:
    photo = tmp_path / "holiday.jpg"
    photo.write_bytes(jpeg_bytes())
    report = tmp_path / "report.html"
    assert main(["report", str(photo), "--format", "html", "--output", str(report), "--quiet"]) == 0
    text = report.read_text(encoding="utf-8")
    assert "<html" in text
    assert "http://" not in text
    assert "https://" not in text


def test_usage_and_unsupported_backend(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "--verbose", "--quiet", str(tmp_path)]) == 2
    config = tmp_path / "config.toml"
    config.write_text('backend = "exiftool"\n', encoding="utf-8")
    assert main(["version", "--config", str(config)]) == 5
    assert "ExifTool backend is not available" in capsys.readouterr().err


def test_symlink_is_not_followed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    photo = tmp_path / "holiday.jpg"
    photo.write_bytes(plain_jpeg())
    link = tmp_path / "link.jpg"
    link.symlink_to(photo)
    assert main(["scan", str(link), "--json", "--quiet"]) == 1
    document = json.loads(capsys.readouterr().out)
    assert document["results"][0]["inspection_status"] == "error"
    assert "symbolic link" in document["results"][0]["errors"][0]


def test_profiles_and_formats(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["profiles"]) == 0
    text = capsys.readouterr().out
    assert "public" in text
    assert "does not" in text.lower() or "anonym" in text.lower()
    assert main(["profiles", "show", "public"]) == 0
    shown = capsys.readouterr().out
    assert "Preserve rules win" in shown
    assert main(["formats"]) == 0
    formats = capsys.readouterr().out
    assert "HEIC" in formats or "heif" in formats.lower()
    assert "disabled" in formats.lower() or "not installed" in formats.lower()


def test_unknown_profile_and_builtin_override(tmp_path: Path) -> None:
    assert main(["clean", "--profile", "missing", str(tmp_path / "none.jpg")]) == 2
    config = tmp_path / "config.toml"
    config.write_text("[profiles.public]\npreserve_copyright = false\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="built in"):
        load_settings(config, use_user_config=False)


def test_custom_profile_removes_only_named_tags(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        "\n".join(
            [
                "[profiles.serials]",
                'remove_tags = ["BodySerialNumber"]',
                "preserve_copyright = true",
                "preserve_orientation = true",
                "preserve_icc = true",
            ]
        ),
        encoding="utf-8",
    )
    photo = tmp_path / "holiday.jpg"
    photo.write_bytes(jpeg_bytes())
    assert (
        main(["clean", str(photo), "--config", str(config), "--profile", "serials", "--quiet"]) == 0
    )
    cleaned = tmp_path / "holiday-clean.jpg"
    code = main(["check", str(cleaned), "--config", str(config), "--profile", "serials", "--quiet"])
    assert code == 0


def test_xmp_doctype_is_rejected() -> None:
    packet = b'<!DOCTYPE foo [<!ENTITY x "y">]><x:xmpmeta></x:xmpmeta>'
    with pytest.raises(XmpError):
        read_xmp(packet)


def test_photograph_json_gains_empty_video_facts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    photo = tmp_path / "still.jpg"
    photo.write_bytes(plain_jpeg())
    assert main(["scan", str(photo), "--json", "--quiet"]) == 0
    result = json.loads(capsys.readouterr().out)["results"][0]
    assert result["duration_seconds"] is None
    assert result["video_codec"] is None
    assert result["audio_tracks"] == []


def test_output_collision_does_not_overwrite(tmp_path: Path) -> None:
    photo = tmp_path / "holiday.jpg"
    photo.write_bytes(jpeg_bytes())
    destination = tmp_path / "holiday-clean.jpg"
    destination.write_bytes(plain_jpeg())
    before = destination.read_bytes()
    assert main(["clean", str(photo), "--quiet"]) == 1
    assert destination.read_bytes() == before
