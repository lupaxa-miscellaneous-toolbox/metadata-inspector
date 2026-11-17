"""Cleaning and verification using synthetic photographs."""

from __future__ import annotations

from pathlib import Path

import piexif
from PIL import Image

from lupaxa.metadata_inspector.catalog import rule_for
from lupaxa.metadata_inspector.engine import (
    clean_bytes,
    detect_format,
    entropy_payload,
    inspect_bytes,
    verify_clean,
)
from lupaxa.metadata_inspector.policy import builtin_profiles
from tests.images import jpeg_bytes, plain_jpeg, png_bytes, tiff_bytes, webp_bytes


def test_jpeg_scan_classifies_gps_and_serial() -> None:
    inspection = inspect_bytes(jpeg_bytes(), "holiday.jpg")
    ids = {finding.id for finding in inspection.findings}
    assert inspection.format == "jpeg"
    assert inspection.status in {"completed", "incomplete"}
    assert "exif.gps.coordinates" in ids
    assert "exif.camera.serial" in ids
    assert "exif.copyright" in ids
    assert "iptc.city" in ids
    assert "xmp.city" in ids
    gps = next(finding for finding in inspection.findings if finding.id == "exif.gps.coordinates")
    assert "decimal degrees" in gps.value
    assert gps.classification == "high"
    serial = next(finding for finding in inspection.findings if finding.id == "exif.camera.serial")
    assert serial.classification == "high"
    model = next(finding for finding in inspection.findings if finding.id == "exif.camera.model")
    assert model.classification == "low"


def test_public_jpeg_clean_keeps_pixels_and_copyright() -> None:
    original = jpeg_bytes()
    inspection = inspect_bytes(original, "holiday.jpg")
    profile = builtin_profiles()["public"]
    cleaned, _warnings, limitations, pixels = clean_bytes(
        original, inspection, profile, apply_orientation=False
    )
    assert limitations == []
    assert cleaned is not None
    assert pixels is False
    assert entropy_payload(original) == entropy_payload(cleaned)
    status, removed, preserved, limits = verify_clean(
        original, cleaned, inspection, profile, pixels_modified=False
    )
    assert status == "passed", limits
    assert "GPS coordinates" in removed
    assert "Camera serial number" in removed
    assert "ICC colour profile" not in removed
    checked = inspect_bytes(cleaned, "clean.jpg")
    remaining = {finding.id for finding in checked.findings}
    assert "exif.gps.coordinates" not in remaining
    assert "exif.camera.serial" not in remaining
    assert "exif.copyright" in remaining
    assert "iptc.copyright" in remaining
    assert "xmp.city" not in remaining
    assert (
        Image.open(__import__("io").BytesIO(original)).size
        == Image.open(__import__("io").BytesIO(cleaned)).size
    )
    assert "Display orientation" in preserved or "Image dimensions" in preserved


def test_anonymous_profile_removes_attribution() -> None:
    original = jpeg_bytes()
    inspection = inspect_bytes(original, "holiday.jpg")
    profile = builtin_profiles()["anonymous"]
    cleaned, warnings, limitations, _pixels = clean_bytes(
        original, inspection, profile, apply_orientation=False
    )
    assert cleaned is not None, limitations
    assert any(
        "attribution" in warning.lower() or "copyright" in warning.lower() for warning in warnings
    )
    checked = inspect_bytes(cleaned, "anon.jpg")
    remaining = {finding.id for finding in checked.findings}
    assert "exif.copyright" not in remaining
    assert "exif.artist" not in remaining


def test_png_and_webp_and_tiff_public_clean_preserve_pixels() -> None:
    profile = builtin_profiles()["public"]
    for name, blob in (("png", png_bytes()), ("webp", webp_bytes()), ("tiff", tiff_bytes())):
        inspection = inspect_bytes(blob, f"photo.{name}")
        assert inspection.format == name
        cleaned, _warnings, limitations, pixels = clean_bytes(
            blob, inspection, profile, apply_orientation=False
        )
        assert cleaned is not None, (name, limitations)
        assert pixels is False
        status, _removed, _preserved, limits = verify_clean(
            blob, cleaned, inspection, profile, pixels_modified=False
        )
        assert status == "passed", (name, limits)
        before = Image.open(__import__("io").BytesIO(blob))
        after = Image.open(__import__("io").BytesIO(cleaned))
        assert before.size == after.size
        assert before.tobytes() == after.tobytes()


def test_malformed_jpeg_is_not_reported_as_cleaned(tmp_path: Path) -> None:
    source = tmp_path / "broken.jpg"
    source.write_bytes(b"\xff\xd8\xff\xe1\x00\x08Exif\x00\xff\xd9")
    inspection = inspect_bytes(source.read_bytes(), source.name)
    assert inspection.status in {"incomplete", "error", "unsupported"}
    profile = builtin_profiles()["public"]
    cleaned, _warnings, limitations, _pixels = clean_bytes(
        source.read_bytes(), inspection, profile, apply_orientation=False
    )
    if cleaned is not None:
        status, _removed, _preserved, _limits = verify_clean(
            source.read_bytes(), cleaned, inspection, profile, pixels_modified=False
        )
        assert status != "passed"
    else:
        assert limitations


def test_detect_format_uses_contents() -> None:
    assert detect_format(plain_jpeg()) == "jpeg"
    assert detect_format(b"not an image") == "unknown"


def test_control_characters_are_not_displayed() -> None:
    image = __import__("io").BytesIO()
    picture = Image.new("RGB", (2, 2), (1, 1, 1))
    exif = piexif.dump(
        {
            "0th": {piexif.ImageIFD.Artist: b"Ada\x1b[31mHACK"},
            "Exif": {},
            "GPS": {},
            "1st": {},
            "thumbnail": None,
        }
    )
    picture.save(image, format="JPEG", exif=exif)
    inspection = inspect_bytes(image.getvalue(), "escape.jpg")
    artist = next(finding for finding in inspection.findings if finding.id == "exif.artist")
    assert "\x1b" not in artist.value
    assert "HACK" in artist.value


def test_dimensions_are_informational_and_time_fragments_are_medium() -> None:
    for field in ("ImageWidth", "ImageLength", "ExifTag", "SomeOtherTag"):
        assert rule_for("EXIF", field).classification == "informational"
    for field in ("OffsetTimeDigitized", "SubSecTime", "SubSecTimeOriginal", "SubSecTimeDigitized"):
        assert rule_for("EXIF", field).classification == "medium"
