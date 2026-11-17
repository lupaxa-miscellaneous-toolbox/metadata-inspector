"""Read and rewrite EXIF dictionaries with piexif."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

import piexif

from .models import Record
from .sanitize import as_text
from .values import format_gps_coordinate, format_value

IFD_FAMILY = {
    "0th": "EXIF",
    "1st": "EXIF",
    "Exif": "EXIF",
    "Interop": "EXIF",
    "GPS": "GPS",
}
IFD_GROUP = {
    "0th": "Image",
    "1st": "Image",
    "Exif": "Exif",
    "Interop": "Interop",
    "GPS": "GPS",
}
GPS_COORDINATE_FIELDS = {"GPSLatitude", "GPSLongitude", "GPSDestLatitude", "GPSDestLongitude"}
GPS_REFERENCE = {
    "GPSLatitude": "GPSLatitudeRef",
    "GPSLongitude": "GPSLongitudeRef",
    "GPSDestLatitude": "GPSDestLatitudeRef",
    "GPSDestLongitude": "GPSDestLongitudeRef",
}


class ExifError(ValueError):
    """EXIF could not be read or rewritten."""


def tag_name(ifd: str, tag: int) -> str:
    """Return the piexif name for a tag, or the numeric id."""
    info = piexif.TAGS.get(IFD_GROUP[ifd], {}).get(tag)
    if not isinstance(info, dict) or "name" not in info:
        return str(tag)
    return str(info["name"])


def load_exif(payload: bytes) -> dict[str, object]:
    """Load EXIF from a JPEG, an Exif payload, or a raw TIFF block."""
    blob = payload
    if payload[:2] in {b"II", b"MM"} and not payload.startswith(b"Exif\x00\x00"):
        blob = b"Exif\x00\x00" + payload
    try:
        loaded = piexif.load(blob)
    except Exception as exc:
        raise ExifError("EXIF metadata could not be parsed") from exc
    if not isinstance(loaded, dict):
        raise ExifError("EXIF metadata could not be parsed")
    return cast(dict[str, object], loaded)


def records_from_exif(exif: Mapping[str, object], source: str) -> list[Record]:
    """Turn a piexif dictionary into inventory records."""
    records: list[Record] = []
    for ifd, family in IFD_FAMILY.items():
        tags = exif.get(ifd)
        if not isinstance(tags, dict):
            continue
        for tag, value in tags.items():
            if not isinstance(tag, int):
                continue
            name = tag_name(ifd, int(tag))
            if name in GPS_REFERENCE.values():
                continue
            interpreted = _interpret(name, value, tags)
            raw, binary = as_text(value if not isinstance(value, tuple) else interpreted)
            if not interpreted:
                continue
            records.append(
                Record(family, name, str(tag), interpreted, raw or interpreted, source, binary)
            )
    thumbnail = exif.get("thumbnail")
    if isinstance(thumbnail, bytes) and thumbnail:
        records.append(
            Record(
                "THUMBNAIL",
                "preview",
                "thumbnail",
                f"{len(thumbnail)} bytes",
                f"{len(thumbnail)} bytes",
                source,
                True,
            )
        )
    return records


def thumbnail_bytes(exif: dict[str, object]) -> bytes | None:
    """Return the embedded JPEG preview, if piexif found one."""
    thumbnail = exif.get("thumbnail")
    if isinstance(thumbnail, bytes) and thumbnail:
        return thumbnail
    return None


def rewrite_exif(exif: dict[str, object], remove_fields: set[tuple[str, str]]) -> bytes | None:
    """Return new EXIF bytes, or None when no EXIF segment should remain."""
    updated: dict[str, object] = {}
    for ifd, family in IFD_FAMILY.items():
        tags = exif.get(ifd)
        if not isinstance(tags, dict):
            updated[ifd] = {}
            continue
        kept: dict[int, object] = {}
        for tag, value in tags.items():
            if not isinstance(tag, int):
                continue
            name = tag_name(ifd, tag)
            if (family, name) in remove_fields:
                continue
            if name in GPS_REFERENCE.values() and _reference_removed(name, remove_fields):
                continue
            kept[tag] = value
        updated[ifd] = kept
    drop_thumbnail = ("THUMBNAIL", "preview") in remove_fields
    if drop_thumbnail:
        updated["1st"] = {}
        updated["thumbnail"] = None
        for ifd_name in ("0th", "1st"):
            tags = updated.get(ifd_name)
            if isinstance(tags, dict):
                tags.pop(513, None)
                tags.pop(514, None)
    else:
        updated["thumbnail"] = exif.get("thumbnail")
    if not _has_tags(updated) and not (
        isinstance(updated.get("thumbnail"), bytes) and updated.get("thumbnail")
    ):
        return None
    try:
        return bytes(piexif.dump(updated))
    except Exception as exc:
        raise ExifError("EXIF metadata could not be rewritten") from exc


def _has_tags(exif: dict[str, object]) -> bool:
    for ifd in IFD_FAMILY:
        tags = exif.get(ifd)
        if isinstance(tags, dict) and tags:
            return True
    return False


def _reference_removed(reference_name: str, remove_fields: set[tuple[str, str]]) -> bool:
    for coordinate, reference in GPS_REFERENCE.items():
        if reference == reference_name and ("GPS", coordinate) in remove_fields:
            return True
    return False


def _interpret(name: str, value: object, tags: dict[object, object]) -> str:
    if name in GPS_COORDINATE_FIELDS:
        ref_name = GPS_REFERENCE[name]
        ref_tag = _tag_number("GPS", ref_name)
        ref = tags.get(ref_tag) if ref_tag is not None else None
        return format_gps_coordinate(value, ref)
    text = format_value(value)
    if name == "Orientation" and text in {"1", "2", "3", "4", "5", "6", "7", "8"}:
        labels = {
            "1": "horizontal",
            "2": "mirrored horizontal",
            "3": "rotated 180",
            "4": "mirrored vertical",
            "5": "mirrored and rotated",
            "6": "rotated 90 clockwise",
            "7": "mirrored and rotated",
            "8": "rotated 90 counter-clockwise",
        }
        return f"{text} ({labels[text]})"
    return text


def _tag_number(ifd: str, name: str) -> int | None:
    for tag, info in piexif.TAGS.get(IFD_GROUP[ifd], {}).items():
        if isinstance(info, dict) and info.get("name") == name and isinstance(tag, int):
            return tag
    return None
