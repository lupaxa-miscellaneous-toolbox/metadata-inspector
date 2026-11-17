"""Make metadata values safe to store and display."""

from __future__ import annotations

import hashlib
import re

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_TEXT = 4096

REDACTED_IDS = frozenset(
    {
        "exif.gps.coordinates",
        "exif.gps.altitude",
        "exif.gps.timestamp",
        "exif.gps.destination",
        "exif.camera.serial",
        "exif.lens.serial",
        "exif.camera.owner",
        "exif.image.unique_id",
        "iptc.contact",
        "xmp.contact",
        "container.device.serial",
        "container.gps.route",
    }
)


def sanitise(value: str) -> str:
    """Remove terminal-control characters and limit length."""
    cleaned = _CONTROL.sub("", value).strip()
    if len(cleaned) > MAX_TEXT:
        return cleaned[:MAX_TEXT] + "… [truncated]"
    return cleaned


def as_text(value: object) -> tuple[str, bool]:
    """Return a display string and whether the original value was binary."""
    if isinstance(value, bytes):
        raw = value.split(b"\x00", 1)[0]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            if len(raw) > 64 or any(byte < 32 and byte not in (9, 10, 13) for byte in raw):
                return safe_binary(value), True
            text = raw.decode("latin-1", errors="replace")
        unprintable = any(ord(char) < 32 and char not in "\t" for char in text)
        if (not text or unprintable) and raw and not text.strip():
            return safe_binary(value), True
        return sanitise(text), False
    if isinstance(value, str):
        return sanitise(value), False
    return sanitise(str(value)), False


def safe_binary(data: bytes) -> str:
    """Describe binary metadata without printing the bytes."""
    digest = hashlib.sha256(data).hexdigest()
    return f"binary length={len(data)} sha256={digest}"


def display_value(finding_id: str, value: str, *, reveal: bool) -> str:
    """Mask precise coordinates, serial numbers, and contact values."""
    if finding_id == "container.gps.route" and not reveal:
        count, _sep, _rest = value.partition(";")
        if _sep:
            return count.strip() + "; [redacted]"
    if reveal or finding_id not in REDACTED_IDS:
        return value
    if not value:
        return value
    return "[redacted]"
