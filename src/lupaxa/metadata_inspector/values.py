"""Format EXIF and GPS values, including decimal degrees."""

from __future__ import annotations

from .sanitize import as_text


def format_value(value: object) -> str:
    """Format an EXIF value as text."""
    if isinstance(value, tuple):
        if value and all(isinstance(item, tuple) for item in value):
            return " ".join(_rational(item) for item in value)
        if len(value) == 2 and all(isinstance(item, int) for item in value):
            return _rational(value)
    text, _binary = as_text(value)
    return text


def _rational(value: object) -> str:
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[1], int) and value[1]:
        number, denom = value
        if isinstance(number, int) and denom == 1:
            return str(number)
        if isinstance(number, int):
            return f"{number}/{denom} ({number / denom:.6g})"
    return str(value)


def reference_text(value: object) -> str:
    """Decode a GPS reference such as N or W."""
    text, _binary = as_text(value)
    return text.strip()


def dms_to_decimal(dms: object, ref: object) -> float | None:
    """Convert a GPS degree/minute/second value to decimal degrees."""
    if not isinstance(dms, tuple) or len(dms) < 2:
        return None
    parts: list[float] = []
    for item in dms[:3]:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[1], int)
            or not item[1]
        ):
            return None
        if not isinstance(item[0], int):
            return None
        parts.append(item[0] / item[1])
    while len(parts) < 3:
        parts.append(0.0)
    decimal = parts[0] + parts[1] / 60 + parts[2] / 3600
    if reference_text(ref).upper() in {"S", "W"}:
        decimal = -decimal
    return decimal


def format_gps_coordinate(dms: object, ref: object) -> str:
    """Show a coordinate in its original form and in decimal degrees."""
    original = format_value(dms)
    ref_text = reference_text(ref)
    if ref_text:
        original = f"{original} {ref_text}"
    decimal = dms_to_decimal(dms, ref)
    if decimal is None:
        return original
    return f"{original} ({decimal:.6f} decimal degrees)"
