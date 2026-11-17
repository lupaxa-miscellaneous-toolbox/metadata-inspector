"""Optional HEIC/HEIF inspection. Cleaning stays disabled until a tested rewriter exists."""

from __future__ import annotations

import io

from .exifedit import ExifError, load_exif, records_from_exif, thumbnail_bytes
from .models import Record


def heif_version() -> str | None:
    """Return the pillow-heif version when that backend is installed."""
    try:
        import pillow_heif
    except ImportError:
        return None
    version = getattr(pillow_heif, "__version__", "")
    return str(version) if version else "installed"


def inspect_heif(data: bytes) -> tuple[list[Record], bytes | None, int, list[str]]:
    """Inspect a HEIC/HEIF file when pillow-heif is installed."""
    try:
        import pillow_heif
        from PIL import Image
    except ImportError as exc:
        raise HeifUnavailable("HEIC/HEIF inspection needs the pillow-heif package") from exc
    pillow_heif.register_heif_opener()
    limitations: list[str] = []
    with Image.open(io.BytesIO(data)) as image:
        info = dict(image.info)
    records: list[Record] = []
    thumbnail: bytes | None = None
    exif = info.get("exif")
    if isinstance(exif, bytes) and exif:
        try:
            loaded = load_exif(exif)
        except ExifError:
            limitations.append("HEIC/HEIF EXIF metadata could not be parsed")
        else:
            records.extend(records_from_exif(loaded, "heif-exif"))
            thumbnail = thumbnail_bytes(loaded)
    icc = info.get("icc_profile")
    icc_bytes = len(icc) if isinstance(icc, bytes) else 0
    return records, thumbnail, icc_bytes, limitations


class HeifUnavailable(RuntimeError):
    """HEIC/HEIF support is not installed."""
