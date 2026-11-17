"""Report the capabilities of this installation."""

from __future__ import annotations

import shutil
import subprocess

import piexif
from PIL import Image

from .heif import heif_version
from .models import SCHEMA_VERSION

HEIF_LIMIT = (
    "Cleaning is disabled until a tested backend can rewrite HEIC/HEIF "
    "without changing required image characteristics."
)


def capability_report() -> dict[str, object]:
    """Describe formats and backends actually available here."""
    heif = heif_version()
    python_backend = f"python (Pillow {Image.__version__}, piexif {piexif.VERSION})"
    families = ["EXIF", "GPS", "IPTC", "XMP", "ICC", "TEXT", "THUMBNAIL"]
    lossless = "Lossless metadata rewrite. Pixels are recompressed only with --apply-orientation."
    return {
        "schema_version": SCHEMA_VERSION,
        "backend": python_backend,
        "exiftool": exiftool_version(),
        "formats": {
            "jpeg": _row(True, True, True, families, python_backend, [lossless]),
            "png": _row(
                True, True, True, ["EXIF", "TEXT", "ICC", "THUMBNAIL"], python_backend, [lossless]
            ),
            "webp": _row(
                True, True, True, ["EXIF", "XMP", "ICC", "THUMBNAIL"], python_backend, [lossless]
            ),
            "tiff": _row(
                True,
                True,
                True,
                ["EXIF", "GPS", "ICC", "THUMBNAIL"],
                python_backend,
                [
                    lossless,
                    "Extra TIFF pages are not rewritten when the profile keeps embedded previews.",
                ],
            ),
            "heif": _row(
                heif is not None,
                False,
                False,
                ["EXIF", "ICC", "THUMBNAIL"] if heif else [],
                f"pillow-heif {heif}" if heif else "not installed",
                [
                    HEIF_LIMIT
                    if heif
                    else "Install the heif extra (pillow-heif) to inspect HEIC/HEIF."
                ],
            ),
            "bmff": _row(
                True,
                True,
                True,
                ["EXIF", "GPS", "XMP", "CONTAINER", "THUMBNAIL"],
                python_backend,
                [
                    "Matroska, WebM, AVI, and other containers are not read.",
                    (
                        "Fragmented MP4, encrypted samples, and media stored outside "
                        "the file are unsupported."
                    ),
                    (
                        "A metadata track that is not ISO 6709 or NMEA is removed by a "
                        "medium-removing profile without interpreting the samples."
                    ),
                    "Cleaning does not re-encode. Picture and sound bytes are copied.",
                    "The video size ceiling defaults to 8 GiB. A moov over 32 MiB is refused.",
                    "ExifTool is not used to inspect or clean movies.",
                ],
            ),
        },
    }


def format_text(report: dict[str, object]) -> str:
    """Render the formats report."""
    lines = [
        "Metadata Inspector",
        str(report["backend"]),
        f"ExifTool: {report['exiftool'] or 'not installed'}",
        "",
    ]
    formats = report["formats"]
    if isinstance(formats, dict):
        for name, row in formats.items():
            if not isinstance(row, dict):
                continue
            lines.append(name.upper())
            lines.append(f"  Inspection: {_yes(row.get('inspection'))}")
            lines.append(f"  Cleaning: {_yes(row.get('cleaning'))}")
            lines.append(f"  Verification: {_yes(row.get('verification'))}")
            families = row.get("families")
            if isinstance(families, list):
                lines.append(
                    "  Families: " + (", ".join(str(item) for item in families) or "(none)")
                )
            lines.append(f"  Backend: {row.get('backend')}")
            limitations = row.get("limitations")
            if isinstance(limitations, list):
                for item in limitations:
                    lines.append(f"  Limitation: {item}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def exiftool_version() -> str | None:
    """Return ExifTool's version when the optional binary is on PATH."""
    executable = shutil.which("exiftool")
    if not executable:
        return None
    try:
        completed = subprocess.run(  # noqa: S603
            [executable, "-ver"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def _row(
    inspection: bool,
    cleaning: bool,
    verification: bool,
    families: list[str],
    backend: str,
    limitations: list[str],
) -> dict[str, object]:
    return {
        "inspection": inspection,
        "cleaning": cleaning,
        "verification": verification,
        "families": families,
        "backend": backend,
        "limitations": limitations,
    }


def _yes(value: object) -> str:
    return "yes" if value else "no"
