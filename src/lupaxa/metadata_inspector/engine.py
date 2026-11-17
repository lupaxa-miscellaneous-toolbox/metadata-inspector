"""Inspect, clean, verify, and compare photographs."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime
from pathlib import Path

from PIL import ImageOps

from .bmff import BmffError, Movie, media_hash, parse_movie, sniff, write_clean
from .catalog import build_findings
from .heif import HeifUnavailable, inspect_heif
from .imaging import ImageSafetyError, decode_image, image_bytes
from .jpeg import JpegError, entropy_payload, inspect_segments, parse_segments, rewrite_segments
from .models import CleanResult, Finding, ImageFacts, Inspection, Profile
from .png import PngError, inspect_png, rewrite_png
from .policy import should_remove
from .tiff import TiffError, inspect_tiff, rewrite_tiff
from .webp import WebpError, inspect_webp, rewrite_webp

BACKEND = "python"
_CLEARED_MOVIE_TIME = "1904-01-01 00:00:00 UTC"
_MOVIE_ORIENTATION = "Orientation applies to photographs. Video files are not rotated."


def detect_format(data: bytes) -> str:
    """Identify a photograph from its contents rather than its filename."""
    if data.startswith(b"\xff\xd8"):
        return "jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith((b"II*\x00", b"MM\x00*")):
        return "tiff"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12]
        if brand in {b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1", b"heif"}:
            return "heif"
        if brand == b"avif":
            return "avif"
    return "unknown"


def inspect_bytes(data: bytes, name: str, *, mtime: str | None = None) -> Inspection:
    """Inspect an in-memory photograph."""
    image_format = detect_format(data)
    inspection = Inspection(file=name, format=image_format, status="completed", backend=BACKEND)
    if image_format == "unknown":
        inspection.status = "unsupported"
        inspection.limitations.append("The file format is not supported for inspection.")
        return inspection
    if image_format == "avif":
        inspection.status = "unsupported"
        inspection.limitations.append("AVIF is not a supported photograph format.")
        return inspection
    try:
        records, thumbnail, icc_bytes, limitations = _read_metadata(data, image_format)
    except HeifUnavailable as exc:
        inspection.status = "unsupported"
        inspection.limitations.append(str(exc))
        return inspection
    except (JpegError, PngError, WebpError, TiffError, ValueError) as exc:
        inspection.status = "incomplete"
        inspection.limitations.append(str(exc))
        records, thumbnail, icc_bytes, limitations = [], None, 0, []
    inspection.records.extend(records)
    inspection.limitations.extend(limitations)
    inspection.facts = _facts(data, image_format, thumbnail, icc_bytes, mtime)
    _orientation_from_records(records, inspection.facts)
    if thumbnail or any(record.family == "THUMBNAIL" for record in records):
        inspection.facts.preview = True
        inspection.facts.preview_separate = True
        if thumbnail:
            inspection.facts.preview_bytes = len(thumbnail)
            _preview_dimensions(thumbnail, inspection.facts)
    if inspection.limitations and inspection.status == "completed":
        inspection.status = "incomplete"
    inspection.findings = build_findings(inspection.records, inspection.facts)
    return inspection


def inspect_path(
    path: Path,
    *,
    max_file_size: int,
    max_video_size: int = 8 * 1024 * 1024 * 1024,
) -> Inspection:
    """Inspect one filesystem path without following a symlink by itself."""
    try:
        info = path.lstat()
    except OSError as exc:
        return _error(str(path), f"cannot read file: {exc.strerror}")
    if path.is_symlink():
        return _error(str(path), "symbolic link was not followed")
    try:
        header = _read_header(path)
    except OSError as exc:
        return _error(str(path), f"cannot read file: {exc.strerror}")
    kind = _video_kind(header)
    if kind is not None:
        if info.st_size > max_video_size:
            return _error(str(path), "file exceeds the configured maximum size")
        return _inspect_movie(path, info.st_mtime, kind)
    if info.st_size > max_file_size:
        return _error(str(path), "file exceeds the configured maximum size")
    try:
        data = path.read_bytes()
    except OSError as exc:
        return _error(str(path), f"cannot read file: {exc.strerror}")
    return inspect_bytes(data, str(path), mtime=_local_mtime(info.st_mtime))


def removal_fields(inspection: Inspection, profile: Profile) -> set[tuple[str, str]]:
    """Return the family and field pairs a profile removes."""
    fields: set[tuple[str, str]] = set()
    for finding in inspection.findings:
        if not should_remove(finding, profile):
            continue
        fields.add((finding.family, finding.field))
        if finding.id == "exif.gps.coordinates":
            fields.update(
                {
                    ("GPS", "GPSLatitude"),
                    ("GPS", "GPSLongitude"),
                    ("XMP", "GPSLatitude"),
                    ("XMP", "GPSLongitude"),
                }
            )
        elif finding.id == "exif.gps.timestamp":
            fields.update({("GPS", "GPSTimeStamp"), ("GPS", "GPSDateStamp")})
        elif finding.id == "exif.gps.destination":
            fields.update({("GPS", "GPSDestLatitude"), ("GPS", "GPSDestLongitude")})
        elif finding.id == "thumbnail.preview":
            fields.add(("THUMBNAIL", "preview"))
        elif finding.id == "icc.profile":
            fields.add(("ICC", "profile"))
    return fields


def clean_bytes(
    data: bytes,
    inspection: Inspection,
    profile: Profile,
    *,
    apply_orientation: bool,
) -> tuple[bytes | None, list[str], list[str], bool]:
    """Return cleaned bytes, warnings, limitations, and whether pixels changed."""
    if inspection.format in {"unknown", "avif"}:
        return None, [], ["This format cannot be cleaned."], False
    if inspection.format == "heif":
        return (
            None,
            [],
            [
                inspection.limitations[0]
                if inspection.limitations
                else "HEIC/HEIF cleaning is disabled."
            ],
            False,
        )
    fields = removal_fields(inspection, profile)
    warnings = _copyright_warning(inspection, profile)
    pixels_modified = False
    working = data
    orientation = inspection.facts.orientation
    if apply_orientation and orientation not in {None, 1}:
        warnings.append(
            "Orientation was applied by re-encoding the image. JPEG files can lose quality."
        )
        try:
            image = decode_image(data)
            turned = ImageOps.exif_transpose(image)
            if turned is None:
                turned = image
            working = image_bytes(turned, inspection.format)
        except ImageSafetyError as exc:
            return None, warnings, [str(exc)], False
        pixels_modified = True
        fields.add(("EXIF", "Orientation"))
    elif orientation not in {None, 1} and ("EXIF", "Orientation") in fields:
        return (
            None,
            warnings,
            [
                (
                    "Removing the orientation tag would display the photograph incorrectly. "
                    "Keep the tag, or pass --apply-orientation to rotate the pixels explicitly."
                )
            ],
            False,
        )
    try:
        cleaned, extra = _rewrite(working, inspection.format, fields)
    except (JpegError, PngError, WebpError, TiffError, ValueError) as exc:
        return None, warnings, [str(exc)], pixels_modified
    warnings.extend(extra)
    return cleaned, warnings, [], pixels_modified


def verify_clean(
    original: bytes,
    cleaned: bytes,
    original_inspection: Inspection,
    profile: Profile,
    *,
    pixels_modified: bool,
) -> tuple[str, list[str], list[str], list[str]]:
    """Independently check a cleaned file. Returns status, removed, preserved, limitations."""
    checked = inspect_bytes(cleaned, original_inspection.file + " (cleaned)")
    limitations = list(checked.limitations)
    if checked.status == "unsupported":
        return (
            "unsupported",
            [],
            [],
            limitations or ["Verification is not available for this file."],
        )
    if checked.status == "error":
        return "failed", [], [], checked.errors or ["The cleaned file could not be inspected."]
    if profile.strict and checked.status != "completed":
        return "incomplete", [], [], limitations or ["Verification could not be completed."]
    prohibited = [finding.name for finding in checked.findings if should_remove(finding, profile)]
    if prohibited:
        return "failed", [], [], [f"Prohibited metadata remains: {', '.join(prohibited)}"]
    try:
        before = decode_image(original)
        after = decode_image(cleaned)
    except ImageSafetyError as exc:
        return "incomplete", [], [], [str(exc)]
    if pixels_modified:
        turned = ImageOps.exif_transpose(before)
        expected = turned if turned is not None else before
        if after.size != expected.size:
            return "failed", [], [], ["Image dimensions changed unexpectedly."]
    elif after.size != before.size or after.tobytes() != before.tobytes():
        return "failed", [], [], ["Image pixels or dimensions changed."]
    orientation_changed = checked.facts.orientation != original_inspection.facts.orientation
    if profile.preserve_orientation and not pixels_modified and orientation_changed:
        return "failed", [], [], ["Display orientation was not preserved."]
    if profile.preserve_icc and original_inspection.facts.icc and not checked.facts.icc:
        return "failed", [], [], ["The ICC colour profile was not preserved."]
    removed = sorted(
        {
            finding.name
            for finding in original_inspection.findings
            if should_remove(finding, profile)
        }
    )
    preserved = ["Image dimensions"]
    if profile.preserve_orientation:
        preserved.append("Display orientation")
    if profile.preserve_icc and original_inspection.facts.icc:
        preserved.append("ICC colour profile")
    remaining = [finding.name for finding in checked.findings if finding.family != "FILESYSTEM"]
    return "passed", removed, preserved + [f"Remaining: {name}" for name in remaining], []


def verify_paths(
    original: Path,
    cleaned: Path,
    profile: Profile,
    *,
    max_file_size: int,
    max_video_size: int,
) -> tuple[str, list[str], list[str], list[str]]:
    """Verify a cleaned file. Movies are hashed; photographs stay on the byte path."""
    if _movie_source(original) or _movie_source(cleaned):
        return _verify_movie_files(
            original,
            cleaned,
            profile,
            max_file_size=max_file_size,
            max_video_size=max_video_size,
        )
    original_bytes = original.read_bytes()
    cleaned_bytes = cleaned.read_bytes()
    source = inspect_bytes(original_bytes, str(original))
    return verify_clean(
        original_bytes,
        cleaned_bytes,
        source,
        profile,
        pixels_modified=False,
    )


def _verify_movie_files(
    original: Path,
    cleaned: Path,
    profile: Profile,
    *,
    max_file_size: int,
    max_video_size: int,
) -> tuple[str, list[str], list[str], list[str]]:
    """Re-read two movies and compare picture and sound payloads by hash."""
    source = inspect_path(original, max_file_size=max_file_size, max_video_size=max_video_size)
    checked = inspect_path(cleaned, max_file_size=max_file_size, max_video_size=max_video_size)
    limitations = list(checked.limitations)
    if source.status == "unsupported" or checked.status == "unsupported":
        return (
            "unsupported",
            [],
            [],
            limitations or ["Verification is not available for this file."],
        )
    if source.status == "error" or checked.status == "error":
        errors = checked.errors or source.errors or ["The cleaned file could not be inspected."]
        return "failed", [], [], errors
    if profile.strict and checked.status != "completed":
        return "incomplete", [], [], limitations or ["Verification could not be completed."]
    prohibited = [
        finding.name for finding in checked.findings if _movie_prohibited(finding, profile)
    ]
    if prohibited:
        return "failed", [], [], [f"Prohibited metadata remains: {', '.join(prohibited)}"]
    try:
        if media_hash(original) != media_hash(cleaned):
            return "failed", [], [], ["Picture or sound payloads changed."]
    except BmffError as exc:
        status = "unsupported" if exc.status == "unsupported" else "incomplete"
        if exc.status == "error":
            status = "failed"
        return status, [], [], [str(exc)]
    removed = sorted(
        {finding.name for finding in source.findings if should_remove(finding, profile)}
    )
    preserved = ["Picture and sound payloads"]
    remaining = [finding.name for finding in checked.findings if finding.family != "FILESYSTEM"]
    return "passed", removed, preserved + [f"Remaining: {name}" for name in remaining], []


def clean_file(
    source: Path,
    destination: Path | None,
    profile: Profile,
    *,
    max_file_size: int,
    max_video_size: int = 8 * 1024 * 1024 * 1024,
    dry_run: bool,
    force: bool,
    apply_orientation: bool,
    in_place: bool,
    backup: bool,
) -> CleanResult:
    """Clean one file. The original is replaced only for an explicit in-place clean."""
    if _movie_source(source):
        return _clean_movie(
            source,
            destination,
            profile,
            max_file_size=max_file_size,
            max_video_size=max_video_size,
            dry_run=dry_run,
            force=force,
            apply_orientation=apply_orientation,
            in_place=in_place,
            backup=backup,
        )
    before = source.read_bytes() if source.is_file() and not source.is_symlink() else b""
    inspection = inspect_path(source, max_file_size=max_file_size, max_video_size=max_video_size)
    result = CleanResult(
        source=str(source),
        output=None if destination is None else str(destination),
        profile=profile.name,
        status="failed",
        dry_run=dry_run,
        inspection=inspection,
    )
    if inspection.status in {"error", "unsupported"}:
        result.status = inspection.status
        result.errors.extend(inspection.errors)
        result.limitations.extend(inspection.limitations)
        result.verification = "unsupported"
        return result
    if destination is None:
        result.errors.append("no output path was provided")
        return result
    if source.resolve() == destination.resolve() and not in_place:
        result.errors.append("refusing to overwrite the original without --in-place")
        return result
    if destination.exists() and not force and not in_place:
        result.errors.append("output already exists")
        return result
    cleaned, warnings, limitations, pixels_modified = clean_bytes(
        before,
        inspection,
        profile,
        apply_orientation=apply_orientation,
    )
    result.warnings.extend(warnings)
    result.limitations.extend(limitations)
    result.pixels_modified = pixels_modified
    if cleaned is None:
        result.status = "unsupported"
        result.verification = "unsupported"
        return result
    status, removed, preserved, verify_limits = verify_clean(
        before,
        cleaned,
        inspection,
        profile,
        pixels_modified=pixels_modified,
    )
    result.removed = removed
    result.preserved = [item for item in preserved if not item.startswith("Remaining:")]
    result.limitations.extend(verify_limits)
    result.verification = status
    if status != "passed":
        result.status = "failed" if status == "failed" else status
        result.errors.append("verification did not pass, so no output file was kept")
        return result
    if dry_run:
        result.status = "dry-run"
        result.output = str(destination)
        return result
    try:
        _commit(destination, cleaned, in_place=in_place, backup=backup, original=source)
    except OSError as exc:
        result.status = "failed"
        result.verification = "failed"
        result.errors.append(f"could not write output: {exc.strerror or exc}")
        return result
    if source.read_bytes() != before:
        result.errors.append("the original file changed while cleaning")
        result.status = "failed"
        return result
    result.status = "cleaned"
    result.output = str(destination)
    return result


def _clean_movie(
    source: Path,
    destination: Path | None,
    profile: Profile,
    *,
    max_file_size: int,
    max_video_size: int,
    dry_run: bool,
    force: bool,
    apply_orientation: bool,
    in_place: bool,
    backup: bool,
) -> CleanResult:
    """Stream-copy a supported movie. Photographs do not use this path."""
    inspection = inspect_path(source, max_file_size=max_file_size, max_video_size=max_video_size)
    result = CleanResult(
        source=str(source),
        output=None if destination is None else str(destination),
        profile=profile.name,
        status="failed",
        dry_run=dry_run,
        inspection=inspection,
    )
    if inspection.status == "error":
        result.status = inspection.status
        result.errors.extend(inspection.errors)
        result.limitations.extend(inspection.limitations)
        result.verification = "unsupported"
        return result
    if inspection.format != "bmff":
        result.status = "unsupported"
        result.limitations.append("This format cannot be cleaned.")
        result.verification = "unsupported"
        return result
    if inspection.status == "unsupported" or (
        inspection.status == "incomplete" and not inspection.records
    ):
        result.status = inspection.status
        result.errors.extend(inspection.errors)
        result.limitations.extend(inspection.limitations)
        result.verification = "unsupported"
        return result
    if apply_orientation:
        result.status = "unsupported"
        result.verification = "unsupported"
        result.limitations.append(_MOVIE_ORIENTATION)
        return result
    if destination is None:
        result.errors.append("no output path was provided")
        return result
    if source.resolve() == destination.resolve() and not in_place:
        result.errors.append("refusing to overwrite the original without --in-place")
        return result
    if destination.exists() and not force and not in_place:
        result.errors.append("output already exists")
        return result
    result.warnings.extend(_copyright_warning(inspection, profile))
    remove = removal_fields(inspection, profile)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".metadata-inspector-", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with source.open("rb") as handle:
            watched = os.fstat(handle.fileno()).st_size
            try:
                before_hash = media_hash(source)
                write_clean(source, temporary, remove)
            except BmffError as exc:
                if temporary.exists():
                    temporary.unlink()
                result.verification = "unsupported"
                if exc.status == "error":
                    result.status = "error"
                    result.errors.append(str(exc))
                else:
                    result.status = exc.status
                    result.limitations.append(str(exc))
                return result
            changed = os.fstat(handle.fileno()).st_size != watched
    except OSError as exc:
        if temporary.exists():
            temporary.unlink()
        result.status = "failed"
        result.verification = "failed"
        result.errors.append(f"could not write output: {exc.strerror or exc}")
        return result
    if changed or not _movie_verified(
        source,
        temporary,
        profile,
        remove,
        before_hash,
        max_file_size=max_file_size,
        max_video_size=max_video_size,
    ):
        return _fail_movie_verification(result, temporary)
    result.removed = sorted(
        {finding.name for finding in inspection.findings if should_remove(finding, profile)}
    )
    result.verification = "passed"
    if dry_run:
        temporary.unlink(missing_ok=True)
        result.status = "dry-run"
        result.output = str(destination)
        return result
    try:
        _commit(
            destination,
            b"",
            in_place=in_place,
            backup=backup,
            original=source,
            ready=temporary,
        )
    except OSError as exc:
        if temporary.exists():
            temporary.unlink()
        result.status = "failed"
        result.verification = "failed"
        result.errors.append(f"could not write output: {exc.strerror or exc}")
        return result
    result.status = "cleaned"
    result.output = str(destination)
    result.pixels_modified = False
    return result


def _fail_movie_verification(result: CleanResult, temporary: Path) -> CleanResult:
    if temporary.exists():
        temporary.unlink()
    result.verification = "failed"
    result.status = "failed"
    result.errors.append("verification did not pass, so no output file was kept")
    return result


def _movie_verified(
    source: Path,
    cleaned: Path,
    profile: Profile,
    remove: set[tuple[str, str]],
    before_hash: str,
    *,
    max_file_size: int,
    max_video_size: int,
) -> bool:
    try:
        before = parse_movie(source)
        after = parse_movie(cleaned)
    except BmffError:
        return False
    checked = inspect_path(cleaned, max_file_size=max_file_size, max_video_size=max_video_size)
    if any(_movie_prohibited(finding, profile) for finding in checked.findings):
        return False
    if media_hash(cleaned) != before_hash:
        return False
    if before.duration_seconds != after.duration_seconds:
        return False
    if _display_size(before) != _display_size(after):
        return False
    if _media_codecs(before) != _media_codecs(after):
        return False
    creation_cleared = ("CONTAINER", "CreationTime") not in remove or after.creation == 0
    modification_cleared = (
        "CONTAINER",
        "ModificationTime",
    ) not in remove or after.modification == 0
    return creation_cleared and modification_cleared


def _movie_prohibited(finding: Finding, profile: Profile) -> bool:
    if not should_remove(finding, profile):
        return False
    if finding.family == "CONTAINER" and finding.field in {"CreationTime", "ModificationTime"}:
        return finding.value != _CLEARED_MOVIE_TIME
    return True


def _display_size(movie: Movie) -> tuple[int | None, int | None]:
    video = next((item for item in movie.tracks if item.handler == "vide" and item.enabled), None)
    if video is None:
        return (None, None)
    return (video.width, video.height)


def _media_codecs(movie: Movie) -> tuple[tuple[str, str], ...]:
    return tuple(
        (item.handler, item.codec) for item in movie.tracks if item.handler in {"vide", "soun"}
    )


def _stream_copy(source: Path, destination: Path) -> None:
    with source.open("rb") as src, destination.open("wb") as out:
        while True:
            block = src.read(1024 * 1024)
            if not block:
                break
            out.write(block)
        out.flush()
        os.fsync(out.fileno())


def _commit(
    destination: Path,
    payload: bytes,
    *,
    in_place: bool,
    backup: bool,
    original: Path,
    ready: Path | None = None,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if in_place and backup:
        backup_path = original.with_name(original.name + ".bak")
        if not backup_path.exists():
            if ready is None:
                backup_path.write_bytes(original.read_bytes())
            else:
                _stream_copy(original, backup_path)
    if ready is not None:
        os.replace(ready, destination)
        return
    fd, temporary = tempfile.mkstemp(prefix=".metadata-inspector-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except Exception:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _rewrite(
    data: bytes, image_format: str, fields: set[tuple[str, str]]
) -> tuple[bytes, list[str]]:
    if image_format == "jpeg":
        return rewrite_segments(parse_segments(data), fields)
    if image_format == "png":
        return rewrite_png(data, fields), []
    if image_format == "webp":
        return rewrite_webp(data, fields), []
    if image_format == "tiff":
        return rewrite_tiff(data, fields), []
    raise ValueError("this format cannot be cleaned")


def _read_metadata(
    data: bytes,
    image_format: str,
) -> tuple[list, bytes | None, int, list[str]]:
    if image_format == "jpeg":
        parts = inspect_segments(parse_segments(data))
        return parts.records, parts.thumbnail, parts.icc_bytes, parts.limitations
    if image_format == "png":
        return inspect_png(data)
    if image_format == "webp":
        return inspect_webp(data)
    if image_format == "tiff":
        info = inspect_tiff(data)
        return info.records, None, info.icc_bytes, info.limitations
    if image_format == "heif":
        return inspect_heif(data)
    return [], None, 0, ["This format cannot be inspected."]


def _facts(
    data: bytes,
    image_format: str,
    thumbnail: bytes | None,
    icc_bytes: int,
    mtime: str | None,
) -> ImageFacts:
    facts = ImageFacts(icc=icc_bytes > 0, icc_bytes=icc_bytes, filesystem_mtime=mtime)
    facts.preview = thumbnail is not None
    if thumbnail:
        facts.preview_bytes = len(thumbnail)
    try:
        image = decode_image(data)
    except ImageSafetyError as exc:
        facts.mode = str(exc)
        return facts
    facts.width, facts.height = image.size
    facts.mode = image.mode
    orientation = image.getexif().get(274)
    if isinstance(orientation, int):
        facts.orientation = orientation
    if image_format == "jpeg":
        _ = entropy_payload(data)
    return facts


def _preview_dimensions(thumbnail: bytes, facts: ImageFacts) -> None:
    try:
        image = decode_image(thumbnail)
    except ImageSafetyError:
        return
    facts.preview_width, facts.preview_height = image.size


def _orientation_from_records(records: list[object], facts: ImageFacts) -> None:
    if facts.orientation is not None:
        return
    for record in records:
        field = getattr(record, "field", "")
        interpreted = getattr(record, "interpreted", "")
        if field == "Orientation" and interpreted[:1].isdigit():
            facts.orientation = int(interpreted.split(" ", 1)[0])
            return


def _copyright_warning(inspection: Inspection, profile: Profile) -> list[str]:
    names = [
        finding.name for finding in inspection.findings if _attribution_removed(finding, profile)
    ]
    if not names:
        return []
    return [
        "This profile removes copyright or attribution metadata: "
        + ", ".join(sorted(set(names)))
        + "."
    ]


def _attribution_removed(finding: Finding, profile: Profile) -> bool:
    return should_remove(finding, profile) and finding.id in {
        "exif.artist",
        "exif.copyright",
        "iptc.byline",
        "iptc.copyright",
        "xmp.creator",
        "xmp.rights",
        "text.author",
        "text.copyright",
        "container.artist",
        "container.copyright",
    }


def _read_header(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read(32)


def _video_kind(header: bytes) -> str | None:
    """Return a movie sniff result, leaving HEIC and AVIF on the photograph path."""
    kind = sniff(header)
    if kind not in {"bmff", "unsupported-bmff"}:
        return None
    if detect_format(header) in {"heif", "avif"}:
        return None
    return kind


def _movie_source(path: Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    try:
        header = _read_header(path)
    except OSError:
        return False
    return _video_kind(header) is not None


def _local_mtime(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S (local filesystem time)")


def _inspect_movie(path: Path, mtime: float, kind: str) -> Inspection:
    try:
        movie = parse_movie(path)
    except BmffError as exc:
        inspection = Inspection(
            file=str(path),
            format="bmff" if kind == "bmff" else "unknown",
            status=exc.status,
            backend=BACKEND,
        )
        if exc.status == "error":
            inspection.errors.append(str(exc))
        else:
            inspection.limitations.append(str(exc))
        return inspection
    facts = _movie_facts(movie, _local_mtime(mtime))
    records = list(movie.records)
    return Inspection(
        file=str(path),
        format="bmff",
        status="incomplete" if movie.limitations else "completed",
        backend=BACKEND,
        findings=build_findings(records, facts),
        records=records,
        facts=facts,
        limitations=list(movie.limitations),
    )


def _movie_facts(movie: Movie, mtime: str) -> ImageFacts:
    facts = ImageFacts(filesystem_mtime=mtime, duration_seconds=movie.duration_seconds)
    video = next(
        (item for item in movie.tracks if item.handler == "vide" and item.enabled),
        None,
    )
    if video is not None:
        facts.width = video.width
        facts.height = video.height
        facts.video_codec = video.codec
    tracks: list[dict[str, object]] = []
    for item in movie.tracks:
        if item.handler != "soun":
            continue
        tracks.append(
            {"codec": item.codec, "channels": item.channels, "sample_rate": item.sample_rate}
        )
    facts.audio_tracks = tracks
    if movie.poster is not None:
        facts.preview = True
        facts.preview_bytes = len(movie.poster)
        facts.preview_separate = False
    return facts


def _error(name: str, message: str) -> Inspection:
    return Inspection(
        file=name,
        format="unknown",
        status="error",
        backend=BACKEND,
        errors=[message],
    )
