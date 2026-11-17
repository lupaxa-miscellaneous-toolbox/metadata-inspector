"""TIFF inspection and lossless tag removal by copying compressed strips."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from PIL import TiffTags

from .exifedit import GPS_REFERENCE, records_from_exif, tag_name
from .models import Record

STRUCTURAL = frozenset(
    {
        256,
        257,
        258,
        259,
        262,
        273,
        277,
        278,
        279,
        282,
        283,
        284,
        296,
        317,
        320,
        322,
        323,
        324,
        325,
        338,
        339,
        530,
        531,
        532,
    }
)
EXIF_POINTER = 34665
GPS_POINTER = 34853
ICC_TAG = 34675
ORIENTATION = 274
SUBIFD = 330
STRIP_OFFSETS = 273
STRIP_COUNTS = 279
TILE_OFFSETS = 324
TILE_COUNTS = 325
TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}


class TiffError(ValueError):
    """The TIFF structure cannot be rewritten safely."""


@dataclass
class TiffEntry:
    """One TIFF directory entry."""

    tag: int
    type: int
    count: int
    inline: bytes
    external: bytes | None


@dataclass
class TiffInfo:
    """Metadata read from a TIFF file."""

    records: list[Record]
    icc_bytes: int
    orientation: int | None
    preview: bool
    limitations: list[str]


def inspect_tiff(data: bytes) -> TiffInfo:
    """Read metadata tags from the first TIFF directory."""
    endian, entries, nxt = _open(data)
    limitations: list[str] = []
    if nxt:
        limitations.append("Later TIFF pages are reported only as an embedded preview")
    exif_entries = _subifd(data, entries, EXIF_POINTER, endian)
    gps_entries = _subifd(data, entries, GPS_POINTER, endian)
    exif = {
        "0th": _pie_values(entries, endian, skip_structural=True),
        "Exif": _pie_values(exif_entries, endian, skip_structural=False),
        "GPS": _pie_values(gps_entries, endian, skip_structural=False),
        "Interop": {},
        "1st": {},
        "thumbnail": None,
    }
    records = records_from_exif(exif, "tiff")
    icc = _entry(entries, ICC_TAG)
    icc_bytes = len(icc.external or icc.inline) if icc else 0
    orientation = _short(entries, ORIENTATION, endian)
    preview = bool(nxt) or _entry(entries, SUBIFD) is not None or _entry(entries, 513) is not None
    return TiffInfo(records, icc_bytes, orientation, preview, limitations)


def rewrite_tiff(data: bytes, remove_fields: set[tuple[str, str]]) -> bytes:
    """Copy image strips and write a directory without the removed tags."""
    endian, entries, nxt = _open(data)
    drop_preview = ("THUMBNAIL", "preview") in remove_fields
    if nxt and not drop_preview:
        raise TiffError("this TIFF has extra pages and the profile keeps embedded previews")
    if _entry(entries, SUBIFD) is not None and not drop_preview:
        raise TiffError("this TIFF stores a subimage and the profile keeps embedded previews")
    exif_entries = _filter(_subifd(data, entries, EXIF_POINTER, endian), "exif", remove_fields)
    gps_entries = _filter(_subifd(data, entries, GPS_POINTER, endian), "gps", remove_fields)
    kept = [entry for entry in entries if _keep_main(entry, remove_fields)]
    if exif_entries:
        kept.append(_pointer(EXIF_POINTER))
    if gps_entries:
        kept.append(_pointer(GPS_POINTER))
    kept.sort(key=lambda entry: entry.tag)
    for entry in kept:
        if entry.tag in {STRIP_OFFSETS, TILE_OFFSETS} and entry.type != 4:
            entry.type = 4
    strips, counts = _image_payloads(data, entries, endian)
    return _assemble(endian, kept, exif_entries, gps_entries, strips, counts)


def _open(data: bytes) -> tuple[str, list[TiffEntry], int]:
    if data.startswith(b"II*\x00"):
        endian = "<"
    elif data.startswith(b"MM\x00*"):
        endian = ">"
    else:
        raise TiffError("only classic TIFF files can be rewritten")
    offset = struct.unpack_from(endian + "I", data, 4)[0]
    entries, nxt = _read_ifd(data, offset, endian)
    return endian, entries, nxt


def _read_ifd(data: bytes, offset: int, endian: str) -> tuple[list[TiffEntry], int]:
    if offset <= 0 or offset + 2 > len(data):
        raise TiffError("TIFF directory offset is outside the file")
    count = struct.unpack_from(endian + "H", data, offset)[0]
    if count > 4096 or offset + 2 + count * 12 + 4 > len(data):
        raise TiffError("TIFF directory is truncated or too large")
    entries: list[TiffEntry] = []
    pos = offset + 2
    for _ in range(count):
        tag, kind, number, value = struct.unpack_from(endian + "HHII", data, pos)
        size = TYPE_SIZE.get(kind)
        if size is None:
            raise TiffError(f"TIFF type {kind} is not supported")
        nbytes = size * number
        if nbytes > 64 * 1024 * 1024:
            raise TiffError("TIFF metadata value exceeds the size limit")
        inline = data[pos + 8 : pos + 12]
        external = None
        if nbytes > 4:
            if value <= 0 or value + nbytes > len(data):
                raise TiffError("TIFF value points outside the file")
            external = data[value : value + nbytes]
        entries.append(TiffEntry(tag, kind, number, inline, external))
        del value
        pos += 12
    nxt = struct.unpack_from(endian + "I", data, pos)[0]
    return entries, nxt


def _subifd(data: bytes, entries: list[TiffEntry], tag: int, endian: str) -> list[TiffEntry]:
    entry = _entry(entries, tag)
    if entry is None:
        return []
    offset = struct.unpack(endian + "I", entry.inline)[0]
    found, _nxt = _read_ifd(data, offset, endian)
    return found


def _keep_main(entry: TiffEntry, remove_fields: set[tuple[str, str]]) -> bool:
    if entry.tag in {EXIF_POINTER, GPS_POINTER, SUBIFD}:
        return False
    if entry.tag in STRUCTURAL:
        return True
    if entry.tag == ORIENTATION:
        return ("EXIF", "Orientation") not in remove_fields
    if entry.tag == ICC_TAG:
        return ("ICC", "profile") not in remove_fields
    name = _main_name(entry.tag)
    return ("EXIF", name) not in remove_fields


def _filter(
    entries: list[TiffEntry], kind: str, remove_fields: set[tuple[str, str]]
) -> list[TiffEntry]:
    family = "GPS" if kind == "gps" else "EXIF"
    ifd = "GPS" if kind == "gps" else "Exif"
    kept: list[TiffEntry] = []
    for entry in entries:
        name = tag_name(ifd, entry.tag)
        if (family, name) in remove_fields:
            continue
        if kind == "gps" and _gps_reference_removed(name, remove_fields):
            continue
        kept.append(entry)
    return kept


def _gps_reference_removed(name: str, remove_fields: set[tuple[str, str]]) -> bool:
    for coordinate, reference in GPS_REFERENCE.items():
        if reference == name and ("GPS", coordinate) in remove_fields:
            return True
    return False


def _image_payloads(
    data: bytes, entries: list[TiffEntry], endian: str
) -> tuple[list[bytes], list[int]]:
    offsets = _entry(entries, STRIP_OFFSETS)
    counts = _entry(entries, STRIP_COUNTS)
    if offsets is None or counts is None:
        offsets = _entry(entries, TILE_OFFSETS)
        counts = _entry(entries, TILE_COUNTS)
    if offsets is None or counts is None:
        raise TiffError("TIFF image data is not stored in strips or tiles")
    offset_values = _integers(offsets, endian)
    count_values = _integers(counts, endian)
    if len(offset_values) != len(count_values) or not offset_values:
        raise TiffError("TIFF strip offsets do not match the strip lengths")
    blobs: list[bytes] = []
    for offset, count in zip(offset_values, count_values, strict=True):
        if count < 0 or offset < 0 or offset + count > len(data):
            raise TiffError("TIFF strip points outside the file")
        blobs.append(data[offset : offset + count])
    return blobs, count_values


def _assemble(
    endian: str,
    main: list[TiffEntry],
    exif_entries: list[TiffEntry],
    gps_entries: list[TiffEntry],
    strips: list[bytes],
    counts: list[int],
) -> bytes:
    out = bytearray(b"II*\x00\x08\x00\x00\x00" if endian == "<" else b"MM\x00*\x00\x00\x00\x08")
    strip_entry = _entry(main, STRIP_OFFSETS) or _entry(main, TILE_OFFSETS)
    if strip_entry is None:
        raise TiffError("TIFF image offsets were lost while rewriting")
    ifd_at = len(out)
    if ifd_at != 8:
        raise TiffError("TIFF header layout was not 8 bytes")
    out += struct.pack(endian + "H", len(main))
    patches: list[tuple[TiffEntry, int]] = []
    for entry in main:
        out += struct.pack(endian + "HHI", entry.tag, entry.type, entry.count)
        patches.append((entry, len(out)))
        out += b"\x00\x00\x00\x00"
    out += struct.pack(endian + "I", 0)
    subifd_at: dict[int, int] = {}
    for entry, at in patches:
        if entry.tag == EXIF_POINTER:
            subifd_at[entry.tag] = _write_ifd(out, exif_entries, endian)
            struct.pack_into(endian + "I", out, at, subifd_at[entry.tag])
        elif entry.tag == GPS_POINTER:
            subifd_at[entry.tag] = _write_ifd(out, gps_entries, endian)
            struct.pack_into(endian + "I", out, at, subifd_at[entry.tag])
        elif entry.tag in {STRIP_OFFSETS, TILE_OFFSETS}:
            continue
        elif entry.external is None:
            out[at : at + 4] = entry.inline
        else:
            struct.pack_into(endian + "I", out, at, _append(out, entry.external))
    written: list[int] = []
    for blob in strips:
        written.append(_append(out, blob))
    _write_offsets(out, patches, strip_entry.tag, written, endian)
    return bytes(out)


def _write_ifd(out: bytearray, entries: list[TiffEntry], endian: str) -> int:
    if len(out) % 2:
        out.append(0)
    start = len(out)
    out += struct.pack(endian + "H", len(entries))
    patches: list[tuple[TiffEntry, int]] = []
    for entry in entries:
        out += struct.pack(endian + "HHI", entry.tag, entry.type, entry.count)
        patches.append((entry, len(out)))
        out += b"\x00\x00\x00\x00"
    out += struct.pack(endian + "I", 0)
    for entry, at in patches:
        if entry.external is None:
            out[at : at + 4] = entry.inline
        else:
            struct.pack_into(endian + "I", out, at, _append(out, entry.external))
    return start


def _write_offsets(
    out: bytearray,
    patches: list[tuple[TiffEntry, int]],
    tag: int,
    offsets: list[int],
    endian: str,
) -> None:
    for entry, at in patches:
        if entry.tag != tag:
            continue
        if entry.count == 1:
            struct.pack_into(endian + "I", out, at, offsets[0])
            return
        array = b"".join(struct.pack(endian + "I", offset) for offset in offsets)
        struct.pack_into(endian + "I", out, at, _append(out, array))
        return
    raise TiffError("TIFF strip offset tag was not written")


def _append(out: bytearray, payload: bytes) -> int:
    if len(out) % 2:
        out.append(0)
    offset = len(out)
    out += payload
    return offset


def _pointer(tag: int) -> TiffEntry:
    return TiffEntry(tag, 4, 1, b"\x00\x00\x00\x00", None)


def _entry(entries: list[TiffEntry], tag: int) -> TiffEntry | None:
    for entry in entries:
        if entry.tag == tag:
            return entry
    return None


def _integers(entry: TiffEntry, endian: str) -> list[int]:
    if entry.type not in {3, 4}:
        raise TiffError("TIFF offsets must be short or long integers")
    fmt = "H" if entry.type == 3 else "I"
    size = 2 if entry.type == 3 else 4
    if entry.count == 1 and entry.external is None:
        return [struct.unpack(endian + fmt, entry.inline[:size])[0]]
    blob = entry.external or b""
    if len(blob) < entry.count * size:
        raise TiffError("TIFF offset array is truncated")
    return [struct.unpack_from(endian + fmt, blob, index * size)[0] for index in range(entry.count)]


def _short(entries: list[TiffEntry], tag: int, endian: str) -> int | None:
    entry = _entry(entries, tag)
    if entry is None or entry.type != 3:
        return None
    value: int = struct.unpack(endian + "H", entry.inline[:2])[0]
    return value


def _main_name(tag: int) -> str:
    info = TiffTags.TAGS_V2.get(tag)
    if info is None:
        return str(tag)
    return str(info.name)


def _pie_values(
    entries: list[TiffEntry],
    endian: str,
    *,
    skip_structural: bool,
) -> dict[int, object]:
    values: dict[int, object] = {}
    for entry in entries:
        if skip_structural and entry.tag in STRUCTURAL.union({EXIF_POINTER, GPS_POINTER, SUBIFD}):
            continue
        decoded = _decode(entry, endian)
        if decoded is None:
            continue
        values[entry.tag] = decoded
    return values


def _decode(entry: TiffEntry, endian: str) -> object | None:
    size = TYPE_SIZE[entry.type]
    blob = entry.inline if entry.external is None else entry.external
    if entry.type in {2, 1, 7}:
        raw = blob if entry.external is not None else blob[: entry.count]
        return raw.split(b"\x00", 1)[0] if entry.type == 2 else raw
    if entry.type == 3 and entry.count == 1:
        short: int = struct.unpack(endian + "H", entry.inline[:2])[0]
        return short
    if entry.type == 4 and entry.count == 1:
        long: int = struct.unpack(endian + "I", entry.inline)[0]
        return long
    if entry.type in {5, 10} and entry.external:
        fmt = "I" if entry.type == 5 else "i"
        values = []
        for index in range(entry.count):
            number, denom = struct.unpack_from(endian + fmt + fmt, entry.external, index * 8)
            values.append((number, denom))
        if len(values) == 1:
            return values[0]
        return tuple(values)
    if entry.external is not None and size * entry.count == len(entry.external):
        return entry.external
    return None
