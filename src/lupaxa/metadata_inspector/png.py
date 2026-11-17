"""PNG chunk inspection and metadata removal without recompressing pixels."""

from __future__ import annotations

import struct
import zlib

from .exifedit import ExifError, load_exif, records_from_exif, rewrite_exif, thumbnail_bytes
from .models import Record
from .sanitize import as_text

SIGNATURE = b"\x89PNG\r\n\x1a\n"
TEXT_CHUNKS = {b"tEXt", b"zTXt", b"iTXt"}


class PngError(ValueError):
    """The PNG structure cannot be used safely."""


def inspect_png(data: bytes) -> tuple[list[Record], bytes | None, int, list[str]]:
    """Return records, a preview, the ICC size, and limitations."""
    records: list[Record] = []
    limitations: list[str] = []
    thumbnail: bytes | None = None
    icc_bytes = 0
    for kind, payload in _chunks(data):
        if kind == b"tEXt":
            records.extend(_text_chunk(payload))
        elif kind == b"zTXt":
            records.extend(_compressed_text(payload))
        elif kind == b"iTXt":
            records.extend(_international_text(payload))
        elif kind == b"eXIf":
            try:
                exif = load_exif(payload)
            except ExifError:
                limitations.append("PNG EXIF metadata could not be parsed")
                continue
            records.extend(records_from_exif(exif, "png-exif"))
            thumbnail = thumbnail_bytes(exif) or thumbnail
        elif kind == b"iCCP":
            icc_bytes += len(payload)
    return records, thumbnail, icc_bytes, limitations


def rewrite_png(data: bytes, remove_fields: set[tuple[str, str]]) -> bytes:
    """Drop or rewrite metadata chunks and copy image chunks unchanged."""
    output = bytearray(SIGNATURE)
    for kind, payload in _chunks(data):
        if kind in TEXT_CHUNKS:
            keyword = _keyword(kind, payload)
            if keyword and ("TEXT", keyword) in remove_fields:
                continue
            output.extend(_chunk(kind, payload))
            continue
        if kind == b"eXIf":
            try:
                rewritten = rewrite_exif(load_exif(payload), remove_fields)
            except ExifError as exc:
                raise PngError(str(exc)) from exc
            if rewritten is None:
                continue
            raw = rewritten[6:] if rewritten.startswith(b"Exif\x00\x00") else rewritten
            output.extend(_chunk(kind, raw))
            continue
        if kind == b"iCCP" and ("ICC", "profile") in remove_fields:
            continue
        output.extend(_chunk(kind, payload))
    return bytes(output)


def _chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    if not data.startswith(SIGNATURE):
        raise PngError("not a PNG file")
    index = len(SIGNATURE)
    chunks: list[tuple[bytes, bytes]] = []
    while index + 12 <= len(data):
        length = struct.unpack_from(">I", data, index)[0]
        kind = data[index + 4 : index + 8]
        if length > len(data) - index - 12:
            raise PngError("PNG chunk length is invalid")
        payload = data[index + 8 : index + 8 + length]
        expected = struct.unpack_from(">I", data, index + 8 + length)[0]
        actual = zlib.crc32(kind + payload) & 0xFFFFFFFF
        if expected != actual:
            raise PngError(f"PNG chunk {kind.decode('ascii', 'replace')} has a bad checksum")
        chunks.append((kind, payload))
        index += 12 + length
        if kind == b"IEND":
            return chunks
    raise PngError("PNG file has no end chunk")


def _chunk(kind: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)


def _keyword(kind: bytes, payload: bytes) -> str:
    if kind == b"tEXt":
        return as_text(payload.split(b"\x00", 1)[0])[0]
    if kind == b"zTXt":
        return as_text(payload.split(b"\x00", 1)[0])[0]
    if kind == b"iTXt":
        return as_text(payload.split(b"\x00", 1)[0])[0]
    return ""


def _text_chunk(payload: bytes) -> list[Record]:
    if b"\x00" not in payload:
        return []
    key, value = payload.split(b"\x00", 1)
    keyword, _binary = as_text(key)
    text, binary = as_text(value)
    if not keyword:
        return []
    return [Record("TEXT", keyword, keyword, text, text, "png-text", binary)]


def _compressed_text(payload: bytes) -> list[Record]:
    if b"\x00" not in payload:
        return []
    key, rest = payload.split(b"\x00", 1)
    if len(rest) < 2:
        return []
    try:
        value = zlib.decompress(rest[1:])
    except zlib.error as exc:
        raise PngError("compressed PNG text could not be read") from exc
    keyword, _binary = as_text(key)
    text, binary = as_text(value)
    return [Record("TEXT", keyword, keyword, text, text, "png-text", binary)]


def _international_text(payload: bytes) -> list[Record]:
    parts = payload.split(b"\x00")
    if len(parts) < 5:
        return []
    keyword, _binary = as_text(parts[0])
    text, binary = as_text(parts[-1])
    if not keyword:
        return []
    return [Record("TEXT", keyword, keyword, text, text, "png-text", binary)]
