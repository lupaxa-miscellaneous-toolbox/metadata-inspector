"""WebP chunk inspection and metadata removal without recompressing frames."""

from __future__ import annotations

import struct

from .exifedit import ExifError, load_exif, records_from_exif, rewrite_exif, thumbnail_bytes
from .models import Record
from .xmp import XmpError, read_xmp, rewrite_xmp

EXIF_FLAG = 0x08
XMP_FLAG = 0x04
ICC_FLAG = 0x20


class WebpError(ValueError):
    """The WebP structure cannot be used safely."""


def inspect_webp(data: bytes) -> tuple[list[Record], bytes | None, int, list[str]]:
    """Return records, a preview, the ICC size, and limitations."""
    records: list[Record] = []
    limitations: list[str] = []
    thumbnail: bytes | None = None
    icc_bytes = 0
    for fourcc, payload in _chunks(data):
        if fourcc == b"EXIF":
            try:
                exif = load_exif(payload)
            except ExifError:
                limitations.append("WebP EXIF metadata could not be parsed")
                continue
            records.extend(records_from_exif(exif, "webp-exif"))
            thumbnail = thumbnail_bytes(exif) or thumbnail
        elif fourcc == b"XMP ":
            try:
                records.extend(read_xmp(payload))
            except XmpError as exc:
                limitations.append(str(exc))
        elif fourcc == b"ICCP":
            icc_bytes += len(payload)
    return records, thumbnail, icc_bytes, limitations


def rewrite_webp(data: bytes, remove_fields: set[tuple[str, str]]) -> bytes:
    """Drop or rewrite EXIF, XMP, and ICC chunks. Frame chunks are copied."""
    chunks = _chunks(data)
    rebuilt: list[tuple[bytes, bytes]] = []
    for fourcc, payload in chunks:
        if fourcc == b"EXIF":
            try:
                rewritten = rewrite_exif(load_exif(payload), remove_fields)
            except ExifError as exc:
                raise WebpError(str(exc)) from exc
            if rewritten is None:
                continue
            rebuilt.append((fourcc, rewritten))
            continue
        if fourcc == b"XMP ":
            fields = {field for family, field in remove_fields if family == "XMP"}
            if not fields:
                rebuilt.append((fourcc, payload))
                continue
            try:
                packet = rewrite_xmp(payload, fields)
            except XmpError:
                continue
            if packet is not None:
                rebuilt.append((fourcc, packet))
            continue
        if fourcc == b"ICCP" and ("ICC", "profile") in remove_fields:
            continue
        rebuilt.append((fourcc, payload))
    present = {fourcc for fourcc, _payload in rebuilt}
    output_chunks: list[tuple[bytes, bytes]] = []
    for fourcc, payload in rebuilt:
        if fourcc == b"VP8X":
            payload = _flags(payload, present)
        output_chunks.append((fourcc, payload))
    body = b"".join(_encode(fourcc, payload) for fourcc, payload in output_chunks)
    return b"RIFF" + struct.pack("<I", len(body) + 4) + b"WEBP" + body


def _flags(payload: bytes, present: set[bytes] | None) -> bytes:
    if len(payload) < 1:
        raise WebpError("VP8X chunk is truncated")
    if present is None:
        return payload
    flags = payload[0]
    if b"EXIF" not in present:
        flags &= ~EXIF_FLAG
    if b"XMP " not in present:
        flags &= ~XMP_FLAG
    if b"ICCP" not in present:
        flags &= ~ICC_FLAG
    return bytes((flags,)) + payload[1:]


def _chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    if not (data.startswith(b"RIFF") and data[8:12] == b"WEBP"):
        raise WebpError("not a WebP file")
    index = 12
    chunks: list[tuple[bytes, bytes]] = []
    while index + 8 <= len(data):
        fourcc = data[index : index + 4]
        size = struct.unpack_from("<I", data, index + 4)[0]
        start = index + 8
        if size > len(data) - start:
            raise WebpError("WebP chunk length is invalid")
        chunks.append((fourcc, data[start : start + size]))
        index = start + size + (size & 1)
    return chunks


def _encode(fourcc: bytes, payload: bytes) -> bytes:
    pad = b"\x00" if len(payload) & 1 else b""
    return fourcc + struct.pack("<I", len(payload)) + payload + pad
