"""Lossless JPEG segment inspection and metadata rewriting."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .exifedit import ExifError, load_exif, records_from_exif, rewrite_exif, thumbnail_bytes
from .iptc import IptcError, read_iptc, rewrite_iptc
from .models import Record
from .xmp import XmpError, read_xmp, rewrite_xmp, xmp_payload

APP1 = 0xE1
APP2 = 0xE2
APP13 = 0xED
SOS = 0xDA
EOI = 0xD9
ICC_PREFIX = b"ICC_PROFILE\x00"


class JpegError(ValueError):
    """The JPEG structure cannot be used safely."""


@dataclass(frozen=True)
class Segment:
    """One JPEG marker and its payload."""

    marker: int
    payload: bytes


@dataclass
class JpegParts:
    """Metadata extracted from JPEG segments."""

    records: list[Record]
    thumbnail: bytes | None
    icc_bytes: int
    limitations: list[str]


def parse_segments(data: bytes) -> list[Segment]:
    """Split a JPEG into markers. Entropy-coded data stays attached to SOS."""
    if not data.startswith(b"\xff\xd8"):
        raise JpegError("not a JPEG file")
    segments: list[Segment] = [Segment(0xD8, b"")]
    index = 2
    while index < len(data):
        if data[index] != 0xFF:
            raise JpegError("JPEG marker was expected")
        while index < len(data) and data[index] == 0xFF:
            index += 1
        if index >= len(data):
            break
        marker = data[index]
        index += 1
        if marker == EOI:
            segments.append(Segment(EOI, b""))
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            segments.append(Segment(marker, b""))
            continue
        if index + 2 > len(data):
            raise JpegError("truncated JPEG segment")
        length = struct.unpack_from(">H", data, index)[0]
        if length < 2 or index + length > len(data):
            raise JpegError("JPEG segment length is invalid")
        payload = data[index + 2 : index + length]
        if marker == SOS:
            entropy_end = _entropy_end(data, index + length)
            segments.append(Segment(marker, data[index - 2 : entropy_end]))
            segments.append(Segment(EOI, b""))
            break
        segments.append(Segment(marker, payload))
        index += length
    if not segments or segments[-1].marker != EOI:
        raise JpegError("JPEG file has no end-of-image marker")
    return segments


def inspect_segments(segments: list[Segment]) -> JpegParts:
    """Read EXIF, IPTC, XMP, ICC, and preview metadata from JPEG segments."""
    records: list[Record] = []
    limitations: list[str] = []
    thumbnail: bytes | None = None
    icc_bytes = 0
    for segment in segments:
        if segment.marker == APP1 and segment.payload.startswith(b"Exif\x00\x00"):
            try:
                exif = load_exif(segment.payload)
            except ExifError:
                limitations.append("EXIF metadata could not be parsed")
                continue
            records.extend(records_from_exif(exif, "jpeg-exif"))
            thumbnail = thumbnail_bytes(exif) or thumbnail
        elif segment.marker == APP1 and xmp_payload(segment.payload) is not None:
            packet = xmp_payload(segment.payload) or b""
            try:
                records.extend(read_xmp(packet))
            except XmpError as exc:
                limitations.append(str(exc))
        elif segment.marker == APP13:
            try:
                records.extend(read_iptc(segment.payload))
            except IptcError as exc:
                limitations.append(str(exc))
        elif segment.marker == APP2 and segment.payload.startswith(ICC_PREFIX):
            icc_bytes += max(0, len(segment.payload) - len(ICC_PREFIX) - 2)
    return JpegParts(records, thumbnail, icc_bytes, limitations)


def rewrite_segments(
    segments: list[Segment],
    remove_fields: set[tuple[str, str]],
) -> tuple[bytes, list[str]]:
    """Rewrite metadata segments and return JPEG bytes plus warnings."""
    warnings: list[str] = []
    output: list[bytes] = [b"\xff\xd8"]
    for segment in segments:
        if segment.marker in {0xD8, EOI}:
            continue
        if segment.marker == SOS:
            output.append(segment.payload)
            continue
        replacement = _rewrite_segment(segment, remove_fields, warnings)
        if replacement is None:
            continue
        output.append(_marker(segment.marker, replacement))
    output.append(b"\xff\xd9")
    return b"".join(output), warnings


def entropy_payload(data: bytes) -> bytes:
    """Return the SOS payload, which holds the compressed image data."""
    for segment in parse_segments(data):
        if segment.marker == SOS:
            return segment.payload
    return b""


def _rewrite_segment(
    segment: Segment,
    remove_fields: set[tuple[str, str]],
    warnings: list[str],
) -> bytes | None:
    if segment.marker == APP1 and segment.payload.startswith(b"Exif\x00\x00"):
        try:
            return rewrite_exif(load_exif(segment.payload), remove_fields)
        except ExifError as exc:
            raise JpegError(str(exc)) from exc
    if segment.marker == APP1 and xmp_payload(segment.payload) is not None:
        packet = xmp_payload(segment.payload) or b""
        fields = {field for family, field in remove_fields if family == "XMP"}
        if not fields:
            return segment.payload
        try:
            rewritten = rewrite_xmp(packet, fields)
        except XmpError:
            warnings.append("XMP could not be edited field by field, so the XMP packet was removed")
            return None
        if rewritten is None:
            return None
        return b"http://ns.adobe.com/xap/1.0/\x00" + rewritten
    if segment.marker == APP13:
        fields = {field for family, field in remove_fields if family == "IPTC"}
        drop_thumbnail = ("THUMBNAIL", "preview") in remove_fields
        if not fields and not drop_thumbnail:
            return segment.payload
        try:
            return rewrite_iptc(segment.payload, fields, drop_thumbnail=drop_thumbnail)
        except IptcError:
            warnings.append(
                "IPTC could not be edited field by field, so the IPTC segment was removed"
            )
            return None
    if segment.marker == APP2 and segment.payload.startswith(ICC_PREFIX):
        if ("ICC", "profile") in remove_fields:
            return None
        return segment.payload
    return segment.payload


def _marker(marker: int, payload: bytes) -> bytes:
    if marker == SOS:
        return b"\xff\xda" + payload
    return b"\xff" + bytes((marker,)) + struct.pack(">H", len(payload) + 2) + payload


def _entropy_end(data: bytes, start: int) -> int:
    index = start
    while index < len(data) - 1:
        if data[index] != 0xFF:
            index += 1
            continue
        nxt = data[index + 1]
        if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:
            index += 2
            continue
        if nxt == 0xFF:
            index += 1
            continue
        if nxt == EOI:
            return index
        index += 2
    raise JpegError("JPEG compressed data has no end-of-image marker")
