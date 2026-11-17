"""Read and selectively edit XMP packets without loading external entities."""

from __future__ import annotations

from typing import cast

import defusedxml.ElementTree as ET

from .models import Record
from .sanitize import sanitise

MAX_XMP_BYTES = 2 * 1024 * 1024
XMP_PREFIX = b"http://ns.adobe.com/xap/1.0/\x00"


class XmpError(ValueError):
    """XMP could not be read safely."""


def xmp_payload(segment: bytes) -> bytes | None:
    """Return the XMP packet inside an APP1 segment, if this segment is XMP."""
    if segment.startswith(XMP_PREFIX):
        return segment[len(XMP_PREFIX) :]
    if b"<x:xmpmeta" in segment[:200] or b"<?xpacket" in segment[:200]:
        return segment
    return None


def read_xmp(packet: bytes) -> list[Record]:
    """Read XMP fields. External entities and oversized packets are rejected."""
    if len(packet) > MAX_XMP_BYTES:
        raise XmpError("XMP packet exceeds the size limit")
    lowered = packet.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise XmpError("XMP packet contains a forbidden declaration")
    start = packet.find(b"<")
    if start < 0:
        raise XmpError("XMP packet has no XML")
    try:
        root = ET.fromstring(packet[start:])
    except ET.ParseError as exc:
        raise XmpError("XMP packet is not well-formed XML") from exc
    records: list[Record] = []
    for element in root.iter():
        if _local(element.tag) != "Description":
            continue
        for name, raw in element.attrib.items():
            field = _local(name)
            if field in {"about"}:
                continue
            text = sanitise(raw)
            if text:
                records.append(_record(field, text))
        for child in list(element):
            field = _local(child.tag)
            text = sanitise(" ".join(part.strip() for part in child.itertext() if part.strip()))
            if text:
                records.append(_record(field, text))
    return records


def rewrite_xmp(packet: bytes, remove_fields: set[str]) -> bytes | None:
    """Remove named XMP fields. Return None when nothing remains to keep."""
    if not remove_fields:
        return packet
    if len(packet) > MAX_XMP_BYTES or b"<!doctype" in packet.lower():
        raise XmpError("XMP packet cannot be edited safely")
    start = packet.find(b"<")
    if start < 0:
        raise XmpError("XMP packet has no XML")
    try:
        root = ET.fromstring(packet[start:])
    except ET.ParseError as exc:
        raise XmpError("XMP packet is not well-formed XML") from exc
    for element in root.iter():
        if _local(element.tag) != "Description":
            continue
        for name in list(element.attrib):
            if _local(name) in remove_fields:
                del element.attrib[name]
        for child in list(element):
            if _local(child.tag) in remove_fields:
                element.remove(child)
    remaining = read_xmp(ET.tostring(root, encoding="utf-8"))
    if not remaining:
        return None
    body = cast(bytes, ET.tostring(root, encoding="utf-8", xml_declaration=False))
    return (
        b'<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
        + body
        + b'\n<?xpacket end="w"?>'
    )


def _record(field: str, text: str) -> Record:
    return Record("XMP", field, field, text, text, "xmp")


def _local(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    if ":" in tag:
        return tag.split(":", 1)[1]
    return tag
