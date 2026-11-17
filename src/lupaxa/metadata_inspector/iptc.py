"""Read and rewrite IPTC-IIM datasets stored in a JPEG APP13 segment."""

from __future__ import annotations

import struct

from .models import Record
from .sanitize import as_text

PHOTOSHOP = b"Photoshop 3.0\x00"
IPTC_RESOURCE = 0x0404
THUMBNAIL_RESOURCES = {0x0409, 0x040C}
DATASETS = {
    (2, 5): "ObjectName",
    (2, 25): "Keywords",
    (2, 55): "DateCreated",
    (2, 60): "TimeCreated",
    (2, 80): "By-line",
    (2, 85): "By-lineTitle",
    (2, 90): "City",
    (2, 92): "Sub-location",
    (2, 95): "Province-State",
    (2, 101): "Country-PrimaryLocationName",
    (2, 105): "Headline",
    (2, 110): "Credit",
    (2, 115): "Source",
    (2, 116): "CopyrightNotice",
    (2, 118): "Contact",
    (2, 120): "Caption-Abstract",
    (2, 122): "Writer-Editor",
}


class IptcError(ValueError):
    """IPTC data could not be read."""


def read_iptc(segment: bytes) -> list[Record]:
    """Read IPTC datasets from an APP13 payload."""
    records: list[Record] = []
    for resource_id, data in _resources(segment):
        if resource_id != IPTC_RESOURCE:
            if resource_id in THUMBNAIL_RESOURCES:
                records.append(
                    Record(
                        "THUMBNAIL",
                        "preview",
                        f"8BIM-{resource_id}",
                        f"{len(data)} bytes",
                        f"{len(data)} bytes",
                        "iptc-thumbnail",
                        binary=True,
                    )
                )
            continue
        records.extend(_datasets(data))
    return records


def rewrite_iptc(segment: bytes, remove_fields: set[str], *, drop_thumbnail: bool) -> bytes | None:
    """Return a new APP13 payload, or None when the segment should be dropped."""
    kept: list[tuple[int, bytes]] = []
    for resource_id, data in _resources(segment):
        if resource_id in THUMBNAIL_RESOURCES and drop_thumbnail:
            continue
        if resource_id == IPTC_RESOURCE:
            data = _filter_datasets(data, remove_fields)
            if not data:
                continue
        kept.append((resource_id, data))
    if not kept:
        return None
    return PHOTOSHOP + b"".join(_encode_resource(resource_id, data) for resource_id, data in kept)


def _datasets(data: bytes) -> list[Record]:
    records: list[Record] = []
    for record_no, dataset, payload in _iter_datasets(data):
        name = DATASETS.get((record_no, dataset), f"{record_no}:{dataset}")
        text, binary = as_text(payload)
        records.append(Record("IPTC", name, f"{record_no}:{dataset}", text, text, "iptc", binary))
    return records


def _filter_datasets(data: bytes, remove_fields: set[str]) -> bytes:
    parts: list[bytes] = []
    for record_no, dataset, payload in _iter_datasets(data):
        name = DATASETS.get((record_no, dataset), f"{record_no}:{dataset}")
        if name in remove_fields:
            continue
        parts.append(_encode_dataset(record_no, dataset, payload))
    return b"".join(parts)


def _iter_datasets(data: bytes) -> list[tuple[int, int, bytes]]:
    found: list[tuple[int, int, bytes]] = []
    index = 0
    while index + 5 <= len(data):
        if data[index] != 0x1C:
            break
        record_no = data[index + 1]
        dataset = data[index + 2]
        length = struct.unpack_from(">H", data, index + 3)[0]
        index += 5
        if length & 0x8000:
            if index + 4 > len(data):
                raise IptcError("truncated IPTC dataset")
            length = struct.unpack_from(">I", data, index)[0]
            index += 4
        if length > len(data) - index or length > 2 * 1024 * 1024:
            raise IptcError("IPTC dataset exceeds the size limit")
        found.append((record_no, dataset, data[index : index + length]))
        index += length
    return found


def _encode_dataset(record_no: int, dataset: int, payload: bytes) -> bytes:
    if len(payload) >= 32768:
        raise IptcError("IPTC dataset is too large to rewrite")
    return bytes((0x1C, record_no, dataset)) + struct.pack(">H", len(payload)) + payload


def _resources(segment: bytes) -> list[tuple[int, bytes]]:
    if not segment.startswith(PHOTOSHOP):
        raise IptcError("APP13 segment is not Photoshop IPTC")
    index = len(PHOTOSHOP)
    resources: list[tuple[int, bytes]] = []
    while index + 8 <= len(segment):
        if segment[index : index + 4] != b"8BIM":
            break
        resource_id = struct.unpack_from(">H", segment, index + 4)[0]
        name_len = segment[index + 6]
        name_field = 1 + name_len
        if name_field % 2:
            name_field += 1
        size_at = index + 6 + name_field
        if size_at + 4 > len(segment):
            raise IptcError("truncated Photoshop resource")
        size = struct.unpack_from(">I", segment, size_at)[0]
        data_at = size_at + 4
        if size > len(segment) - data_at:
            raise IptcError("Photoshop resource exceeds the segment")
        resources.append((resource_id, segment[data_at : data_at + size]))
        index = data_at + size + (size % 2)
    return resources


def _encode_resource(resource_id: int, data: bytes) -> bytes:
    padded = data + (b"\x00" if len(data) % 2 else b"")
    return (
        b"8BIM"
        + struct.pack(">H", resource_id)
        + b"\x00\x00"
        + struct.pack(">I", len(data))
        + padded
    )
