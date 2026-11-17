"""Read and rewrite ISO BMFF metadata without loading media into memory."""

from __future__ import annotations

import hashlib
import os
import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import BinaryIO

from .exifedit import ExifError, load_exif, records_from_exif, rewrite_exif
from .jpeg import JpegError, inspect_segments, parse_segments
from .models import Record
from .sanitize import safe_binary
from .xmp import XmpError, read_xmp, rewrite_xmp

MAX_MOOV_BYTES = 32 * 1024 * 1024
SUPPORTED_BRANDS = frozenset(
    {
        b"qt  ",
        b"mp41",
        b"mp42",
        b"isom",
        b"iso2",
        b"avc1",
        b"M4V ",
        b"3gp4",
        b"3gp5",
        b"3gp6",
        b"3gp7",
        b"3ge6",
        b"3gg6",
    }
)
_FRAGMENTED = frozenset({b"iso5", b"iso6", b"dash", b"msdh"})
_QT_EPOCH = datetime(1904, 1, 1, tzinfo=UTC)
_ISO6709 = re.compile(r"([-+]\d+(?:\.\d+)?)([-+]\d+(?:\.\d+)?)")
_LOCATION_KEY = "com.apple.quicktime.location.ISO6709"
_SERIAL_SUFFIXES = ("serialnumber", "uniqueid", "serial")
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_EXIF_PREFIXES = (b"Exif\x00\x00", b"II*\x00", b"MM\x00*")
_UDTA_TEXT = {
    b"\xa9mak": "Make",
    b"\xa9mod": "Model",
    b"\xa9swr": "Software",
    b"\xa9day": "CreationTime",
    b"\xa9nam": "Title",
    b"\xa9des": "Description",
    b"\xa9cmt": "Comment",
    b"\xa9ART": "Artist",
    b"\xa9cpy": "Copyright",
}
_ILST_TEXT = {
    "com.apple.quicktime.make": "Make",
    "com.apple.quicktime.model": "Model",
    "com.apple.quicktime.software": "Software",
    "com.apple.quicktime.creationdate": "CreationTime",
}
_MEDIA_HANDLERS = frozenset({"vide", "soun"})
_TIMED_TEXT_HANDLERS = frozenset({"text", "sbtl", "subt", "clcp"})
_STRUCTURAL_MOOV = frozenset({b"mvhd", b"trak", b"udta", b"meta", b"mvex", b"iods"})
_NMEA = re.compile(r"\$(?:GP|GN)(?:RMC|GGA)")
_NMEA_COORD = re.compile(r"\d+(?:\.\d+)?")
_UNCLASSIFIED_TIMED = "unclassified timed metadata; samples were not interpreted"


class BmffError(ValueError):
    """A movie could not be inspected or cleaned."""

    def __init__(self, message: str, status: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class SampleRange:
    """Absolute file offset and length of one media sample."""

    offset: int
    length: int


@dataclass
class Track:
    """One trak: handler, codec, display or audio facts, and sample ranges."""

    handler: str
    codec: str
    enabled: bool
    width: int | None
    height: int | None
    channels: int | None
    sample_rate: int | None
    samples: list[SampleRange]
    stsd: bytes


@dataclass
class Movie:
    """Parsed movie header and its tracks."""

    brand: bytes
    duration_seconds: float | None
    creation: int | None
    modification: int | None
    mvhd: bytes
    tracks: list[Track]
    limitations: list[str]
    records: list[Record]
    poster: bytes | None = None


@dataclass
class _Found:
    """Limitations and poster bytes gathered while reading one header."""

    limitations: list[str]
    poster: bytes | None = None


def sniff(header: bytes) -> str | None:
    """Classify a short header as BMFF, an unsupported movie, or neither."""
    if header[:4] == b"\x1a\x45\xdf\xa3":
        return "unsupported-bmff"
    if header[:4] == b"RIFF" and header[8:12] == b"AVI ":
        return "unsupported-bmff"
    if len(header) < 12 or header[4:8] != b"ftyp":
        return None
    brand = header[8:12]
    if brand in _FRAGMENTED or brand == b"M4A ":
        return "unsupported-bmff"
    if brand in SUPPORTED_BRANDS:
        return "bmff"
    return "unsupported-bmff"


def read_moov(path: Path) -> tuple[bytes, bytes]:
    """Return the major brand and the moov payload. Media atoms are skipped."""
    with path.open("rb") as handle:
        header = handle.read(32)
        handle.seek(0)
        kind = sniff(header)
        if kind is None:
            raise BmffError("The file format is not supported for inspection.", "unsupported")
        if kind == "unsupported-bmff":
            raise BmffError("This movie container is not supported.", "unsupported")
        brand = header[8:12]
        found: bytes | None = None
        for name, start, size, header_len in _top_atoms(handle):
            if name == b"moof":
                raise BmffError("Fragmented movies are not supported.", "unsupported")
            if name == b"moov":
                if found is not None:
                    raise BmffError(
                        "A movie with more than one moov is not supported.", "unsupported"
                    )
                if size > MAX_MOOV_BYTES:
                    raise BmffError("movie header exceeds the metadata size limit", "error")
                handle.seek(start + header_len)
                found = _read_exact(handle, size - header_len)
            else:
                handle.seek(start + size)
        if found is None:
            raise BmffError("no movie header (moov) was found", "incomplete")
        return brand, found


def media_hash(path: Path) -> str:
    """Return the SHA-256 hex digest of picture and sound samples, in track order."""
    movie = parse_movie(path)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for track in movie.tracks:
            if track.handler not in _MEDIA_HANDLERS:
                continue
            for sample in track.samples:
                _hash_range(handle, digest, sample)
    return digest.hexdigest()


def parse_movie(path: Path) -> Movie:
    """Return duration, codecs, display size, sample offsets, and header tags."""
    brand, moov = read_moov(path)
    mvhd_payload = _child(moov, b"mvhd")
    if mvhd_payload is None or len(mvhd_payload) < 20:
        raise BmffError("no movie header (moov) was found", "incomplete")
    creation, modification, seconds = _movie_timing(mvhd_payload)
    tracks = [_parse_trak(payload) for name, payload in _children(moov) if name == b"trak"]
    found = _Found(limitations=[])
    records = _header_records(moov, creation, modification, found)
    records.extend(_timed_records(path, tracks))
    return Movie(
        brand,
        seconds,
        creation,
        modification,
        mvhd_payload,
        tracks,
        found.limitations,
        records,
        found.poster,
    )


def _top_atoms(handle: BinaryIO) -> Iterator[tuple[bytes, int, int, int]]:
    file_end = handle.seek(0, 2)
    handle.seek(0)
    while handle.tell() + 8 <= file_end:
        start = handle.tell()
        raw = _read_exact(handle, 8)
        size = int.from_bytes(raw[:4], "big")
        name = raw[4:8]
        header_len = 8
        if size == 1:
            size = int.from_bytes(_read_exact(handle, 8), "big")
            header_len = 16
        elif size == 0:
            size = file_end - start
        if size < header_len:
            raise BmffError("file ended inside an atom", "incomplete")
        if start + size > file_end:
            if name == b"moov" and size > MAX_MOOV_BYTES:
                yield name, start, size, header_len
                return
            raise BmffError("file ended inside an atom", "incomplete")
        yield name, start, size, header_len
        handle.seek(start + size)


def _hash_range(handle: BinaryIO, digest: hashlib._Hash, sample: SampleRange) -> None:
    handle.seek(sample.offset)
    remaining = sample.length
    while remaining:
        block = handle.read(min(remaining, 1024 * 1024))
        if not block:
            raise BmffError("file ended inside an atom", "incomplete")
        digest.update(block)
        remaining -= len(block)


def _read_exact(handle: BinaryIO, count: int) -> bytes:
    data = handle.read(count)
    if len(data) != count:
        raise BmffError("file ended inside an atom", "incomplete")
    return data


def _movie_timing(mvhd_payload: bytes) -> tuple[int, int, float | None]:
    version = mvhd_payload[0]
    if version == 0:
        creation, modification, timescale, duration = struct.unpack(">IIII", mvhd_payload[4:20])
    else:
        # Version 1 uses 64-bit creation, modification, and duration (28 bytes).
        if len(mvhd_payload) < 32:
            raise BmffError("no movie header (moov) was found", "incomplete")
        creation, modification, timescale, duration = struct.unpack(">QQIQ", mvhd_payload[4:32])
    seconds = duration / timescale if timescale else None
    return creation, modification, seconds


def _parse_trak(payload: bytes) -> Track:
    tkhd = _child(payload, b"tkhd")
    enabled = False
    width: int | None = None
    height: int | None = None
    if tkhd is not None and len(tkhd) >= 8:
        enabled = bool(int.from_bytes(tkhd[:4], "big") & 1)
        width = int.from_bytes(tkhd[-8:-4], "big") >> 16
        height = int.from_bytes(tkhd[-4:], "big") >> 16
    mdia = _child(payload, b"mdia") or b""
    handler = _handler(_child(mdia, b"hdlr"))
    minf = _child(mdia, b"minf") or b""
    _refuse_external_dref(_child(_child(minf, b"dinf") or b"", b"dref"))
    stbl = _child(minf, b"stbl") or b""
    stsd = _child(stbl, b"stsd") or b""
    _refuse_encrypted(stsd)
    codec, entry = _sample_entry(stsd)
    channels: int | None = None
    sample_rate: int | None = None
    if handler == "soun" and len(entry) >= 28:
        channels = int.from_bytes(entry[16:18], "big")
        sample_rate = int.from_bytes(entry[24:28], "big") >> 16
    return Track(
        handler,
        codec,
        enabled,
        width,
        height,
        channels,
        sample_rate,
        _sample_ranges(stbl),
        stsd,
    )


def _handler(hdlr: bytes | None) -> str:
    if hdlr is None or len(hdlr) < 12:
        raise BmffError("a track has no handler", "incomplete")
    return _ascii_fourcc(hdlr[8:12], "a track has no handler")


def _ascii_fourcc(value: bytes, message: str) -> str:
    try:
        return value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise BmffError(message, "incomplete") from exc


def _refuse_external_dref(dref: bytes | None) -> None:
    """Reject data references that point outside this file."""
    if dref is None or len(dref) < 8:
        return
    for _name, entry in _children(dref[8:]):
        flags = int.from_bytes(entry[:4], "big") if len(entry) >= 4 else 0
        if (flags & 1) == 0:
            raise BmffError("media is stored outside the file", "unsupported")


def _refuse_encrypted(stsd: bytes) -> None:
    """Reject protected sample entries before their payloads are read."""
    if len(stsd) < 8:
        return
    for name, _entry in _children(stsd[8:]):
        if name in {b"encv", b"enca"}:
            raise BmffError("encrypted media is not supported", "unsupported")


def _sample_entry(stsd: bytes) -> tuple[str, bytes]:
    """Return the first sample-entry type and its payload."""
    if len(stsd) < 16:
        return "", b""
    size = int.from_bytes(stsd[8:12], "big")
    header_len = 8
    if size == 1:
        if len(stsd) < 24:
            return "", b""
        size = int.from_bytes(stsd[16:24], "big")
        header_len = 16
    if size < header_len or 8 + size > len(stsd):
        return "", b""
    codec = _ascii_fourcc(stsd[12:16], "a sample entry is incomplete")
    return codec, stsd[8 + header_len : 8 + size]


def _sample_ranges(stbl: bytes) -> list[SampleRange]:
    stsz = _require_child(stbl, b"stsz")
    stco = _child(stbl, b"stco")
    co64 = _child(stbl, b"co64")
    stsc = _require_child(stbl, b"stsc")
    sizes = _sample_sizes(stsz)
    chunks = _chunk_offsets(stco, co64)
    per_chunk = _samples_per_chunk(stsc, len(chunks))
    ranges: list[SampleRange] = []
    index = 0
    for offset, count in zip(chunks, per_chunk, strict=True):
        cursor = offset
        for _ in range(count):
            if index >= len(sizes):
                raise BmffError("a sample table that does not fit the file", "incomplete")
            length = sizes[index]
            ranges.append(SampleRange(cursor, length))
            cursor += length
            index += 1
    if index != len(sizes):
        raise BmffError("a sample table that does not fit the file", "incomplete")
    return ranges


def _sample_sizes(stsz: bytes | None) -> list[int]:
    if stsz is None or len(stsz) < 12:
        return []
    sample_size = int.from_bytes(stsz[4:8], "big")
    sample_count = int.from_bytes(stsz[8:12], "big")
    if sample_count == 0:
        return []
    if sample_size:
        if sample_count > MAX_MOOV_BYTES // 4:
            raise BmffError("a sample table that does not fit the file", "incomplete")
        return [sample_size] * sample_count
    sizes: list[int] = []
    for index in range(sample_count):
        start = 12 + index * 4
        if start + 4 > len(stsz):
            break
        sizes.append(int.from_bytes(stsz[start : start + 4], "big"))
    return sizes


def _chunk_offsets(stco: bytes | None, co64: bytes | None) -> list[int]:
    if stco is not None:
        return _offset_table(stco, 4)
    if co64 is not None:
        return _offset_table(co64, 8)
    return []


def _offset_table(payload: bytes, width: int) -> list[int]:
    if len(payload) < 8:
        return []
    count = int.from_bytes(payload[4:8], "big")
    offsets: list[int] = []
    for index in range(count):
        start = 8 + index * width
        if start + width > len(payload):
            break
        offsets.append(int.from_bytes(payload[start : start + width], "big"))
    return offsets


def _samples_per_chunk(stsc: bytes, chunk_count: int) -> list[int]:
    if len(stsc) < 8 or chunk_count == 0:
        return [1] * chunk_count
    entry_count = int.from_bytes(stsc[4:8], "big")
    entries: list[tuple[int, int]] = []
    for index in range(entry_count):
        start = 8 + index * 12
        if start + 8 > len(stsc):
            break
        first = int.from_bytes(stsc[start : start + 4], "big")
        per_chunk = int.from_bytes(stsc[start + 4 : start + 8], "big")
        entries.append((first, per_chunk))
    if not entries:
        return [1] * chunk_count
    counts: list[int] = []
    for chunk in range(1, chunk_count + 1):
        chosen = entries[0][1]
        for first, per_chunk in entries:
            if first <= chunk:
                chosen = per_chunk
            else:
                break
        counts.append(chosen)
    return counts


def _children(payload: bytes) -> list[tuple[bytes, bytes]]:
    boxes: list[tuple[bytes, bytes]] = []
    pos = 0
    end = len(payload)
    while pos + 8 <= end:
        size = int.from_bytes(payload[pos : pos + 4], "big")
        header_len = 8
        if size == 1:
            if pos + 16 > end:
                break
            size = int.from_bytes(payload[pos + 8 : pos + 16], "big")
            header_len = 16
        elif size == 0:
            size = end - pos
        if size < header_len or pos + size > end:
            break
        name = payload[pos + 4 : pos + 8]
        boxes.append((name, payload[pos + header_len : pos + size]))
        pos += size
    return boxes


def _child(payload: bytes, name: bytes) -> bytes | None:
    for child_name, child_payload in _children(payload):
        if child_name == name:
            return child_payload
    return None


def _require_child(payload: bytes, name: bytes) -> bytes:
    child = _child(payload, name)
    if child is None:
        raise BmffError("a sample table that does not fit the file", "incomplete")
    return child


def _timed_records(path: Path, tracks: list[Track]) -> list[Record]:
    selected = [track for track in tracks if track.handler not in _MEDIA_HANDLERS]
    if not selected:
        return []
    media = _media_ranges(tracks)
    blocked = {id(track) for track in selected if _track_samples_blocked(track.samples, media)}
    payloads: dict[int, bytes] = {}
    readable = [track for track in selected if id(track) not in blocked]
    if readable:
        with path.open("rb") as handle:
            for track in readable:
                payloads[id(track)] = _read_sample_bytes(handle, track.samples)
    records: list[Record] = []
    for track in selected:
        if id(track) in blocked:
            records.append(_timed_record(track))
            continue
        route = _route_record(payloads[id(track)], track)
        records.append(route if route is not None else _timed_record(track))
    return records


def _media_ranges(tracks: list[Track]) -> list[SampleRange]:
    return [
        sample for track in tracks if track.handler in _MEDIA_HANDLERS for sample in track.samples
    ]


def _track_samples_blocked(samples: list[SampleRange], media: list[SampleRange]) -> bool:
    """Refuse a metadata read that is oversized or shares bytes with picture or sound."""
    if _sample_span(samples) > MAX_MOOV_BYTES:
        return True
    return _ranges_overlap_any(samples, media)


def _sample_span(samples: list[SampleRange]) -> int:
    total = 0
    for sample in samples:
        total += sample.length
        if total > MAX_MOOV_BYTES:
            return total
    return total


def _read_sample_bytes(handle: BinaryIO, samples: list[SampleRange]) -> bytes:
    if _sample_span(samples) > MAX_MOOV_BYTES:
        raise BmffError("metadata samples exceed the metadata size limit", "incomplete")
    parts: list[bytes] = []
    for sample in samples:
        handle.seek(sample.offset)
        parts.append(_read_exact(handle, sample.length))
    return b"".join(parts)


def _route_record(payload: bytes, track: Track) -> Record | None:
    points = _coordinate_points(payload.decode("latin-1"))
    if points is None:
        return None
    count, first = points
    value = f"{count} points; {first}"
    return Record("GPS", "Route", track.codec or track.handler, value, value, "trak")


def _coordinate_points(text: str) -> tuple[int, str] | None:
    located = list(_ISO6709.finditer(text))
    if located:
        return len(located), located[0].group(0)
    pairs: list[str] = []
    for match in _NMEA.finditer(text):
        line = text[match.start() :].splitlines()[0]
        pair = _nmea_pair(line)
        if pair is not None:
            pairs.append(pair)
    if not pairs:
        return None
    return len(pairs), pairs[0]


def _nmea_pair(sentence: str) -> str | None:
    fields = sentence.split("*", 1)[0].split(",")
    kind = fields[0] if fields else ""
    if kind.endswith("RMC") and len(fields) >= 7:
        lat, ns, lon, ew = fields[3], fields[4], fields[5], fields[6]
    elif kind.endswith("GGA") and len(fields) >= 6:
        lat, ns, lon, ew = fields[2], fields[3], fields[4], fields[5]
    else:
        return None
    if not _nmea_coordinate_valid(lat, ns, lon, ew):
        return None
    return f"{lat}{ns}{lon}{ew}"


def _nmea_coordinate_valid(lat: str, ns: str, lon: str, ew: str) -> bool:
    if ns not in {"N", "S"} or ew not in {"E", "W"}:
        return False
    return _NMEA_COORD.fullmatch(lat) is not None and _NMEA_COORD.fullmatch(lon) is not None


def _timed_record(track: Track) -> Record:
    if track.handler == "tmcd":
        field, value = "Timecode", "timecode track"
    elif track.handler in _TIMED_TEXT_HANDLERS:
        field, value = "TimedText", "timed text track"
    else:
        field, value = "TimedMetadata", _UNCLASSIFIED_TIMED
    return Record("CONTAINER", field, track.codec or track.handler, value, value, "trak")


def _header_records(moov: bytes, creation: int, modification: int, found: _Found) -> list[Record]:
    records: list[Record] = []
    if creation != 0:
        created = _quicktime_time(creation)
        records.append(Record("CONTAINER", "CreationTime", "mvhd", created, created, "mvhd"))
    if modification != 0:
        modified = _quicktime_time(modification)
        records.append(Record("CONTAINER", "ModificationTime", "mvhd", modified, modified, "mvhd"))
    for name, payload in _children(moov):
        if name in {b"free", b"skip"}:
            continue
        if name == b"udta":
            records.extend(_udta_records(payload, found))
        elif name == b"meta":
            records.extend(_meta_records(payload, found))
        elif name == b"trak":
            records.extend(_track_container_records(payload, found))
        elif name not in _STRUCTURAL_MOOV:
            records.append(_binary_container_item(name, payload, "moov"))
    return records


def _track_container_records(payload: bytes, found: _Found) -> list[Record]:
    records: list[Record] = []
    for name, child in _children(payload):
        if name == b"udta":
            records.extend(_udta_records(child, found))
        elif name == b"meta":
            records.extend(_meta_records(child, found))
    return records


def _binary_container_item(name: bytes, payload: bytes, source: str) -> Record:
    described = safe_binary(payload)
    tag = name.decode("latin-1")
    return Record("CONTAINER", "BinaryItem", tag, described, described, source, binary=True)


def _quicktime_time(seconds: int) -> str:
    try:
        moment = _QT_EPOCH + timedelta(seconds=seconds)
    except OverflowError as exc:
        raise BmffError("movie time is outside the supported range", "incomplete") from exc
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def _udta_records(payload: bytes, found: _Found) -> list[Record]:
    records: list[Record] = []
    for name, child in _children(payload):
        if name == b"meta":
            records.extend(_meta_records(child, found))
            continue
        if name in {b"free", b"skip"}:
            continue
        records.extend(_udta_item_records(name, child, found))
    return records


def _udta_item_records(name: bytes, payload: bytes, found: _Found) -> list[Record]:
    tag = name.decode("latin-1")
    embedded = _embedded_records(payload, covr=name == b"covr", tag=tag, source="udta", found=found)
    if name == b"\xa9xyz":
        return [*embedded, *_gps_records(_udta_text(payload), tag, "udta")]
    field = _UDTA_TEXT.get(name)
    if field is not None:
        text = _udta_text(payload)
        return [*embedded, Record("CONTAINER", field, tag, text, text, "udta")]
    if _known_metadata_blob(name, payload):
        return embedded
    if _udta_payload_is_text(payload):
        text = _udta_text(payload)
        return [*embedded, Record("CONTAINER", "Text", tag, text, text, "udta")]
    return [*embedded, _binary_container_item(name, payload, "udta")]


def _udta_payload_is_text(payload: bytes) -> bool:
    body = payload[4:] if len(payload) >= 4 and payload[:1] == b"\x00" else payload
    body = body.rstrip(b"\x00")
    if b"\x00" in body:
        return False
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(ord(char) >= 32 or char in "\t\n\r" for char in text)


def _known_metadata_blob(name: bytes, payload: bytes) -> bool:
    return _is_poster(name, payload) or _is_embedded_metadata(payload)


def _is_embedded_metadata(data: bytes) -> bool:
    if data.startswith(_EXIF_PREFIXES):
        return True
    return b"<x:xmpmeta" in data or b"<?xpacket" in data


def _udta_text(payload: bytes) -> str:
    body = payload[4:] if payload[:1] == b"\x00" and len(payload) >= 4 else payload
    return body.decode("utf-8", errors="replace").rstrip("\x00")


def _gps_records(text: str, tag: str, source: str) -> list[Record]:
    match = _ISO6709.search(text)
    if match is None:
        return []
    latitude, longitude = match.group(1), match.group(2)
    return [
        Record("GPS", "GPSLatitude", tag, latitude, latitude, source),
        Record("GPS", "GPSLongitude", tag, longitude, longitude, source),
    ]


def _meta_records(payload: bytes, found: _Found) -> list[Record]:
    children = _meta_children(payload)
    keys_payload = next((child for name, child in children if name == b"keys"), None)
    ilst_payload = next((child for name, child in children if name == b"ilst"), None)
    if ilst_payload is None:
        return []
    if keys_payload is None:
        if _ilst_children_are_fourcc(ilst_payload):
            return _fourcc_ilst_records(ilst_payload, found)
        return []
    return _ilst_records(ilst_payload, _mdta_keys(keys_payload), found)


def _ilst_children_are_fourcc(payload: bytes) -> bool:
    names = [name for name, _child in _children(payload) if name not in {b"free", b"skip"}]
    return bool(names) and all(_is_fourcc_tag(name) for name in names)


def _is_fourcc_tag(name: bytes) -> bool:
    """Return whether an ilst child is a fourcc tag rather than a keys index."""
    if len(name) != 4 or name in {b"free", b"skip"}:
        return False
    if name[:2] == b"\x00\x00":
        return not 1 <= int.from_bytes(name, "big") <= 65535
    return True


def _fourcc_ilst_records(payload: bytes, found: _Found) -> list[Record]:
    records: list[Record] = []
    for name, child in _children(payload):
        if name in {b"free", b"skip"}:
            continue
        data = _child(child, b"data")
        if data is None or len(data) < 8:
            records.extend(_udta_item_records(name, child, found))
            continue
        records.extend(_fourcc_data_records(name, data, found))
    return records


def _fourcc_data_records(name: bytes, data: bytes, found: _Found) -> list[Record]:
    tag = name.decode("latin-1")
    value = data[8:]
    embedded = _embedded_records(
        value, covr=_is_poster(name, value), tag=tag, source="ilst", found=found
    )
    if name == b"\xa9xyz":
        text = value.decode("utf-8", errors="replace").rstrip("\x00")
        return [*embedded, *_gps_records(text, tag, "ilst")]
    if _known_metadata_blob(name, value):
        return embedded
    if not _utf8_data(data[:4]):
        return [*embedded, _binary_container_item(name, value, "ilst")]
    field = _UDTA_TEXT.get(name, "Text")
    text = value.decode("utf-8", errors="replace").rstrip("\x00")
    return [*embedded, Record("CONTAINER", field, tag, text, text, "ilst")]


def _meta_children(payload: bytes) -> list[tuple[bytes, bytes]]:
    direct = _children(payload)
    if _meta_starts_with_boxes(payload, direct):
        return direct
    if len(payload) >= 12:
        return _children(payload[4:])
    return direct


def _meta_starts_with_boxes(payload: bytes, children: list[tuple[bytes, bytes]]) -> bool:
    names = {name for name, _child in children}
    if not names & {b"hdlr", b"keys", b"ilst"}:
        return False
    # Version 0 is four zero bytes, which the box walker treats as size 0.
    swallowed = len(children) == 1 and int.from_bytes(payload[:4], "big") in {0, 1}
    return not swallowed


def _mdta_keys(payload: bytes) -> list[str]:
    start = 0 if _mdta_entry(payload, 0) else 8
    if start == 8 and not _mdta_entry(payload, 8):
        return []
    keys: list[str] = []
    position = start
    while position + 8 <= len(payload):
        size = int.from_bytes(payload[position : position + 4], "big")
        namespace = payload[position + 4 : position + 8]
        if size < 8 or position + size > len(payload) or namespace != b"mdta":
            break
        key = payload[position + 8 : position + size].decode("utf-8", errors="replace")
        keys.append(key.rstrip("\x00"))
        position += size
    return keys


def _mdta_entry(payload: bytes, position: int) -> bool:
    if position + 8 > len(payload):
        return False
    size = int.from_bytes(payload[position : position + 4], "big")
    namespace = payload[position + 4 : position + 8]
    return 8 <= size <= len(payload) - position and namespace == b"mdta"


def _ilst_records(payload: bytes, keys: list[str], found: _Found) -> list[Record]:
    records: list[Record] = []
    for name, child in _children(payload):
        index = int.from_bytes(name, "big")
        if not 1 <= index <= len(keys):
            continue
        data = _child(child, b"data")
        if data is None or len(data) < 8:
            continue
        records.extend(_ilst_item(keys[index - 1], data, found))
    return records


def _ilst_item(key: str, data: bytes, found: _Found) -> list[Record]:
    value = data[8:]
    embedded = _embedded_records(value, covr=False, tag=key, source="ilst", found=found)
    if not _utf8_data(data[:4]):
        described = safe_binary(value)
        binary = Record("CONTAINER", "BinaryItem", key, described, described, "ilst", binary=True)
        return [*embedded, binary]
    text = value.decode("utf-8", errors="replace").rstrip("\x00")
    if key == _LOCATION_KEY:
        return [*embedded, *_gps_records(text, key, "ilst")]
    field = _ILST_TEXT.get(key)
    if field is None and key.lower().endswith(_SERIAL_SUFFIXES):
        field = "SerialNumber"
    if field is None:
        field = "Text"
    return [*embedded, Record("CONTAINER", field, key, text, text, "ilst")]


def _embedded_records(
    data: bytes,
    *,
    covr: bool,
    tag: str,
    source: str,
    found: _Found,
) -> list[Record]:
    records: list[Record] = []
    image_poster = data.startswith((b"\xff\xd8", _PNG_SIGNATURE))
    if not image_poster:
        if b"<x:xmpmeta" in data or b"<?xpacket" in data:
            try:
                records.extend(read_xmp(data))
            except XmpError as exc:
                found.limitations.append(str(exc))
        if data.startswith(_EXIF_PREFIXES):
            try:
                records.extend(records_from_exif(load_exif(data), "bmff-exif"))
            except ExifError:
                found.limitations.append("EXIF metadata could not be parsed")
    if covr or image_poster:
        records.extend(_poster_records(data, tag, source, found))
    return records


def _poster_records(data: bytes, tag: str, source: str, found: _Found) -> list[Record]:
    if data.startswith(b"\xff\xd8"):
        try:
            parts = inspect_segments(parse_segments(data))
        except JpegError:
            return _unparsed_poster(data, tag, source, found)
        found.poster = data
        found.limitations.extend(parts.limitations)
        return parts.records
    if data.startswith(_PNG_SIGNATURE):
        found.poster = data
        return []
    return _unparsed_poster(data, tag, source, found)


def _unparsed_poster(data: bytes, tag: str, source: str, found: _Found) -> list[Record]:
    described = safe_binary(data)
    return [Record("CONTAINER", "UnparsedPoster", tag, described, described, source, binary=True)]


def _utf8_data(header: bytes) -> bool:
    # Type 1 is UTF-8. Files store it as a big-endian integer (00 00 00 01).
    return header[:1] == b"\x01" or int.from_bytes(header, "big") == 1


_OFFSET_CONTAINERS = frozenset({b"trak", b"mdia", b"minf", b"stbl"})
_COPY_BYTES = 1024 * 1024


@dataclass
class _Piece:
    """One moov child kept for the cleaned file, with its track when it is a trak."""

    kind: bytes
    raw: bytes
    track: Track | None = None


def write_clean(source: Path, destination: Path, remove: set[tuple[str, str]]) -> None:
    """Write original ftyp, an edited moov, and one mdat of the kept samples."""
    movie = parse_movie(source)
    media = [track for track in movie.tracks if track.handler in _MEDIA_HANDLERS]
    other = [track for track in movie.tracks if track.handler not in _MEDIA_HANDLERS]
    _refuse_overlap(media, other)
    ftyp = _read_ftyp(source)
    _brand, moov = read_moov(source)
    pieces, kept, dropped = _edit_moov(moov, movie, source, remove)
    _refuse_overlap(kept, dropped)
    groups = [
        _chunk_groups(piece.raw, piece.track.samples) for piece in pieces if piece.track is not None
    ]
    placed = _relative_offsets(groups)
    samples = _samples_in_file_order(groups)
    payload_len = sum(sample.length for sample in samples)
    moov_box = _pack_moov(pieces, groups, placed, len(ftyp), payload_len)
    _stream_mdat(source, destination, ftyp, moov_box, samples)


def _read_ftyp(path: Path) -> bytes:
    with path.open("rb") as handle:
        file_end = handle.seek(0, 2)
        handle.seek(0)
        header = _read_exact(handle, 8)
        size = int.from_bytes(header[:4], "big")
        name = header[4:8]
        header_len = 8
        if size == 1:
            size = int.from_bytes(_read_exact(handle, 8), "big")
            header_len = 16
        elif size == 0:
            size = file_end
        if name != b"ftyp" or size < header_len or size > file_end:
            raise BmffError("The file format is not supported for inspection.", "unsupported")
        handle.seek(0)
        return _read_exact(handle, size)


def _edit_moov(
    moov: bytes,
    movie: Movie,
    source: Path,
    remove: set[tuple[str, str]],
) -> tuple[list[_Piece], list[Track], list[Track]]:
    pieces: list[_Piece] = []
    kept: list[Track] = []
    dropped: list[Track] = []
    track_index = 0
    media = _media_ranges(movie.tracks)
    children, rest = _split_boxes(moov)
    for name, inner, raw in children:
        if name in {b"free", b"skip"}:
            continue
        if name == b"mvhd":
            pieces.append(_Piece(name, _box(b"mvhd", _zero_timestamps(inner, remove))))
            continue
        if name == b"trak":
            if track_index >= len(movie.tracks):
                raise BmffError("a track has no handler", "incomplete")
            track = movie.tracks[track_index]
            track_index += 1
            if _drop_track(source, track, remove, media):
                dropped.append(track)
                continue
            pieces.append(_Piece(name, _edit_trak_box(raw, remove), track))
            kept.append(track)
            continue
        if name == b"udta":
            edited = _edit_udta(inner, remove)
            if edited:
                pieces.append(_Piece(name, _box(b"udta", edited)))
            continue
        if name == b"meta":
            edited = _edit_meta(inner, remove)
            if edited:
                pieces.append(_Piece(name, _box(b"meta", edited)))
            continue
        if name in {b"mvex", b"iods"}:
            pieces.append(_Piece(name, raw))
            continue
        if ("CONTAINER", "BinaryItem") in remove:
            continue
        pieces.append(_Piece(name, raw))
    if rest:
        pieces.append(_Piece(b"rest", rest))
    return pieces, kept, dropped


def _edit_trak_box(raw: bytes, remove: set[tuple[str, str]]) -> bytes:
    children, rest = _split_boxes(_box_payload(raw))
    parts = bytearray()
    for name, inner, child_raw in children:
        if name == b"udta":
            edited = _edit_udta(inner, remove)
            if edited:
                parts += _box(b"udta", edited)
            continue
        if name == b"meta":
            edited = _edit_meta(inner, remove)
            if edited:
                parts += _box(b"meta", edited)
            continue
        parts += child_raw
    parts += rest
    return _box(b"trak", bytes(parts))


def _drop_track(
    source: Path,
    track: Track,
    remove: set[tuple[str, str]],
    media: list[SampleRange],
) -> bool:
    if track.handler in _MEDIA_HANDLERS:
        return False
    if not track.handler:
        raise BmffError("a track has no handler", "incomplete")
    return _track_pair(source, track, media) in remove


def _track_pair(source: Path, track: Track, media: list[SampleRange]) -> tuple[str, str]:
    if not _track_samples_blocked(track.samples, media):
        with source.open("rb") as handle:
            payload = _read_sample_bytes(handle, track.samples)
        if _route_record(payload, track) is not None:
            return ("GPS", "Route")
    record = _timed_record(track)
    return (record.family, record.field)


def _refuse_overlap(kept: list[Track], dropped: list[Track]) -> None:
    kept_ranges = [sample for track in kept for sample in track.samples]
    dropped_ranges = [sample for track in dropped for sample in track.samples]
    if _ranges_overlap_any(dropped_ranges, kept_ranges):
        raise BmffError("metadata samples overlap picture or sound", "error")


def _ranges_overlap_any(left: list[SampleRange], right: list[SampleRange]) -> bool:
    """Return whether any range in the two sorted lists shares a byte."""
    ordered_left = sorted(left, key=lambda sample: (sample.offset, sample.length))
    ordered_right = sorted(right, key=lambda sample: (sample.offset, sample.length))
    index = 0
    other = 0
    while index < len(ordered_left) and other < len(ordered_right):
        first = ordered_left[index]
        second = ordered_right[other]
        if _ranges_overlap(first, second):
            return True
        if first.offset + first.length <= second.offset:
            index += 1
        else:
            other += 1
    return False


def _ranges_overlap(left: SampleRange, right: SampleRange) -> bool:
    return left.offset < right.offset + right.length and right.offset < left.offset + left.length


def _zero_timestamps(payload: bytes, remove: set[tuple[str, str]]) -> bytes:
    clear_creation = ("CONTAINER", "CreationTime") in remove
    clear_modification = ("CONTAINER", "ModificationTime") in remove
    if not clear_creation and not clear_modification:
        return payload
    data = bytearray(payload)
    if not data:
        return payload
    if data[0] == 0:
        if clear_creation and len(data) >= 8:
            data[4:8] = b"\x00\x00\x00\x00"
        if clear_modification and len(data) >= 12:
            data[8:12] = b"\x00\x00\x00\x00"
        return bytes(data)
    if clear_creation and len(data) >= 12:
        data[4:12] = b"\x00" * 8
    if clear_modification and len(data) >= 20:
        data[12:20] = b"\x00" * 8
    return bytes(data)


def _edit_udta(payload: bytes, remove: set[tuple[str, str]]) -> bytes:
    children, rest = _split_boxes(payload)
    parts = bytearray()
    for name, inner, raw in children:
        if name in {b"free", b"skip"}:
            continue
        if name == b"meta":
            edited = _edit_meta(inner, remove)
            if edited:
                parts += _box(b"meta", edited)
            continue
        item = _edit_udta_item(name, inner, raw, remove)
        if item:
            parts += item
    parts += rest
    return bytes(parts)


def _edit_udta_item(
    name: bytes, inner: bytes, raw: bytes, remove: set[tuple[str, str]]
) -> bytes | None:
    if _is_poster(name, inner) and _drop_poster(remove):
        return None
    pair = _udta_pair(name, inner)
    if pair is not None and pair in remove:
        return None
    rewritten = _rewrite_metadata_blob(inner, remove)
    if rewritten is None:
        return None
    if rewritten == inner:
        return raw
    return _box(name, rewritten)


def _udta_pair(name: bytes, payload: bytes) -> tuple[str, str] | None:
    if name == b"\xa9xyz":
        return ("GPS", "GPSLatitude")
    field = _UDTA_TEXT.get(name)
    if field is not None:
        return ("CONTAINER", field)
    if _known_metadata_blob(name, payload):
        return None
    if _udta_payload_is_text(payload):
        return ("CONTAINER", "Text")
    return ("CONTAINER", "BinaryItem")


def _drop_poster(remove: set[tuple[str, str]]) -> bool:
    return ("THUMBNAIL", "preview") in remove or ("CONTAINER", "UnparsedPoster") in remove


def _is_poster(name: bytes, payload: bytes) -> bool:
    return name == b"covr" or payload.startswith((b"\xff\xd8", _PNG_SIGNATURE))


def _rewrite_metadata_blob(data: bytes, remove: set[tuple[str, str]]) -> bytes | None:
    if data.startswith(_EXIF_PREFIXES):
        return _rewrite_exif_blob(data, remove)
    if b"<x:xmpmeta" in data or b"<?xpacket" in data:
        return _rewrite_xmp_blob(data, remove)
    return data


def _rewrite_exif_blob(data: bytes, remove: set[tuple[str, str]]) -> bytes | None:
    interested = any(family in {"EXIF", "GPS", "THUMBNAIL"} for family, _field in remove)
    try:
        loaded = load_exif(data)
        if not interested:
            return data
        return rewrite_exif(loaded, remove)
    except ExifError as exc:
        raise BmffError("EXIF metadata could not be rewritten", "incomplete") from exc


def _rewrite_xmp_blob(data: bytes, remove: set[tuple[str, str]]) -> bytes | None:
    fields = {field for family, field in remove if family == "XMP"}
    try:
        if not fields:
            read_xmp(data)
            return data
        return rewrite_xmp(data, fields)
    except XmpError as exc:
        raise BmffError(str(exc), "incomplete") from exc


def _edit_meta(payload: bytes, remove: set[tuple[str, str]]) -> bytes:
    prefix, children, rest = _meta_layout(payload)
    keys_inner = next((inner for name, inner, _raw in children if name == b"keys"), None)
    keys = _mdta_keys(keys_inner) if keys_inner is not None else []
    parts = bytearray(prefix)
    for name, inner, raw in children:
        if name in {b"free", b"skip"}:
            continue
        if name == b"ilst":
            parts += _box(b"ilst", _edit_ilst(inner, keys, remove))
            continue
        parts += raw
    parts += rest
    return bytes(parts)


def _meta_layout(payload: bytes) -> tuple[bytes, list[tuple[bytes, bytes, bytes]], bytes]:
    direct, rest = _split_boxes(payload)
    pairs = [(name, inner) for name, inner, _raw in direct]
    if _meta_starts_with_boxes(payload, pairs):
        return b"", direct, rest
    if len(payload) < 4:
        return b"", direct, rest
    nested, nested_rest = _split_boxes(payload[4:])
    return payload[:4], nested, nested_rest


def _edit_ilst(payload: bytes, keys: list[str], remove: set[tuple[str, str]]) -> bytes:
    children, rest = _split_boxes(payload)
    parts = bytearray()
    keyless_fourcc = not keys and _ilst_children_are_fourcc(payload)
    for name, inner, raw in children:
        if name in {b"free", b"skip"}:
            continue
        if keyless_fourcc and _is_fourcc_tag(name):
            item = _edit_keyless_ilst_item(name, inner, raw, remove)
            if item:
                parts += item
            continue
        index = int.from_bytes(name, "big")
        data = _child(inner, b"data")
        if data is None or len(data) < 8 or not 1 <= index <= len(keys):
            parts += raw
            continue
        value = data[8:]
        if _is_poster(b"", value) and _drop_poster(remove):
            continue
        pair = _ilst_pair(keys[index - 1], data)
        if pair is not None and pair in remove:
            continue
        rewritten = _rewrite_metadata_blob(value, remove)
        if rewritten is None:
            continue
        if rewritten == value:
            parts += raw
            continue
        updated = _replace_child(inner, b"data", data[:8] + rewritten)
        parts += _box(name, updated)
    parts += rest
    return bytes(parts)


def _edit_keyless_ilst_item(
    name: bytes, inner: bytes, raw: bytes, remove: set[tuple[str, str]]
) -> bytes | None:
    data = _child(inner, b"data")
    if data is None or len(data) < 8:
        return _edit_udta_item(name, inner, raw, remove)
    value = data[8:]
    if _is_poster(name, value) and _drop_poster(remove):
        return None
    pair = _fourcc_data_pair(name, data)
    if pair is not None and pair in remove:
        return None
    rewritten = _rewrite_metadata_blob(value, remove)
    if rewritten is None:
        return None
    if rewritten == value:
        return raw
    updated = _replace_child(inner, b"data", data[:8] + rewritten)
    return _box(name, updated)


def _fourcc_data_pair(name: bytes, data: bytes) -> tuple[str, str] | None:
    value = data[8:]
    if name == b"\xa9xyz":
        return ("GPS", "GPSLatitude")
    if _known_metadata_blob(name, value):
        return None
    if not _utf8_data(data[:4]):
        return ("CONTAINER", "BinaryItem")
    return ("CONTAINER", _UDTA_TEXT.get(name, "Text"))


def _ilst_pair(key: str, data: bytes) -> tuple[str, str] | None:
    value = data[8:]
    if key == _LOCATION_KEY:
        return ("GPS", "GPSLatitude")
    if not _utf8_data(data[:4]):
        if value.startswith((b"\xff\xd8", _PNG_SIGNATURE)):
            return ("THUMBNAIL", "preview")
        return ("CONTAINER", "BinaryItem")
    field = _ILST_TEXT.get(key)
    if field is None and key.lower().endswith(_SERIAL_SUFFIXES):
        field = "SerialNumber"
    if field is None:
        field = "Text"
    return ("CONTAINER", field)


def _replace_child(payload: bytes, target: bytes, new_inner: bytes) -> bytes:
    children, rest = _split_boxes(payload)
    parts = bytearray()
    replaced = False
    for name, _inner, raw in children:
        if name == target and not replaced:
            parts += _box(name, new_inner)
            replaced = True
        else:
            parts += raw
    parts += rest
    return bytes(parts)


def _chunk_groups(trak: bytes, samples: list[SampleRange]) -> list[list[SampleRange]]:
    payload = _box_payload(trak)
    mdia = _child(payload, b"mdia") or b""
    minf = _child(mdia, b"minf") or b""
    stbl = _child(minf, b"stbl") or b""
    counts = _samples_per_chunk(
        _child(stbl, b"stsc") or b"",
        len(_chunk_offsets(_child(stbl, b"stco"), _child(stbl, b"co64"))),
    )
    groups: list[list[SampleRange]] = []
    index = 0
    for count in counts:
        groups.append(samples[index : index + count])
        index += count
    if index != len(samples):
        raise BmffError("a sample table that does not fit the file", "incomplete")
    return groups


def _relative_offsets(groups: list[list[list[SampleRange]]]) -> dict[int, int]:
    placed: dict[int, int] = {}
    cursor = 0
    for sample in _samples_in_file_order(groups):
        placed[id(sample)] = cursor
        cursor += sample.length
    return placed


def _samples_in_file_order(groups: list[list[list[SampleRange]]]) -> list[SampleRange]:
    samples = [sample for chunks in groups for chunk in chunks for sample in chunk]
    samples.sort(key=lambda sample: (sample.offset, sample.length, id(sample)))
    return samples


def _pack_moov(
    pieces: list[_Piece],
    groups: list[list[list[SampleRange]]],
    placed: dict[int, int],
    ftyp_len: int,
    payload_len: int,
) -> bytes:
    mdat_header = 16 if 8 + payload_len >= 0x100000000 else 8
    narrow = _assemble_moov(pieces, _chunk_tables(groups, placed, 0), False)
    base = ftyp_len + len(narrow) + mdat_header
    wide = any(base + relative >= 2**32 for relative in placed.values())
    if wide:
        sized = _assemble_moov(pieces, _chunk_tables(groups, placed, 0), True)
        base = ftyp_len + len(sized) + mdat_header
    return _assemble_moov(pieces, _chunk_tables(groups, placed, base), wide)


def _chunk_tables(
    groups: list[list[list[SampleRange]]], placed: dict[int, int], base: int
) -> list[list[int]]:
    tables: list[list[int]] = []
    for chunks in groups:
        table: list[int] = []
        for samples in chunks:
            if not samples:
                table.append(0)
                continue
            table.append(base + placed[id(samples[0])])
        tables.append(table)
    return tables


def _assemble_moov(pieces: list[_Piece], tables: list[list[int]], wide: bool) -> bytes:
    body = bytearray()
    table_index = 0
    for piece in pieces:
        if piece.kind == b"trak":
            body += _patch_offsets(piece.raw, tables[table_index], wide)
            table_index += 1
            continue
        body += piece.raw
    return _box(b"moov", bytes(body))


def _patch_offsets(box: bytes, offsets: list[int], wide: bool) -> bytes:
    name = box[4:8]
    if name in {b"stco", b"co64"}:
        return _offset_box(offsets, wide)
    if name not in _OFFSET_CONTAINERS:
        return box
    children, rest = _split_boxes(_box_payload(box))
    rebuilt = bytearray()
    for child_name, _inner, raw in children:
        if child_name in {b"free", b"skip"}:
            continue
        rebuilt += _patch_offsets(raw, offsets, wide)
    rebuilt += rest
    return _box(name, bytes(rebuilt))


def _offset_box(offsets: list[int], wide: bool) -> bytes:
    width = 8 if wide else 4
    kind = b"co64" if wide else b"stco"
    body = struct.pack(">II", 0, len(offsets))
    body += b"".join(offset.to_bytes(width, "big") for offset in offsets)
    return _box(kind, body)


def _stream_mdat(
    source: Path,
    destination: Path,
    ftyp: bytes,
    moov: bytes,
    samples: list[SampleRange],
) -> None:
    payload_len = sum(sample.length for sample in samples)
    with source.open("rb") as src, destination.open("wb") as out:
        out.write(ftyp)
        out.write(moov)
        out.write(_mdat_header(payload_len))
        for sample in samples:
            _copy_range(src, out, sample)
        out.flush()
        os.fsync(out.fileno())


def _mdat_header(payload_len: int) -> bytes:
    if 8 + payload_len >= 0x100000000:
        total = 16 + payload_len
        return b"\x00\x00\x00\x01mdat" + total.to_bytes(8, "big")
    return (8 + payload_len).to_bytes(4, "big") + b"mdat"


def _copy_range(src: BinaryIO, out: BinaryIO, sample: SampleRange) -> None:
    src.seek(sample.offset)
    remaining = sample.length
    while remaining:
        block = src.read(min(remaining, _COPY_BYTES))
        if not block:
            raise BmffError("file ended inside an atom", "incomplete")
        out.write(block)
        remaining -= len(block)


def _split_boxes(payload: bytes) -> tuple[list[tuple[bytes, bytes, bytes]], bytes]:
    boxes: list[tuple[bytes, bytes, bytes]] = []
    position = 0
    end = len(payload)
    while position + 8 <= end:
        size = int.from_bytes(payload[position : position + 4], "big")
        header_len = 8
        if size == 1:
            if position + 16 > end:
                break
            size = int.from_bytes(payload[position + 8 : position + 16], "big")
            header_len = 16
        elif size == 0:
            size = end - position
        if size < header_len or position + size > end:
            break
        name = payload[position + 4 : position + 8]
        inner = payload[position + header_len : position + size]
        boxes.append((name, inner, payload[position : position + size]))
        position += size
    return boxes, payload[position:]


def _box(name: bytes, payload: bytes) -> bytes:
    total = 8 + len(payload)
    if total >= 0x100000000:
        total = 16 + len(payload)
        return b"\x00\x00\x00\x01" + name + total.to_bytes(8, "big") + payload
    return total.to_bytes(4, "big") + name + payload


def _box_payload(box: bytes) -> bytes:
    if int.from_bytes(box[:4], "big") == 1:
        return box[16:]
    return box[8:]
