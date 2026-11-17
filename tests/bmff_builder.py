"""Build the small ISO BMFF files the video tests inspect."""

from __future__ import annotations

import struct


def atom(kind: bytes, payload: bytes) -> bytes:
    """Return one atom, using a 64-bit size when the box does not fit in 32 bits."""
    if len(kind) != 4:
        raise ValueError("atom type must be 4 bytes")
    total = 8 + len(payload)
    if total >= 0x100000000:
        total = 16 + len(payload)
        return b"\x00\x00\x00\x01" + kind + total.to_bytes(8, "big") + payload
    return total.to_bytes(4, "big") + kind + payload


def movie(brand: bytes, moov_payload: bytes, mdat: bytes, *, moov_first: bool = True) -> bytes:
    """Return an ftyp plus moov and mdat in the requested order."""
    if len(brand) != 4:
        raise ValueError("brand must be 4 bytes")
    ftyp = atom(b"ftyp", brand + b"\x00\x00\x00\x00" + brand)
    moov = atom(b"moov", moov_payload)
    media = atom(b"mdat", mdat)
    body = moov + media if moov_first else media + moov
    return ftyp + body


def udta(items: dict[bytes, str]) -> bytes:
    """Return a udta atom with one child for each user-data item."""
    body = b"".join(
        atom(kind, b"\x00\x00\x00\x00" + text.encode("utf-8")) for kind, text in items.items()
    )
    return atom(b"udta", body)


def udta_raw(items: list[tuple[bytes, bytes]]) -> bytes:
    return atom(b"udta", b"".join(atom(kind, payload) for kind, payload in items))


def children(payload: bytes) -> list[tuple[bytes, int, bytes]]:
    """Return (type, start, inner_payload) for each child box."""
    boxes: list[tuple[bytes, int, bytes]] = []
    pos = 0
    while pos + 8 <= len(payload):
        size = int.from_bytes(payload[pos : pos + 4], "big")
        if size < 8 or pos + size > len(payload):
            break
        boxes.append((payload[pos + 4 : pos + 8], pos, payload[pos + 8 : pos + size]))
        pos += size
    return boxes


def mvhd(*, timescale: int, duration: int, creation: int, modification: int) -> bytes:
    payload = struct.pack(
        ">IIIIIIHH",
        0,
        creation,
        modification,
        timescale,
        duration,
        0x00010000,
        0x0100,
        0,
    )
    payload += b"\x00" * 8
    payload += struct.pack(">9I", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    payload += b"\x00" * 24 + struct.pack(">I", 2)
    return atom(b"mvhd", payload)


def track(
    handler: bytes,
    codec: bytes,
    *,
    enabled: bool = True,
    width: int = 0,
    height: int = 0,
    channels: int = 0,
    sample_rate: int = 0,
    samples: bytes = b"",
    external: bool = False,
) -> tuple[bytes, bytes]:
    """Return one trak and the sample bytes assemble() will put in mdat."""
    flags = 0x7 if enabled else 0
    matrix = struct.pack(">9I", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
    tkhd = struct.pack(">6I", flags, 0, 0, 1, 0, 1000) + (b"\x00" * 8)
    tkhd += struct.pack(">4H", 0, 0, 0, 0) + matrix
    tkhd += struct.pack(">II", width << 16, height << 16)
    mdhd = struct.pack(">5I2H", 0, 0, 0, 1000, 1000, 0x55C4, 0)
    hdlr = struct.pack(">I", 0) + b"\x00\x00\x00\x00" + handler + (b"\x00" * 12) + b"\x00"
    if handler == b"soun":
        entry = b"\x00" * 6 + struct.pack(">H", 1)
        entry += struct.pack(">HH", 0, 0) + (b"\x00" * 4)
        entry += struct.pack(">HH", channels, 16) + struct.pack(">HH", 0, 0)
        entry += struct.pack(">I", sample_rate << 16)
    else:
        entry = b"\x00" * 8
    stsd = atom(b"stsd", struct.pack(">II", 0, 1) + atom(codec, entry))
    size = len(samples)
    table = struct.pack(">I", size) if size else b""
    stsz = atom(b"stsz", struct.pack(">III", 0, 0, 1 if size else 0) + table)
    stsc = atom(b"stsc", struct.pack(">IIIII", 0, 1, 1, 1 if size else 0, 1))
    stco = atom(b"stco", struct.pack(">III", 0, 1, 0))
    url_flags = 0 if external else 1
    dref = atom(b"dref", struct.pack(">III", 0, 1, 12) + b"url " + struct.pack(">I", url_flags))
    stbl = atom(b"stbl", stsd + stsz + stsc + stco)
    minf = atom(b"minf", atom(b"dinf", dref) + stbl)
    mdia = atom(b"mdia", atom(b"mdhd", mdhd) + atom(b"hdlr", hdlr) + minf)
    return atom(b"trak", atom(b"tkhd", tkhd) + mdia), samples


def _set_stco(box: bytes, offset: int) -> bytes:
    name = box[4:8]
    inner = box[8:]
    if name == b"stco":
        mutable = bytearray(inner)
        mutable[8:12] = offset.to_bytes(4, "big")
        return atom(b"stco", bytes(mutable))
    kids = children(inner)
    if not kids:
        return box
    rebuilt = b"".join(
        _set_stco(inner[start : start + 8 + len(payload)], offset) for _kind, start, payload in kids
    )
    return atom(name, rebuilt)


def multi_chunk(
    handler: bytes, codec: bytes, chunks: list[bytes], **kwargs: int | bool
) -> tuple[bytes, list[bytes]]:
    """Return one trak whose sample table has one sample per chunk."""
    trak, _first = track(handler, codec, samples=b"\x00", **kwargs)
    sizes = b"".join(struct.pack(">I", len(chunk)) for chunk in chunks)
    stsz = atom(b"stsz", struct.pack(">III", 0, 0, len(chunks)) + sizes)
    stsc = atom(b"stsc", struct.pack(">IIIII", 0, 1, 1, 1, 1))
    stco = atom(b"stco", struct.pack(">II", 0, len(chunks)) + (b"\x00\x00\x00\x00" * len(chunks)))
    trak = _replace_child(trak, b"stsz", stsz)
    trak = _replace_child(trak, b"stsc", stsc)
    trak = _replace_child(trak, b"stco", stco)
    return trak, chunks


def _replace_child(box: bytes, kind: bytes, replacement: bytes) -> bytes:
    name = box[4:8]
    inner = box[8:]
    if name == kind:
        return replacement
    kids = children(inner)
    if not kids:
        return box
    rebuilt = b"".join(
        _replace_child(inner[start : start + 8 + len(payload)], kind, replacement)
        for _child_name, start, payload in kids
    )
    return atom(name, rebuilt)


def _set_stco_entries(box: bytes, offsets: list[int]) -> bytes:
    name = box[4:8]
    inner = box[8:]
    if name == b"stco":
        mutable = bytearray(inner)
        for index, offset in enumerate(offsets):
            start = 8 + (index * 4)
            mutable[start : start + 4] = offset.to_bytes(4, "big")
        return atom(b"stco", bytes(mutable))
    kids = children(inner)
    if not kids:
        return box
    rebuilt = b"".join(
        _set_stco_entries(inner[start : start + 8 + len(payload)], offsets)
        for _child_name, start, payload in kids
    )
    return atom(name, rebuilt)


def assemble_ordered(
    brand: bytes,
    parts: list[bytes],
    tracks: list[tuple[bytes, list[bytes]]],
    order: list[tuple[int, int]],
) -> bytes:
    """Return a file whose chunks sit in mdat in the given track order."""
    payload = bytearray(b"".join(parts))
    for trak, _chunks in tracks:
        payload += trak
    ftyp = atom(b"ftyp", brand + b"\x00\x00\x00\x00" + brand)
    data_at = len(ftyp) + 8 + len(payload) + 8
    placed = [[0 for _chunk in chunks] for _trak, chunks in tracks]
    cursor = 0
    blobs: list[bytes] = []
    for track_index, chunk_index in order:
        placed[track_index][chunk_index] = data_at + cursor
        blob = tracks[track_index][1][chunk_index]
        blobs.append(blob)
        cursor += len(blob)
    rebuilt = bytearray()
    track_index = 0
    for name, start, inner in children(bytes(payload)):
        box = bytes(payload[start : start + 8 + len(inner)])
        if name == b"trak":
            box = _set_stco_entries(box, placed[track_index])
            track_index += 1
        rebuilt += box
    return ftyp + atom(b"moov", bytes(rebuilt)) + atom(b"mdat", b"".join(blobs))


def assemble(
    brand: bytes,
    parts: list[bytes | tuple[bytes, bytes]],
    *,
    moov_first: bool = True,
) -> bytes:
    """Return a file whose stco entries point at the packed sample bytes."""
    payload = bytearray()
    samples: list[bytes] = []
    for part in parts:
        if isinstance(part, tuple):
            payload += part[0]
            samples.append(part[1])
        else:
            payload += part
    ftyp = atom(b"ftyp", brand + b"\x00\x00\x00\x00" + brand)
    data_at = len(ftyp) + ((8 + len(payload)) if moov_first else 0) + 8
    running = 0
    sample_index = 0
    rebuilt = bytearray()
    for name, start, inner in children(bytes(payload)):
        box = payload[start : start + 8 + len(inner)]
        if name == b"trak":
            box = _set_stco(bytes(box), data_at + running)
            running += len(samples[sample_index])
            sample_index += 1
        rebuilt += box
    moov_box = atom(b"moov", bytes(rebuilt))
    media = atom(b"mdat", b"".join(samples))
    return ftyp + (moov_box + media if moov_first else media + moov_box)
