"""Synthetic photographs. These files contain no real personal information."""

from __future__ import annotations

import io
import struct

import piexif
from PIL import Image
from PIL.PngImagePlugin import PngInfo


def jpeg_bytes() -> bytes:
    """Return a tiny JPEG with GPS, a serial number, copyright, and software."""
    image = Image.new("RGB", (8, 6), (12, 34, 56))
    exif = piexif.dump(
        {
            "0th": {
                piexif.ImageIFD.Make: b"TestMake",
                piexif.ImageIFD.Model: b"TestModel",
                piexif.ImageIFD.Orientation: 1,
                piexif.ImageIFD.Software: b"TestEdit 1.0",
                piexif.ImageIFD.Artist: b"Test Artist",
                piexif.ImageIFD.Copyright: b"Copyright Test",
                piexif.ImageIFD.DateTime: b"2020:01:02 03:04:05",
            },
            "Exif": {
                piexif.ExifIFD.DateTimeOriginal: b"2020:01:02 03:04:05",
                piexif.ExifIFD.BodySerialNumber: b"SN-TEST-1",
                piexif.ExifIFD.LensModel: b"TestLens",
            },
            "GPS": {
                piexif.GPSIFD.GPSLatitudeRef: b"N",
                piexif.GPSIFD.GPSLatitude: ((51, 1), (30, 1), (0, 1)),
                piexif.GPSIFD.GPSLongitudeRef: b"W",
                piexif.GPSIFD.GPSLongitude: ((0, 1), (7, 1), (30, 1)),
            },
            "1st": {},
            "thumbnail": None,
        }
    )
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=85, exif=exif)
    payload = buffer.getvalue()
    payload = _inject_app(payload, 0xED, _iptc_segment())
    return _inject_app(payload, 0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + _xmp_packet())


def png_bytes() -> bytes:
    """Return a tiny PNG with text metadata and EXIF."""
    image = Image.new("RGB", (8, 6), (1, 2, 3))
    info = PngInfo()
    info.add_text("Author", "Test Artist")
    info.add_text("Comment", "synthetic")
    exif = piexif.dump(
        {
            "0th": {piexif.ImageIFD.Make: b"TestMake"},
            "Exif": {piexif.ExifIFD.BodySerialNumber: b"SN-TEST-1"},
            "GPS": {},
            "1st": {},
            "thumbnail": None,
        }
    )
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", pnginfo=info, exif=exif)
    return buffer.getvalue()


def webp_bytes() -> bytes:
    """Return a tiny WebP with EXIF."""
    image = Image.new("RGB", (8, 6), (4, 5, 6))
    exif = piexif.dump(
        {
            "0th": {
                piexif.ImageIFD.Make: b"TestMake",
                piexif.ImageIFD.Copyright: b"Copyright Test",
            },
            "Exif": {piexif.ExifIFD.BodySerialNumber: b"SN-TEST-1"},
            "GPS": {
                piexif.GPSIFD.GPSLatitudeRef: b"S",
                piexif.GPSIFD.GPSLatitude: ((10, 1), (0, 1), (0, 1)),
                piexif.GPSIFD.GPSLongitudeRef: b"E",
                piexif.GPSIFD.GPSLongitude: ((20, 1), (0, 1), (0, 1)),
            },
            "1st": {},
            "thumbnail": None,
        }
    )
    buffer = io.BytesIO()
    image.save(buffer, format="WEBP", exif=exif)
    return buffer.getvalue()


def tiff_bytes() -> bytes:
    """Return a tiny TIFF with manufacturer and software tags."""
    image = Image.new("RGB", (8, 6), (7, 8, 9))
    exif = Image.Exif()
    exif[271] = "TestMake"
    exif[305] = "TestEdit 1.0"
    exif[306] = "2020:01:02 03:04:05"
    exif[33432] = "Copyright Test"
    buffer = io.BytesIO()
    image.save(buffer, format="TIFF", exif=exif.tobytes())
    return buffer.getvalue()


def plain_jpeg() -> bytes:
    """Return a JPEG with no privacy metadata."""
    image = Image.new("RGB", (4, 4), (9, 9, 9))
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=85)
    return buffer.getvalue()


def _xmp_packet() -> bytes:
    return (
        b'<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        b'<rdf:Description xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/" '
        b'photoshop:City="TestCity"/>'
        b"</rdf:RDF></x:xmpmeta>"
        b'<?xpacket end="w"?>'
    )


def _iptc_segment() -> bytes:
    city = _dataset(2, 90, b"TestCity")
    rights = _dataset(2, 116, b"Copyright Test")
    body = city + rights
    resource = (
        b"8BIM" + struct.pack(">H", 0x0404) + b"\x00\x00" + struct.pack(">I", len(body)) + body
    )
    return b"Photoshop 3.0\x00" + resource


def _dataset(record: int, dataset: int, payload: bytes) -> bytes:
    return bytes((0x1C, record, dataset)) + struct.pack(">H", len(payload)) + payload


def _inject_app(data: bytes, marker: int, payload: bytes) -> bytes:
    segment = b"\xff" + bytes((marker,)) + struct.pack(">H", len(payload) + 2) + payload
    return data[:2] + segment + data[2:]
