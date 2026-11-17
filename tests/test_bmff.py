import io
import json
import struct
from pathlib import Path

import piexif
import pytest
from PIL import Image

from lupaxa.metadata_inspector.bmff import (
    MAX_MOOV_BYTES,
    BmffError,
    media_hash,
    parse_movie,
    read_moov,
    sniff,
)
from lupaxa.metadata_inspector.catalog import build_findings
from lupaxa.metadata_inspector.cli import main
from lupaxa.metadata_inspector.engine import inspect_path
from lupaxa.metadata_inspector.models import ImageFacts
from lupaxa.metadata_inspector.sanitize import display_value
from tests.bmff_builder import (
    assemble,
    assemble_ordered,
    atom,
    movie,
    multi_chunk,
    mvhd,
    track,
    udta,
    udta_raw,
)
from tests.images import plain_jpeg


def test_sniff_accepts_phone_brands() -> None:
    for brand in (b"qt  ", b"mp42", b"M4V ", b"3gp4", b"isom"):
        data = movie(brand, atom(b"mvhd", b""), b"")
        assert sniff(data[:32]) == "bmff"


def test_sniff_rejects_fragmented_and_audio_brands() -> None:
    assert sniff(movie(b"iso6", b"", b"")[:32]) == "unsupported-bmff"
    assert sniff(movie(b"M4A ", b"", b"")[:32]) == "unsupported-bmff"


def test_sniff_refuses_ebml_and_avi_only() -> None:
    assert sniff(b"\x1a\x45\xdf\xa3" + b"\x00" * 28) == "unsupported-bmff"
    assert sniff(b"RIFF\x00\x00\x00\x00AVI ") == "unsupported-bmff"
    assert sniff(b"RIFF\x00\x00\x00\x00WEBP") is None
    assert sniff(b"\xff\xd8\xff" + b"\x00" * 16) is None


def test_read_moov_before_and_after_media(tmp_path: Path) -> None:
    payload = atom(b"mvhd", b"header-times")
    media = b"\x00" * 1024 * 1024
    for moov_first in (True, False):
        path = tmp_path / f"clip-{moov_first}.mp4"
        path.write_bytes(movie(b"mp42", payload, media, moov_first=moov_first))
        brand, moov = read_moov(path)
        assert brand == b"mp42"
        assert moov == payload


def test_declared_moov_over_32_mib_is_not_loaded(tmp_path: Path) -> None:
    path = tmp_path / "huge.mp4"
    # size field claims a moov bigger than the cap; the file itself stays small
    fake = b"\x00\x00\x00\x14ftypmp42\x00\x00\x00\x00mp42"
    claimed = (MAX_MOOV_BYTES + 1).to_bytes(4, "big") + b"moov"
    path.write_bytes(fake + claimed)
    with pytest.raises(BmffError) as caught:
        read_moov(path)
    assert caught.value.status == "error"
    assert "metadata size" in str(caught.value)


def test_moof_is_unsupported(tmp_path: Path) -> None:
    path = tmp_path / "frag.mp4"
    path.write_bytes(movie(b"mp42", atom(b"mvhd", b""), b"") + atom(b"moof", b""))
    with pytest.raises(BmffError) as caught:
        read_moov(path)
    assert caught.value.status == "unsupported"


def test_constant_stsz_sample_count_is_capped(tmp_path: Path) -> None:
    header = mvhd(timescale=1000, duration=1, creation=0, modification=0)
    video = track(b"vide", b"avc1", enabled=True, width=320, height=240, samples=b"x")
    data = bytearray(assemble(b"mp42", [header, video]))
    marker = data.index(b"stsz")
    payload = marker + 4
    data[payload + 4 : payload + 8] = struct.pack(">I", 1)
    data[payload + 8 : payload + 12] = struct.pack(">I", MAX_MOOV_BYTES)
    path = tmp_path / "huge-stsz-count.mp4"
    path.write_bytes(data)
    with pytest.raises(BmffError) as caught:
        parse_movie(path)
    assert caught.value.status == "incomplete"
    assert "sample table" in str(caught.value)


def test_facts_come_from_the_first_enabled_video_track(tmp_path: Path) -> None:
    header = mvhd(timescale=1000, duration=2500, creation=100, modification=200)
    disabled = track(b"vide", b"hvc1", enabled=False, width=1, height=1, samples=b"nope")
    video = track(b"vide", b"avc1", enabled=True, width=320, height=240, samples=b"PIC1")
    audio = track(b"soun", b"mp4a", enabled=True, channels=2, sample_rate=48000, samples=b"SND1")
    path = tmp_path / "facts.mp4"
    path.write_bytes(assemble(b"mp42", [header, disabled, video, audio]))
    parsed = parse_movie(path)
    assert parsed.duration_seconds == 2.5
    assert parsed.creation == 100
    assert parsed.modification == 200
    assert [item.handler for item in parsed.tracks] == ["vide", "vide", "soun"]
    assert parsed.tracks[1].codec == "avc1"
    assert (parsed.tracks[1].width, parsed.tracks[1].height) == (320, 240)
    assert parsed.tracks[1].samples[0].length == 4
    assert (parsed.tracks[2].channels, parsed.tracks[2].sample_rate) == (2, 48000)
    assert path.read_bytes()[parsed.tracks[1].samples[0].offset :][:4] == b"PIC1"


def test_user_data_becomes_classified_findings(tmp_path: Path) -> None:
    tags = udta(
        {
            b"\xa9xyz": "+51.5074-000.1278/",
            b"\xa9mak": "Lupaxa",
            b"\xa9mod": "Cam",
            b"\xa9day": "2024-01-02",
            b"\xa9ART": "Ada",
            b"\xa9cpy": "Copyright Ada",
        }
    )
    path = tmp_path / "tags.mov"
    path.write_bytes(
        assemble(
            b"qt  ",
            [mvhd(timescale=600, duration=600, creation=0, modification=0), tags],
        )
    )
    parsed = parse_movie(path)
    findings = build_findings(parsed.records, ImageFacts())
    by_id = {item.id: item for item in findings}
    assert by_id["exif.gps.coordinates"].classification == "high"
    coordinates = by_id["exif.gps.coordinates"].value
    assert display_value("exif.gps.coordinates", coordinates, reveal=False) == "[redacted]"
    assert "51.5074" in display_value(
        "exif.gps.coordinates", by_id["exif.gps.coordinates"].value, reveal=True
    )
    assert by_id["container.device.make"].classification == "low"
    assert by_id["container.datetime.creation"].classification == "medium"
    assert by_id["container.artist"].classification == "medium"
    assert by_id["container.copyright"].classification == "informational"


def _poster() -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (2, 2), (9, 8, 7)).save(buffer, format="JPEG", quality=80)
    return buffer.getvalue()


def test_xmp_exif_and_poster(tmp_path: Path) -> None:
    xmp = (
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        b'<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/" dc:creator="Ada"/>'
        b"</rdf:RDF></x:xmpmeta>"
    )
    exif = piexif.dump(
        {
            "0th": {piexif.ImageIFD.Make: b"FromExif"},
            "Exif": {},
            "GPS": {},
            "1st": {},
            "thumbnail": None,
        }
    )
    tags = udta_raw([(b"XMP_", xmp), (b"exif", exif), (b"covr", _poster())])
    header = mvhd(timescale=600, duration=600, creation=0, modification=0)
    path = tmp_path / "rich.mov"
    path.write_bytes(assemble(b"qt  ", [header, tags]))
    parsed = parse_movie(path)
    assert any(record.interpreted == "Ada" for record in parsed.records)
    assert any(
        record.field == "Make" and record.interpreted == "FromExif" for record in parsed.records
    )
    assert parsed.poster is not None
    assert parsed.poster.startswith(b"\xff\xd8")

    broken = udta_raw([(b"covr", b"not-an-image")])
    other = tmp_path / "broken.mov"
    other.write_bytes(assemble(b"qt  ", [header, broken]))
    parsed = parse_movie(other)
    assert parsed.poster is None
    assert any(record.field == "UnparsedPoster" for record in parsed.records)


def test_covr_jpeg_ignores_trailing_xmp_but_raw_xmp_reports_limitation(tmp_path: Path) -> None:
    header = mvhd(timescale=600, duration=600, creation=0, modification=0)
    jpeg_with_xmp_suffix = _poster() + b"<x:xmpmeta"
    covr_only = tmp_path / "covr-xmp-suffix.mov"
    covr_only.write_bytes(assemble(b"qt  ", [header, udta_raw([(b"covr", jpeg_with_xmp_suffix)])]))
    with_covr = parse_movie(covr_only)
    assert with_covr.poster is not None
    assert with_covr.poster.startswith(b"\xff\xd8")
    assert not any("not well-formed" in item for item in with_covr.limitations)

    broken_xmp = b"<x:xmpmeta>"
    xmp_only = tmp_path / "broken-xmp.mov"
    xmp_only.write_bytes(assemble(b"qt  ", [header, udta_raw([(b"XMP_", broken_xmp)])]))
    with_xmp = parse_movie(xmp_only)
    assert with_xmp.duration_seconds is not None
    assert any("not well-formed" in item for item in with_xmp.limitations)


def test_timed_metadata_tracks(tmp_path: Path) -> None:
    header = mvhd(timescale=1000, duration=1000, creation=0, modification=0)
    video = track(b"vide", b"avc1", width=16, height=16, samples=b"PIC1")
    sound = track(b"soun", b"mp4a", channels=1, sample_rate=8000, samples=b"SND1")
    route = track(b"meta", b"mett", samples=b"+51.5000-000.1200/\n+51.5100-000.1300/\n")
    timecode = track(b"tmcd", b"tmcd", samples=b"TC")
    text = track(b"text", b"text", samples=b"hello")
    binary = track(b"meta", b"gpmd", samples=b"\x00\x01binary")
    path = tmp_path / "route.mp4"
    path.write_bytes(assemble(b"mp42", [header, video, sound, route, timecode, text, binary]))
    parsed = parse_movie(path)
    fields = {record.field for record in parsed.records}
    assert "Route" in fields
    assert "PIC1" not in "".join(record.interpreted for record in parsed.records)
    route_record = next(record for record in parsed.records if record.field == "Route")
    assert route_record.interpreted.startswith("2 points;")
    findings = build_findings(parsed.records, ImageFacts())
    route_finding = next(item for item in findings if item.field == "Route")
    assert route_finding.classification == "high"
    assert "timezone offset" not in route_finding.explanation.lower()
    shown = display_value(route_finding.id, route_finding.value, reveal=False)
    assert shown.startswith("2 points;")
    assert "51.5" not in shown
    assert "[redacted]" in shown
    timecode = next(item for item in findings if item.field == "Timecode")
    assert timecode.classification == "informational"
    timed_text = next(item for item in findings if item.field == "TimedText")
    assert timed_text.classification == "medium"
    timed = next(item for item in findings if item.field == "TimedMetadata")
    assert timed.classification == "medium"
    assert b"binary" not in route_record.interpreted.encode()
    assert all(b"binary" not in record.interpreted.encode() for record in parsed.records)


def test_gpmd_fake_nmea_stays_timed_metadata_without_secret(tmp_path: Path) -> None:
    header = mvhd(timescale=1000, duration=1000, creation=0, modification=0)
    video = track(b"vide", b"avc1", width=16, height=16, samples=b"PIC1")
    gpmd = track(b"meta", b"gpmd", samples=b"$GPRMC,1,2,SECRET,N,DATA,W")
    path = tmp_path / "gpmd-fake-nmea.mp4"
    path.write_bytes(assemble(b"mp42", [header, video, gpmd]))
    parsed = parse_movie(path)
    timed = next(record for record in parsed.records if record.field == "TimedMetadata")
    assert timed.tag == "gpmd"
    assert "Route" not in {record.field for record in parsed.records}
    assert all("SECRET" not in record.interpreted for record in parsed.records)


def test_gpmd_skips_bad_nmea_then_accepts_well_formed_gga(tmp_path: Path) -> None:
    header = mvhd(timescale=1000, duration=1000, creation=0, modification=0)
    video = track(b"vide", b"avc1", width=16, height=16, samples=b"PIC1")
    sample = (
        b"$GPRMC,short,SECRET\n$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47"
    )
    gpmd = track(b"meta", b"gpmd", samples=sample)
    path = tmp_path / "gpmd-nmea-skip-then-gga.mp4"
    path.write_bytes(assemble(b"mp42", [header, video, gpmd]))
    parsed = parse_movie(path)
    route = next(record for record in parsed.records if record.field == "Route")
    assert route.interpreted == "1 points; 4807.038N01131.000E"
    assert all("SECRET" not in record.interpreted for record in parsed.records)


def test_gpmd_well_formed_rmc_route_omits_checksum(tmp_path: Path) -> None:
    header = mvhd(timescale=1000, duration=1000, creation=0, modification=0)
    video = track(b"vide", b"avc1", width=16, height=16, samples=b"PIC1")
    sample = b"$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A"
    gpmd = track(b"meta", b"gpmd", samples=sample)
    path = tmp_path / "gpmd-nmea-rmc.mp4"
    path.write_bytes(assemble(b"mp42", [header, video, gpmd]))
    parsed = parse_movie(path)
    route = next(record for record in parsed.records if record.field == "Route")
    assert route.interpreted == "1 points; 4807.038N01131.000E"
    assert "6A" not in route.interpreted


def test_external_dref_is_unsupported(tmp_path: Path) -> None:
    header = mvhd(timescale=1000, duration=1000, creation=0, modification=0)
    video = track(b"vide", b"avc1", width=16, height=16, samples=b"PIC1", external=True)
    path = tmp_path / "external-dref.mp4"
    path.write_bytes(assemble(b"mp42", [header, video]))
    with pytest.raises(BmffError) as caught:
        parse_movie(path)
    assert caught.value.status == "unsupported"
    assert str(caught.value) == "media is stored outside the file"


def test_gpmd_short_nmea_stays_timed_metadata_without_sample_bytes(tmp_path: Path) -> None:
    header = mvhd(timescale=1000, duration=1000, creation=0, modification=0)
    video = track(b"vide", b"avc1", width=16, height=16, samples=b"PIC1")
    gpmd = track(b"meta", b"gpmd", samples=b"$GPRMC,short" + b"SECRET")
    path = tmp_path / "gpmd-nmea-short.mp4"
    path.write_bytes(assemble(b"mp42", [header, video, gpmd]))
    parsed = parse_movie(path)
    timed = next(record for record in parsed.records if record.field == "TimedMetadata")
    assert timed.tag == "gpmd"
    assert "Route" not in {record.field for record in parsed.records}
    assert all("SECRET" not in record.interpreted for record in parsed.records)


def test_missing_handler_is_incomplete(tmp_path: Path) -> None:
    trak = atom(b"trak", atom(b"tkhd", b"\x00" * 84))
    path = tmp_path / "no-handler.mp4"
    header = mvhd(timescale=1000, duration=1000, creation=0, modification=0)
    path.write_bytes(assemble(b"mp42", [header, (trak, b"")]))
    with pytest.raises(BmffError) as caught:
        parse_movie(path)
    assert caught.value.status == "incomplete"


def test_metadata_chunk_between_picture_chunks(tmp_path: Path) -> None:
    header = mvhd(timescale=1000, duration=1000, creation=0, modification=0)
    video = multi_chunk(b"vide", b"avc1", [b"PIC1", b"PIC2"], width=16, height=16)
    meta = multi_chunk(b"meta", b"mett", [b"META"])
    path = tmp_path / "between.mp4"
    path.write_bytes(assemble_ordered(b"mp42", [header], [video, meta], [(0, 0), (1, 0), (0, 1)]))
    parsed = parse_movie(path)
    picture = parsed.tracks[0].samples
    middle = parsed.tracks[1].samples[0]
    assert len(picture) == 2
    assert picture[0].offset < middle.offset < picture[1].offset


video_track = track(
    b"vide",
    b"avc1",
    enabled=True,
    width=320,
    height=240,
    samples=b"PIC1",
)
audio_track = track(
    b"soun",
    b"mp4a",
    enabled=True,
    channels=2,
    sample_rate=48000,
    samples=b"SND1",
)


def minimal_movie(brand: bytes = b"mp42") -> bytes:
    header = mvhd(timescale=1000, duration=1000, creation=0, modification=0)
    video = track(b"vide", b"avc1", width=16, height=16, samples=b"PIC1")
    return assemble(brand, [header, video])


def test_scan_reports_video_facts_and_keeps_schema(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "clip.mp4"
    path.write_bytes(
        assemble(
            b"mp42",
            [
                mvhd(timescale=1000, duration=1500, creation=0, modification=0),
                video_track,
                audio_track,
            ],
        )
    )
    assert main(["scan", str(path), "--json", "--quiet"]) == 0
    document = json.loads(capsys.readouterr().out)
    result = document["results"][0]
    assert document["schema_version"] == "1.0"
    assert result["format"] == "bmff"
    assert result["duration_seconds"] == 1.5
    assert result["video_codec"] == "avc1"
    assert result["audio_tracks"] == [{"codec": "mp4a", "channels": 2, "sample_rate": 48000}]
    assert "soundtrack" in result["disclaimer"]


def test_directory_scan_includes_movies_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "clip.mp4").write_bytes(minimal_movie())
    (tmp_path / "clip.m4v").write_bytes(minimal_movie(b"M4V "))
    (tmp_path / "clip.mov").write_bytes(minimal_movie(b"qt  "))
    (tmp_path / "clip.3gp").write_bytes(minimal_movie(b"3gp4"))
    (tmp_path / "song.m4a").write_bytes(minimal_movie(b"M4A "))
    (tmp_path / "notes.txt").write_text("no", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--json", "--quiet"]) == 0
    names = {Path(item["file"]).name for item in json.loads(capsys.readouterr().out)["results"]}
    assert names == {"clip.mp4", "clip.m4v", "clip.mov", "clip.3gp"}


def test_video_over_the_ceiling_is_not_read(tmp_path: Path) -> None:
    path = tmp_path / "big.mp4"
    path.write_bytes(minimal_movie())
    inspection = inspect_path(path, max_file_size=100, max_video_size=1)
    assert inspection.status == "error"
    assert "maximum size" in inspection.errors[0]


def interleaved_movie() -> bytes:
    header = mvhd(timescale=1000, duration=1000, creation=3_000_000_000, modification=3_000_000_100)
    tags = udta({b"\xa9mak": "Lupaxa", b"\xa9xyz": "+51.5074-000.1278/"})
    video = multi_chunk(b"vide", b"avc1", [b"PIC1", b"PIC2"], width=16, height=16)
    sound = multi_chunk(b"soun", b"mp4a", [b"SND1"], channels=1, sample_rate=8000)
    meta = multi_chunk(b"meta", b"mett", [b"META"])
    timecode = multi_chunk(b"tmcd", b"tmcd", [b"TC"])
    text = multi_chunk(b"text", b"text", [b"hello"])
    binary = multi_chunk(b"meta", b"gpmd", [b"\x00\x01gpmd"])
    tracks = [video, sound, meta, timecode, text, binary]
    order = [(0, 0), (2, 0), (0, 1), (1, 0), (3, 0), (4, 0), (5, 0)]
    return assemble_ordered(b"mp42", [header, tags], tracks, order)


def overlapping_movie() -> bytes:
    """Return a file whose metadata sample starts at the picture sample's offset."""
    header = mvhd(timescale=1000, duration=1000, creation=0, modification=0)
    video = multi_chunk(b"vide", b"avc1", [b"PIC1"], width=16, height=16)
    meta = multi_chunk(b"meta", b"mett", [b"META"])
    data = assemble_ordered(b"mp42", [header], [video, meta], [(0, 0), (1, 0)])
    first = data.find(b"stco")
    second = data.find(b"stco", first + 4)
    picture_offset = data[first + 12 : first + 16]
    return data[: second + 12] + picture_offset + data[second + 16 :]


def test_public_clean_keeps_picture_and_sound_bytes(tmp_path: Path) -> None:
    # Video chunks PIC1 and PIC2, with META sitting between them in the file.
    # User data: make Lupaxa, GPS +51.5074-000.1278/, creation via mvhd.
    # Tracks: vide, soun, tmcd, text, gpmd.
    source = tmp_path / "clip.mp4"
    source.write_bytes(interleaved_movie())
    before = media_hash(source)
    assert main(["clean", str(source), "--profile", "public", "--quiet"]) == 0
    cleaned = tmp_path / "clip-clean.mp4"
    assert source.read_bytes() == interleaved_movie()
    assert media_hash(cleaned) == before
    inspection = inspect_path(cleaned, max_file_size=10**9, max_video_size=10**9)
    ids = {item.id for item in inspection.findings}
    assert "exif.gps.coordinates" not in ids
    assert "container.timed_text" not in ids
    assert "container.timed_metadata" not in ids
    assert "container.device.make" in ids
    assert "container.timecode" in ids
    assert b"META" not in cleaned.read_bytes()


def test_overlap_refuses_the_clean(tmp_path: Path) -> None:
    source = tmp_path / "overlap.mp4"
    source.write_bytes(overlapping_movie())
    assert main(["clean", str(source), "--quiet"]) == 1
    assert not (tmp_path / "overlap-clean.mp4").exists()


def test_apply_orientation_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "clip.mp4"
    source.write_bytes(minimal_movie())
    photo = tmp_path / "still.jpg"
    photo.write_bytes(plain_jpeg())
    assert main(["clean", str(source), "--apply-orientation", "--quiet"]) == 5
    assert main(["clean", str(photo), str(source), "--apply-orientation", "--quiet"]) == 6


def refusal_fixture(builder: str) -> bytes:
    """Return a file the scanner must refuse."""
    header = mvhd(timescale=1000, duration=1000, creation=0, modification=0)
    if builder == "moof":
        return movie(b"mp42", header, b"") + atom(b"moof", b"")
    if builder == "second_moov":
        return movie(b"mp42", header, b"") + atom(b"moov", b"")
    if builder == "encrypted":
        video = track(b"vide", b"encv", width=16, height=16, samples=b"PIC1")
        return assemble(b"mp42", [header, video])
    if builder == "external_dref":
        video = track(b"vide", b"avc1", width=16, height=16, samples=b"PIC1", external=True)
        return assemble(b"mp42", [header, video])
    if builder == "truncated":
        # Declared moov size runs past EOF and stays at most 32 MiB.
        ftyp = atom(b"ftyp", b"mp42\x00\x00\x00\x00mp42")
        declared = 1024
        return ftyp + declared.to_bytes(4, "big") + b"moov"
    if builder == "mkv":
        return b"\x1a\x45\xdf\xa3" + b"\x00" * 64
    if builder == "avi":
        return b"RIFF\x00\x00\x00\x00AVI "
    raise ValueError(builder)


@pytest.mark.parametrize(
    ("builder", "status"),
    [
        ("moof", "unsupported"),
        ("second_moov", "unsupported"),
        ("encrypted", "unsupported"),
        ("external_dref", "unsupported"),
        ("truncated", "incomplete"),
        ("mkv", "unsupported"),
        ("avi", "unsupported"),
    ],
)
def test_refusals(tmp_path: Path, builder: str, status: str) -> None:
    path = tmp_path / "clip.bin"
    path.write_bytes(refusal_fixture(builder))
    code = main(["scan", str(path), "--json", "--quiet"])
    assert code == (5 if status == "unsupported" else 1)


def test_unknown_udta_text_is_kept_and_binary_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "PLANTED-SECRET"
    binary = b"\xff" + secret.encode("ascii") + b"\x00\xfe"
    tags = udta_raw(
        [
            (b"note", b"\x00\x00\x00\x00hello caption"),
            (b"priv", binary),
        ]
    )
    header = mvhd(timescale=1000, duration=1000, creation=3_000_000_000, modification=3_000_000_100)
    video = track(b"vide", b"avc1", width=16, height=16, samples=b"PIC1")
    source = tmp_path / "tags.mp4"
    source.write_bytes(assemble(b"mp42", [header, tags, video]))
    parsed = parse_movie(source)
    text = next(record for record in parsed.records if record.field == "Text")
    item = next(record for record in parsed.records if record.field == "BinaryItem")
    assert text.interpreted == "hello caption"
    assert item.binary is True
    assert secret not in text.interpreted
    assert secret not in text.raw
    assert secret not in item.interpreted
    assert secret not in item.raw
    findings = build_findings(parsed.records, ImageFacts())
    by_field = {finding.field: finding for finding in findings}
    assert by_field["Text"].classification == "low"
    assert by_field["BinaryItem"].classification == "medium"

    assert main(["clean", str(source), "--profile", "public", "--quiet"]) == 0
    cleaned = tmp_path / "tags-clean.mp4"
    cleaned_movie = parse_movie(cleaned)
    assert cleaned_movie.creation == 0
    assert cleaned_movie.modification == 0
    assert any(
        record.field == "Text" and record.interpreted == "hello caption"
        for record in cleaned_movie.records
    )
    assert all(record.field != "BinaryItem" for record in cleaned_movie.records)
    assert not any(
        record.field in {"CreationTime", "ModificationTime"} for record in cleaned_movie.records
    )
    assert secret.encode("ascii") not in cleaned.read_bytes()
    assert main(["check", str(cleaned), "--quiet"]) == 0
    assert main(["verify", str(cleaned), "--quiet"]) == 0

    def refuse_read_bytes(self: Path) -> bytes:
        raise AssertionError(f"read_bytes {self}")

    monkeypatch.setattr(Path, "read_bytes", refuse_read_bytes)
    assert main(["verify", str(source), str(cleaned), "--quiet"]) == 0


def test_non_ascii_handler_is_incomplete(tmp_path: Path) -> None:
    header = mvhd(timescale=1000, duration=1000, creation=0, modification=0)
    video = track(b"\xff\xfe\x00\x01", b"avc1", width=16, height=16, samples=b"PIC1")
    path = tmp_path / "handler.mp4"
    path.write_bytes(assemble(b"mp42", [header, video]))
    with pytest.raises(BmffError) as caught:
        parse_movie(path)
    assert caught.value.status == "incomplete"


def test_formats_names_the_limits(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["formats"]) == 0
    text = capsys.readouterr().out
    assert "BMFF" in text
    assert "Matroska" in text
    assert "Fragmented" in text
    assert "ExifTool" in text
