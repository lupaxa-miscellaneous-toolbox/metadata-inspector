"""Offline classification and explanations for known metadata fields."""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, ImageFacts, Record
from .sanitize import sanitise

_NO_TZ = (
    " A timestamp with no timezone offset is not assumed to be UTC. "
    "This is the metadata timestamp, not the file's filesystem timestamp."
)
_SAFE = " Removing the field does not change the visible pixels."
_MEDIA = " Removing the field does not change picture or sound."
_NOT_PROOF = " This is not proof of a privacy breach."


@dataclass(frozen=True)
class Rule:
    """Classification rule for one known field."""

    id: str
    name: str
    classification: str
    explanation: str
    action: str
    attribution: bool = False
    structural: bool = False


def _rule(
    id_: str,
    name: str,
    classification: str,
    explanation: str,
    action: str,
    *,
    attribution: bool = False,
    structural: bool = False,
) -> Rule:
    return Rule(id_, name, classification, explanation, action, attribution, structural)


def _media_rule(
    id_: str,
    name: str,
    classification: str,
    detail: str,
    action: str,
    *,
    attribution: bool = False,
) -> Rule:
    return _rule(
        id_,
        name,
        classification,
        detail + _MEDIA + _NOT_PROOF,
        action,
        attribution=attribution,
    )


RULES: dict[tuple[str, str], Rule] = {
    ("EXIF", "Make"): _rule(
        "exif.camera.make",
        "Camera manufacturer",
        "low",
        "The camera manufacturer stored by the device." + _SAFE + _NOT_PROOF,
        "Usually safe to remove. The public profile keeps it.",
    ),
    ("EXIF", "Model"): _rule(
        "exif.camera.model",
        "Camera model",
        "low",
        "The camera model is not a unique device identifier." + _SAFE + _NOT_PROOF,
        "Usually safe to remove. The public profile keeps it.",
    ),
    ("EXIF", "BodySerialNumber"): _rule(
        "exif.camera.serial",
        "Camera serial number",
        "high",
        "A camera serial number can link photographs that otherwise look unrelated."
        + _SAFE
        + _NOT_PROOF,
        "Remove before sharing.",
    ),
    ("EXIF", "CameraOwnerName"): _rule(
        "exif.camera.owner",
        "Camera owner name",
        "high",
        "The camera owner name is personal information stored by the device." + _SAFE + _NOT_PROOF,
        "Remove before sharing.",
    ),
    ("EXIF", "LensMake"): _rule(
        "exif.lens.make",
        "Lens manufacturer",
        "low",
        "The lens manufacturer stored beside the photograph." + _SAFE + _NOT_PROOF,
        "Usually safe to remove. The public profile keeps it.",
    ),
    ("EXIF", "LensModel"): _rule(
        "exif.lens.model",
        "Lens model",
        "low",
        "The lens model is not a unique identifier." + _SAFE + _NOT_PROOF,
        "Usually safe to remove. The public profile keeps it.",
    ),
    ("EXIF", "LensSerialNumber"): _rule(
        "exif.lens.serial",
        "Lens serial number",
        "high",
        "A lens serial number can link photographs from the same piece of equipment."
        + _SAFE
        + _NOT_PROOF,
        "Remove before sharing.",
    ),
    ("EXIF", "ImageUniqueID"): _rule(
        "exif.image.unique_id",
        "Image unique identifier",
        "high",
        "This identifier is meant to distinguish this image from others." + _SAFE + _NOT_PROOF,
        "Remove before sharing.",
    ),
    ("EXIF", "DateTime"): _rule(
        "exif.datetime",
        "Modification timestamp",
        "medium",
        "A metadata modification time recorded in the file." + _NO_TZ + _SAFE + _NOT_PROOF,
        "Remove if the time should not be shared.",
    ),
    ("EXIF", "DateTimeOriginal"): _rule(
        "exif.datetime.original",
        "Original capture timestamp",
        "medium",
        "The capture time recorded by the camera or an editor." + _NO_TZ + _SAFE + _NOT_PROOF,
        "Remove if the capture time should not be shared.",
    ),
    ("EXIF", "DateTimeDigitized"): _rule(
        "exif.datetime.digitized",
        "Digitisation timestamp",
        "medium",
        "The time the image was digitised." + _NO_TZ + _SAFE + _NOT_PROOF,
        "Remove if the time should not be shared.",
    ),
    ("EXIF", "OffsetTime"): _rule(
        "exif.datetime.offset",
        "Timezone offset",
        "medium",
        "A timezone offset stored for a metadata timestamp." + _SAFE + _NOT_PROOF,
        "Remove together with the timestamp it qualifies.",
    ),
    ("EXIF", "OffsetTimeOriginal"): _rule(
        "exif.datetime.offset.original",
        "Original timezone offset",
        "medium",
        "The timezone offset for the original capture time." + _SAFE + _NOT_PROOF,
        "Remove together with the capture timestamp.",
    ),
    ("EXIF", "OffsetTimeDigitized"): _rule(
        "exif.datetime.offset.digitized",
        "Digitised timezone offset",
        "medium",
        "The timezone offset for the digitisation time." + _SAFE + _NOT_PROOF,
        "Remove together with the digitisation timestamp.",
    ),
    ("EXIF", "SubSecTime"): _rule(
        "exif.datetime.subsec",
        "Sub-second modification time",
        "medium",
        "The fractional seconds for the modification timestamp." + _SAFE + _NOT_PROOF,
        "Remove together with the modification timestamp.",
    ),
    ("EXIF", "SubSecTimeOriginal"): _rule(
        "exif.datetime.subsec.original",
        "Sub-second capture time",
        "medium",
        "The fractional seconds for the original capture time." + _SAFE + _NOT_PROOF,
        "Remove together with the capture timestamp.",
    ),
    ("EXIF", "SubSecTimeDigitized"): _rule(
        "exif.datetime.subsec.digitized",
        "Sub-second digitisation time",
        "medium",
        "The fractional seconds for the digitisation time." + _SAFE + _NOT_PROOF,
        "Remove together with the digitisation timestamp.",
    ),
    ("EXIF", "Software"): _rule(
        "exif.software",
        "Editing software",
        "low",
        "The name of software that wrote or edited the file. This is ordinary "
        "software metadata, not a unique identifier." + _SAFE + _NOT_PROOF,
        "Usually safe to remove.",
    ),
    ("EXIF", "Artist"): _rule(
        "exif.artist",
        "Artist",
        "medium",
        "An artist or author name stored in the file. This is attribution, "
        "which is separate from a device identifier." + _SAFE,
        "The public profile keeps attribution. Anonymous and minimal profiles remove it.",
        attribution=True,
    ),
    ("EXIF", "Copyright"): _rule(
        "exif.copyright",
        "Copyright notice",
        "informational",
        "Copyright text is rights metadata, not by itself a device identifier." + _SAFE,
        "The public profile keeps copyright. Removing it discards attribution.",
        attribution=True,
    ),
    ("EXIF", "ImageDescription"): _rule(
        "exif.description",
        "Image description",
        "low",
        "A description stored in the file. The text itself may identify a person or place."
        + _SAFE
        + _NOT_PROOF,
        "Review the text before sharing.",
    ),
    ("EXIF", "Orientation"): _rule(
        "exif.orientation",
        "Orientation",
        "informational",
        "This tag tells viewers how to rotate the stored pixels. Removing it "
        "without rotating the pixels makes the photograph display "
        "incorrectly.",
        "Keep this tag unless you explicitly rotate the image.",
        structural=True,
    ),
    ("GPS", "GPSLatitude"): _rule(
        "exif.gps.coordinates",
        "GPS coordinates",
        "high",
        "Latitude and longitude record where the photograph was taken. "
        "Coordinates are not sent to a mapping service." + _SAFE + _NOT_PROOF,
        "Remove before sharing.",
    ),
    ("GPS", "GPSAltitude"): _rule(
        "exif.gps.altitude",
        "GPS altitude",
        "high",
        "Altitude stored with the GPS fix." + _SAFE + _NOT_PROOF,
        "Remove before sharing.",
    ),
    ("GPS", "GPSTimeStamp"): _rule(
        "exif.gps.timestamp",
        "GPS timestamp",
        "high",
        "The time recorded by the GPS receiver. A missing timezone is not treated as UTC."
        + _SAFE
        + _NOT_PROOF,
        "Remove before sharing.",
    ),
    ("GPS", "GPSDateStamp"): _rule(
        "exif.gps.timestamp",
        "GPS timestamp",
        "high",
        "The date recorded by the GPS receiver." + _SAFE + _NOT_PROOF,
        "Remove before sharing.",
    ),
    ("GPS", "GPSProcessingMethod"): _rule(
        "exif.gps.processing_method",
        "GPS processing method",
        "medium",
        "How the device derived the GPS position." + _SAFE + _NOT_PROOF,
        "Remove with the other GPS fields.",
    ),
    ("GPS", "GPSDestLatitude"): _rule(
        "exif.gps.destination",
        "GPS destination",
        "high",
        "A destination location stored in GPS metadata." + _SAFE + _NOT_PROOF,
        "Remove before sharing.",
    ),
    ("GPS", "Route"): _media_rule(
        "container.gps.route",
        "GPS route",
        "high",
        "A route stored with the movie records where the camera moved.",
        "Remove before sharing.",
    ),
    ("IPTC", "By-line"): _rule(
        "iptc.byline",
        "Author",
        "medium",
        "The IPTC by-line names a person credited for the photograph." + _SAFE,
        "The public profile keeps attribution.",
        attribution=True,
    ),
    ("IPTC", "CopyrightNotice"): _rule(
        "iptc.copyright",
        "Copyright notice",
        "informational",
        "An IPTC copyright notice is rights metadata." + _SAFE,
        "The public profile keeps copyright.",
        attribution=True,
    ),
    ("IPTC", "City"): _rule(
        "iptc.city",
        "Location name",
        "medium",
        "A place name stored in IPTC. It is not a GPS coordinate." + _SAFE + _NOT_PROOF,
        "Remove if the place should not be shared.",
    ),
    ("IPTC", "Sub-location"): _rule(
        "iptc.sublocation",
        "Location name",
        "medium",
        "A more specific place name stored in IPTC." + _SAFE + _NOT_PROOF,
        "Remove if the place should not be shared.",
    ),
    ("IPTC", "Province-State"): _rule(
        "iptc.province",
        "Location name",
        "medium",
        "A region name stored in IPTC." + _SAFE + _NOT_PROOF,
        "Remove if the place should not be shared.",
    ),
    ("IPTC", "Country-PrimaryLocationName"): _rule(
        "iptc.country",
        "Location name",
        "medium",
        "A country name stored in IPTC." + _SAFE + _NOT_PROOF,
        "Remove if the place should not be shared.",
    ),
    ("IPTC", "Contact"): _rule(
        "iptc.contact",
        "Contact information",
        "high",
        "Contact details stored in IPTC." + _SAFE + _NOT_PROOF,
        "Remove before sharing.",
    ),
    ("IPTC", "Caption-Abstract"): _rule(
        "iptc.caption",
        "Caption",
        "low",
        "A caption stored in the file. The text may identify people or "
        "places." + _SAFE + _NOT_PROOF,
        "Review the text before sharing.",
    ),
    ("IPTC", "DateCreated"): _rule(
        "iptc.date.created",
        "IPTC creation date",
        "medium",
        "A creation date stored in IPTC." + _NO_TZ + _SAFE + _NOT_PROOF,
        "Remove if the date should not be shared.",
    ),
    ("XMP", "CreatorTool"): _rule(
        "xmp.creator_tool",
        "Editing software",
        "low",
        "Software named in XMP. This is ordinary software metadata unless the "
        "value is a unique identifier." + _SAFE + _NOT_PROOF,
        "Usually safe to remove.",
    ),
    ("XMP", "creator"): _rule(
        "xmp.creator",
        "Creator",
        "medium",
        "A creator name stored in XMP." + _SAFE,
        "The public profile keeps attribution.",
        attribution=True,
    ),
    ("XMP", "rights"): _rule(
        "xmp.rights",
        "Rights",
        "informational",
        "Rights text stored in XMP." + _SAFE,
        "The public profile keeps rights metadata.",
        attribution=True,
    ),
    ("XMP", "CreateDate"): _rule(
        "xmp.createdate",
        "XMP creation timestamp",
        "medium",
        "An XMP creation time. An offset in the value is reported. A value "
        "with no offset is not treated as UTC." + _SAFE + _NOT_PROOF,
        "Remove if the time should not be shared.",
    ),
    ("XMP", "ModifyDate"): _rule(
        "xmp.modifydate",
        "XMP modification timestamp",
        "medium",
        "An XMP modification time." + _NO_TZ + _SAFE + _NOT_PROOF,
        "Remove if the time should not be shared.",
    ),
    ("XMP", "DocumentID"): _rule(
        "xmp.document_id",
        "Document identifier",
        "medium",
        "An application-generated identifier that can correlate copies of a "
        "file. It is not a camera serial number." + _SAFE + _NOT_PROOF,
        "Remove if files should not be correlated.",
    ),
    ("XMP", "InstanceID"): _rule(
        "xmp.instance_id",
        "Instance identifier",
        "medium",
        "An application-generated identifier for this revision of the file." + _SAFE + _NOT_PROOF,
        "Remove if files should not be correlated.",
    ),
    ("XMP", "OriginalDocumentID"): _rule(
        "xmp.original_document_id",
        "Original document identifier",
        "medium",
        "An identifier that can tie a derivative file back to an earlier "
        "file." + _SAFE + _NOT_PROOF,
        "Remove if files should not be correlated.",
    ),
    ("XMP", "City"): _rule(
        "xmp.city",
        "Location name",
        "medium",
        "A place name stored in XMP." + _SAFE + _NOT_PROOF,
        "Remove if the place should not be shared.",
    ),
    ("XMP", "Country"): _rule(
        "xmp.country",
        "Location name",
        "medium",
        "A country name stored in XMP." + _SAFE + _NOT_PROOF,
        "Remove if the place should not be shared.",
    ),
    ("XMP", "GPSLatitude"): _rule(
        "exif.gps.coordinates",
        "GPS coordinates",
        "high",
        "GPS latitude stored in XMP. Coordinates are not sent to a mapping "
        "service." + _SAFE + _NOT_PROOF,
        "Remove before sharing.",
    ),
    ("ICC", "profile"): _rule(
        "icc.profile",
        "ICC colour profile",
        "informational",
        "An ICC profile can be required for the photograph to display in the "
        "intended colours. It is not treated as disposable privacy metadata.",
        "Keep this profile unless a custom profile explicitly removes it.",
        structural=True,
    ),
    ("THUMBNAIL", "preview"): _rule(
        "thumbnail.preview",
        "Embedded preview",
        "medium",
        "A preview stored separately from the main image. It can contain its "
        "own metadata or show a different crop. Any comparison with the main "
        "image is heuristic.",
        "The built-in cleaning profiles remove embedded previews.",
    ),
    ("FILESYSTEM", "mtime"): _rule(
        "filesystem.mtime",
        "Filesystem modification time",
        "informational",
        "This is the file's filesystem timestamp, not a timestamp embedded in the photograph.",
        "Cleaning does not change the original file's filesystem timestamps.",
        structural=True,
    ),
    ("TEXT", "Author"): _rule(
        "text.author",
        "Author",
        "medium",
        "An author string stored in the image container." + _SAFE,
        "The public profile keeps attribution.",
        attribution=True,
    ),
    ("TEXT", "Copyright"): _rule(
        "text.copyright",
        "Copyright notice",
        "informational",
        "Copyright text stored in the image container." + _SAFE,
        "The public profile keeps copyright.",
        attribution=True,
    ),
    ("CONTAINER", "SerialNumber"): _media_rule(
        "container.device.serial",
        "Serial number",
        "high",
        "A serial number stored in the movie can link recordings that otherwise look unrelated.",
        "Remove before sharing.",
    ),
    ("CONTAINER", "CreationTime"): _media_rule(
        "container.datetime.creation",
        "Creation time",
        "medium",
        "The creation time stored in the movie header or user data.",
        "Remove if the time should not be shared.",
    ),
    ("CONTAINER", "ModificationTime"): _media_rule(
        "container.datetime.modification",
        "Modification time",
        "medium",
        "The modification time stored in the movie header.",
        "Remove if the time should not be shared.",
    ),
    ("CONTAINER", "Artist"): _media_rule(
        "container.artist",
        "Artist",
        "medium",
        "An artist or author name stored in the movie. This is attribution, "
        "which is separate from a device identifier.",
        "The public profile keeps attribution. Anonymous and minimal profiles remove it.",
        attribution=True,
    ),
    ("CONTAINER", "Copyright"): _media_rule(
        "container.copyright",
        "Copyright notice",
        "informational",
        "Copyright text is rights metadata, not by itself a device identifier.",
        "The public profile keeps copyright. Removing it discards attribution.",
        attribution=True,
    ),
    ("CONTAINER", "Make"): _media_rule(
        "container.device.make",
        "Device make",
        "low",
        "The device manufacturer stored in the movie.",
        "Usually safe to remove. The public profile keeps it.",
    ),
    ("CONTAINER", "Model"): _media_rule(
        "container.device.model",
        "Device model",
        "low",
        "The device model stored in the movie. It is not a unique device identifier.",
        "Usually safe to remove. The public profile keeps it.",
    ),
    ("CONTAINER", "Software"): _media_rule(
        "container.software",
        "Software",
        "low",
        "The name of software that wrote the movie. This is ordinary software metadata, "
        "not a unique identifier.",
        "Usually safe to remove.",
    ),
    ("CONTAINER", "Title"): _media_rule(
        "container.title",
        "Title",
        "low",
        "A title stored in the movie. The text itself may identify a person or place.",
        "Review the text before sharing.",
    ),
    ("CONTAINER", "Description"): _media_rule(
        "container.description",
        "Description",
        "low",
        "A description stored in the movie. The text itself may identify a person or place.",
        "Review the text before sharing.",
    ),
    ("CONTAINER", "Comment"): _media_rule(
        "container.comment",
        "Comment",
        "low",
        "A comment stored in the movie. The text itself may identify a person or place.",
        "Review the text before sharing.",
    ),
    ("CONTAINER", "Text"): _media_rule(
        "container.text",
        "Text",
        "low",
        "Text stored in the movie. The text itself may identify a person or place.",
        "Review the text before sharing.",
    ),
    ("CONTAINER", "BinaryItem"): _media_rule(
        "container.binary",
        "Binary item",
        "medium",
        "A binary metadata item stored in the movie.",
        "Remove if the value should not be shared.",
    ),
    ("CONTAINER", "Timecode"): _media_rule(
        "container.timecode",
        "Timecode",
        "informational",
        "A timecode stored in the movie.",
        "The public profile keeps this field.",
    ),
    ("CONTAINER", "TimedText"): _media_rule(
        "container.timed_text",
        "Timed text",
        "medium",
        "Timed text stored in the movie. The text may identify a person or place.",
        "Review the text before sharing.",
    ),
    ("CONTAINER", "TimedMetadata"): _media_rule(
        "container.timed_metadata",
        "Timed metadata",
        "medium",
        "Timed metadata stored in the movie.",
        "Remove if the value should not be shared.",
    ),
    ("CONTAINER", "UnparsedPoster"): _media_rule(
        "container.poster.unparsed",
        "Unparsed poster",
        "medium",
        "A poster image was present but not parsed.",
        "Remove if the poster should not be shared.",
    ),
}

TECHNICAL_EXIF = frozenset(
    {
        "ExposureTime",
        "FNumber",
        "ISOSpeedRatings",
        "PhotographicSensitivity",
        "FocalLength",
        "FocalLengthIn35mmFilm",
        "Flash",
        "WhiteBalance",
        "MeteringMode",
        "ExposureProgram",
        "SceneCaptureType",
        "Contrast",
        "Saturation",
        "Sharpness",
        "ExifVersion",
        "FlashpixVersion",
        "ColorSpace",
        "ComponentsConfiguration",
        "PixelXDimension",
        "PixelYDimension",
        "ImageWidth",
        "ImageLength",
        "ExifTag",
        "XResolution",
        "YResolution",
        "ResolutionUnit",
        "YCbCrPositioning",
    }
)

ATTRIBUTION_IDS = frozenset(rule.id for rule in RULES.values() if rule.attribution)


def rule_for(family: str, field: str) -> Rule:
    """Return the classification rule for a family and field name."""
    known = RULES.get((family, field))
    if known is not None:
        return known
    if family == "EXIF" and field in TECHNICAL_EXIF:
        return _rule(
            f"exif.technical.{field.lower()}",
            field,
            "informational",
            f"{field} is camera technical metadata with limited privacy impact."
            + _SAFE
            + _NOT_PROOF,
            "The public profile keeps this field.",
        )
    if family == "GPS":
        return _rule(
            f"exif.gps.{field.lower()}",
            field,
            "medium",
            f"{field} is location-related GPS metadata." + _SAFE + _NOT_PROOF,
            "Remove with the other location fields.",
        )
    if family == "TEXT":
        return _rule(
            f"text.{field.lower()}",
            field,
            "low",
            (
                f"The text field {field} was stored in the image container. "
                "The text may identify a person or place."
            )
            + _SAFE
            + _NOT_PROOF,
            "Review the text before sharing.",
        )
    slug = "".join(char.lower() if char.isalnum() else "-" for char in field).strip("-") or "field"
    return _rule(
        f"info.{family.lower()}.{slug}",
        field,
        "informational",
        f"{field} is ordinary file information, like the orientation tag." + _NOT_PROOF,
        "The public profile keeps this field.",
    )


def finding_from_record(record: Record) -> Finding:
    """Classify one inventory record."""
    rule = rule_for(record.family, record.field)
    explanation = rule.explanation
    if (
        record.family in {"EXIF", "IPTC", "XMP", "GPS"}
        and record.field != "Route"
        and _has_offset(record.interpreted)
    ):
        explanation += " A timezone offset is present in the stored value."
    return Finding(
        id=rule.id,
        name=rule.name,
        family=record.family,
        field=record.field,
        tag=record.tag,
        value=record.interpreted,
        classification=rule.classification,
        explanation=explanation,
        action=rule.action,
        source=record.source,
    )


def _has_offset(value: str) -> bool:
    text = value.strip()
    if len(text) < 6 or "T" not in text and "+" not in text:
        return text.endswith("Z")
    return text.endswith("Z") or "+" in text[10:] or (text.rfind("-") > 10)


def build_findings(records: list[Record], facts: ImageFacts) -> list[Finding]:
    """Classify records, combining GPS latitude and longitude into one finding."""
    findings: list[Finding] = []
    latitudes = [record for record in records if record.field in {"GPSLatitude", "GPSLongitude"}]
    consumed: set[int] = set()
    if latitudes:
        rule = RULES[("GPS", "GPSLatitude")]
        value = "; ".join(f"{record.field} {record.interpreted}" for record in latitudes)
        findings.append(
            Finding(
                id=rule.id,
                name=rule.name,
                family="GPS",
                field="GPSLatitude",
                tag=latitudes[0].tag,
                value=sanitise(value),
                classification=rule.classification,
                explanation=rule.explanation,
                action=rule.action,
                source=latitudes[0].source,
            )
        )
        consumed.update(id(record) for record in latitudes)
    seen: set[str] = {finding.id for finding in findings}
    for record in records:
        if id(record) in consumed:
            continue
        finding = finding_from_record(record)
        if finding.id in seen and finding.id.startswith("exif.gps.timestamp"):
            continue
        seen.add(finding.id)
        findings.append(finding)
    if facts.preview:
        rule = RULES[("THUMBNAIL", "preview")]
        size = facts.preview_bytes or 0
        dimensions = ""
        if facts.preview_width and facts.preview_height:
            dimensions = f", {facts.preview_width} x {facts.preview_height}"
        separate = "stored separately from the main image" if facts.preview_separate else "embedded"
        extra = ""
        if (
            facts.preview_width
            and facts.preview_height
            and facts.width
            and facts.height
            and (facts.preview_width, facts.preview_height) != (facts.width, facts.height)
        ):
            extra = " Heuristic: the preview dimensions differ from the main image."
        findings.append(
            Finding(
                id=rule.id,
                name=rule.name,
                family="THUMBNAIL",
                field="preview",
                tag="thumbnail",
                value=f"yes, {size} bytes{dimensions}, {separate}",
                classification=rule.classification,
                explanation=rule.explanation + extra,
                action=rule.action,
                source="preview",
            )
        )
    if facts.icc:
        rule = RULES[("ICC", "profile")]
        findings.append(
            Finding(
                id=rule.id,
                name=rule.name,
                family="ICC",
                field="profile",
                tag="icc",
                value=f"{facts.icc_bytes} bytes",
                classification=rule.classification,
                explanation=rule.explanation,
                action=rule.action,
                source="icc",
            )
        )
    if facts.filesystem_mtime:
        rule = RULES[("FILESYSTEM", "mtime")]
        findings.append(
            Finding(
                id=rule.id,
                name=rule.name,
                family="FILESYSTEM",
                field="mtime",
                tag="mtime",
                value=facts.filesystem_mtime,
                classification=rule.classification,
                explanation=rule.explanation,
                action=rule.action,
                source="filesystem",
            )
        )
    return findings


def explain_field(field: str) -> str | None:
    """Return an offline explanation for a field name, if one exists."""
    for (family, name), rule in RULES.items():
        if name.lower() == field.lower() or rule.id.lower() == field.lower():
            return (
                f"{rule.name} ({family} {name}). {rule.explanation} {rule.action} "
                "Removing metadata does not anonymise the visible photograph."
            )
    return None
