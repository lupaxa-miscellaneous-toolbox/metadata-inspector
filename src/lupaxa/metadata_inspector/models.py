"""Shared data types for inspection, cleaning, and verification."""

from __future__ import annotations

from dataclasses import dataclass, field

SCHEMA_VERSION = "1.0"

CLASSIFICATIONS = ("high", "medium", "low", "informational")
SEVERITY_ORDER = {
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
}

EXIT_OK = 0
EXIT_OPERATIONAL = 1
EXIT_USAGE = 2
EXIT_POLICY = 3
EXIT_VERIFICATION = 4
EXIT_UNSUPPORTED = 5
EXIT_PARTIAL = 6

DISCLAIMER = (
    "Removing metadata does not remove identifying information that is visible in the photograph."
)
CLASSIFICATION_DISCLAIMER = (
    "A classification describes the metadata that was found. "
    "It does not prove that a privacy breach has occurred."
)
COMPARE_DISCLAIMER = (
    "Matching metadata is not proof that two photographs came from the "
    "same device or the same person."
)


@dataclass(frozen=True)
class Record:
    """One metadata field from an image."""

    family: str
    field: str
    tag: str
    interpreted: str
    raw: str
    source: str
    binary: bool = False


@dataclass(frozen=True)
class Finding:
    """A classified metadata finding."""

    id: str
    name: str
    family: str
    field: str
    tag: str
    value: str
    classification: str
    explanation: str
    action: str
    source: str


@dataclass
class ImageFacts:
    """Properties of the photograph that cleaning must be able to check."""

    width: int | None = None
    height: int | None = None
    mode: str | None = None
    orientation: int | None = None
    preview: bool = False
    preview_bytes: int | None = None
    preview_width: int | None = None
    preview_height: int | None = None
    preview_separate: bool | None = None
    icc: bool = False
    icc_bytes: int = 0
    filesystem_mtime: str | None = None


@dataclass
class Inspection:
    """The result of inspecting one file."""

    file: str
    format: str
    status: str
    backend: str
    findings: list[Finding] = field(default_factory=list)
    records: list[Record] = field(default_factory=list)
    facts: ImageFacts = field(default_factory=ImageFacts)
    limitations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        """Count findings by classification."""
        counts = dict.fromkeys(CLASSIFICATIONS, 0)
        for finding in self.findings:
            counts[finding.classification] = counts.get(finding.classification, 0) + 1
        return counts

    def families(self) -> list[str]:
        """Return metadata families in a stable order."""
        found = {record.family for record in self.records}
        found.update(finding.family for finding in self.findings)
        order = [
            "EXIF",
            "GPS",
            "IPTC",
            "XMP",
            "ICC",
            "TEXT",
            "THUMBNAIL",
            "CONTAINER",
            "FILESYSTEM",
        ]
        listed = [name for name in order if name in found]
        listed.extend(sorted(found.difference(listed)))
        return listed


@dataclass
class CleanResult:
    """The result of cleaning one file."""

    source: str
    output: str | None
    profile: str
    status: str
    dry_run: bool
    warnings: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    preserved: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    verification: str = "unsupported"
    pixels_modified: bool = False
    inspection: Inspection | None = None


@dataclass(frozen=True)
class Profile:
    """Rules for a cleaning profile."""

    name: str
    description: str
    remove_families: frozenset[str] = frozenset()
    remove_tags: frozenset[str] = frozenset()
    preserve_tags: frozenset[str] = frozenset()
    remove_classifications: frozenset[str] = frozenset()
    preserve_copyright: bool = False
    preserve_orientation: bool = True
    preserve_icc: bool = True
    remove_thumbnails: bool = True
    strict: bool = True


@dataclass(frozen=True)
class Settings:
    """Effective configuration after precedence is applied."""

    profile: str = "public"
    suffix: str = "-clean"
    report_format: str = "text"
    colour: bool = True
    max_file_size: int = 100 * 1024 * 1024
    max_depth: int = 32
    workers: int = 4
    follow_symlinks: bool = False
    backend: str = "python"
    redact: bool = True
    include_hidden: bool = False
    profiles: dict[str, Profile] = field(default_factory=dict)
