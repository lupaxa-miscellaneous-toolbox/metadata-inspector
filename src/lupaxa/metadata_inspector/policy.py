"""Cleaning profiles and the preserve-over-remove precedence."""

from __future__ import annotations

from .catalog import ATTRIBUTION_IDS, rule_for
from .models import CLASSIFICATIONS, Finding, Profile

PRECEDENCE = (
    "Preserve rules win over remove rules. A preserved tag is kept even when "
    "its family or classification is selected for removal. Orientation is kept "
    "when preserve_orientation is true. ICC profiles are kept when preserve_icc "
    "is true. Copyright and attribution are kept when preserve_copyright is true. "
    "Set those flags to false to allow removal. No profile guarantees anonymity."
)

_BUILTINS: dict[str, Profile] = {
    "metadata": Profile(
        name="metadata",
        description=(
            "Remove removable non-essential metadata and keep structural and "
            "rendering information, including orientation and ICC profiles."
        ),
        remove_classifications=frozenset({"high", "medium", "low", "informational"}),
        preserve_copyright=False,
        preserve_orientation=True,
        preserve_icc=True,
        remove_thumbnails=True,
        strict=True,
    ),
    "public": Profile(
        name="public",
        description=(
            "Remove information that is typically inappropriate for public "
            "sharing: GPS data, unique device identifiers, contact details, "
            "and other high or medium findings. Copyright and attribution stay."
        ),
        remove_classifications=frozenset({"high", "medium"}),
        preserve_copyright=True,
        preserve_orientation=True,
        preserve_icc=True,
        remove_thumbnails=True,
        strict=True,
    ),
    "anonymous": Profile(
        name="anonymous",
        description=(
            "Remove identifying metadata, including author and attribution fields. "
            "The photograph itself may remain identifiable."
        ),
        remove_classifications=frozenset({"high", "medium", "low"}),
        preserve_copyright=False,
        preserve_orientation=True,
        preserve_icc=True,
        remove_thumbnails=True,
        strict=True,
    ),
    "minimal": Profile(
        name="minimal",
        description=(
            "Remove as much non-essential metadata as possible while keeping "
            "orientation and colour information required for display."
        ),
        remove_classifications=frozenset({"high", "medium", "low", "informational"}),
        preserve_copyright=False,
        preserve_orientation=True,
        preserve_icc=True,
        remove_thumbnails=True,
        strict=True,
    ),
}


def builtin_profiles() -> dict[str, Profile]:
    """Return the built-in cleaning profiles."""
    return dict(_BUILTINS)


def should_remove(finding: Finding, profile: Profile) -> bool:
    """Decide whether a finding is removed, using documented precedence."""
    if finding.family == "FILESYSTEM":
        return False
    if finding.id in profile.preserve_tags or finding.field in profile.preserve_tags:
        return False
    if profile.preserve_orientation and finding.id == "exif.orientation":
        return False
    if profile.preserve_icc and finding.id == "icc.profile":
        return False
    if finding.id in ATTRIBUTION_IDS or _is_attribution(finding):
        return not profile.preserve_copyright
    if finding.id in profile.remove_tags or finding.field in profile.remove_tags:
        return True
    if finding.family in profile.remove_families:
        return True
    if finding.family == "THUMBNAIL" and profile.remove_thumbnails:
        return True
    return finding.classification in profile.remove_classifications


def _is_attribution(finding: Finding) -> bool:
    rule = rule_for(finding.family, finding.field)
    return rule.attribution or rule.id in ATTRIBUTION_IDS


def validate_profile(profile: Profile) -> None:
    """Reject a profile whose classification names are unknown."""
    unknown = profile.remove_classifications.difference(CLASSIFICATIONS)
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ValueError(f"unknown privacy classification in profile {profile.name}: {names}")


def profile_lines(profile: Profile) -> list[str]:
    """Describe a profile for the profiles command."""
    lines = [
        f"Profile: {profile.name}",
        profile.description,
        PRECEDENCE,
        f"Remove families: {_fmt(profile.remove_families)}",
        f"Remove tags: {_fmt(profile.remove_tags)}",
        f"Preserve tags: {_fmt(profile.preserve_tags)}",
        f"Remove classifications: {_fmt(profile.remove_classifications)}",
        f"Preserve copyright and attribution: {yes_no(profile.preserve_copyright)}",
        f"Preserve orientation: {yes_no(profile.preserve_orientation)}",
        f"Preserve ICC profile: {yes_no(profile.preserve_icc)}",
        f"Remove embedded previews: {yes_no(profile.remove_thumbnails)}",
        f"Strict verification: {yes_no(profile.strict)}",
        "This profile does not make a photograph anonymous.",
    ]
    return lines


def yes_no(value: bool) -> str:
    """Return yes or no."""
    return "yes" if value else "no"


def _fmt(values: frozenset[str]) -> str:
    if not values:
        return "(none)"
    return ", ".join(sorted(values))
