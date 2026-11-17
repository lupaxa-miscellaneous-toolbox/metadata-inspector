"""Render inspections and cleaning results for people and for scripts."""

from __future__ import annotations

import csv
import html
import io
import json
from collections.abc import Iterable

from .models import (
    CLASSIFICATION_DISCLAIMER,
    CLASSIFICATIONS,
    COMPARE_DISCLAIMER,
    DISCLAIMER,
    SCHEMA_VERSION,
    CleanResult,
    Finding,
    Inspection,
)
from .sanitize import display_value

_COLOURS = {
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "informational": "\033[2m",
}
_RESET = "\033[0m"
_SOUNDTRACK = (
    " Removing metadata does not remove identifying information in the picture or the soundtrack."
)


def inspection_disclaimer(image_format: str) -> str:
    """Return the disclaimer for one inspected format."""
    if image_format == "bmff":
        return DISCLAIMER + _SOUNDTRACK
    return DISCLAIMER


def media_fact_lines(inspection: Inspection) -> list[str]:
    """Return duration, video codec, and audio lines when those facts are present."""
    lines: list[str] = []
    facts = inspection.facts
    if facts.duration_seconds is not None:
        lines.append(f"Duration: {facts.duration_seconds}")
    if facts.video_codec is not None:
        lines.append(f"Video codec: {facts.video_codec}")
    for track in facts.audio_tracks:
        lines.append(
            f"Audio: {track.get('codec')}, {track.get('channels')} channels, "
            f"{track.get('sample_rate')} Hz"
        )
    return lines


def inspection_payload(inspection: Inspection, *, reveal: bool) -> dict[str, object]:
    """Build the stable JSON object for one inspection."""
    return {
        "schema_version": SCHEMA_VERSION,
        "file": inspection.file,
        "format": inspection.format,
        "inspection_status": inspection.status,
        "backend": inspection.backend,
        "width": inspection.facts.width,
        "height": inspection.facts.height,
        "duration_seconds": inspection.facts.duration_seconds,
        "video_codec": inspection.facts.video_codec,
        "audio_tracks": inspection.facts.audio_tracks,
        "families": inspection.families(),
        "findings": [_finding_payload(finding, reveal=reveal) for finding in inspection.findings],
        "summary": inspection.summary(),
        "limitations": inspection.limitations,
        "errors": inspection.errors,
        "disclaimer": inspection_disclaimer(inspection.format),
    }


def _finding_payload(finding: Finding, *, reveal: bool) -> dict[str, object]:
    value = display_value(finding.id, finding.value, reveal=reveal)
    return {
        "id": finding.id,
        "name": finding.name,
        "family": finding.family,
        "field": finding.field,
        "tag": finding.tag,
        "classification": finding.classification,
        "value": value,
        "redacted": value == "[redacted]",
        "explanation": finding.explanation,
        "action": finding.action,
        "source": finding.source,
    }


def dumps_json(payload: object) -> str:
    """Serialise one JSON document."""
    return json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False)


def dumps_json_lines(items: Iterable[object]) -> str:
    """Serialise JSON Lines."""
    return "\n".join(json.dumps(item, ensure_ascii=False, allow_nan=False) for item in items) + "\n"


def text_inspections(
    inspections: list[Inspection],
    *,
    reveal: bool,
    colour: bool,
    verbose: bool,
) -> str:
    """Render the scan report used in the terminal."""
    blocks = [
        text_inspection(inspection, reveal=reveal, colour=colour, verbose=verbose)
        for inspection in inspections
    ]
    if len(inspections) > 1:
        blocks.append(_aggregate(inspections))
    if any(inspection.format == "bmff" for inspection in inspections):
        blocks.append(inspection_disclaimer("bmff"))
    else:
        blocks.append(DISCLAIMER)
    return "\n\n".join(blocks) + "\n"


def text_inspection(
    inspection: Inspection,
    *,
    reveal: bool,
    colour: bool,
    verbose: bool,
) -> str:
    """Render one file."""
    lines = [
        "Metadata Inspector",
        "",
        f"File: {inspection.file}",
        f"Format: {inspection.format.upper()}",
    ]
    if inspection.facts.width and inspection.facts.height:
        lines.append(f"Dimensions: {inspection.facts.width} x {inspection.facts.height}")
    lines.extend(media_fact_lines(inspection))
    if inspection.errors:
        lines.append("Errors: " + "; ".join(inspection.errors))
    visible = [
        finding
        for finding in inspection.findings
        if finding.family != "FILESYSTEM"
        and (verbose or finding.classification in {"high", "medium", "low"})
    ]
    if visible:
        lines.extend(["", "Privacy findings:"])
        for finding in visible:
            label = finding.classification.upper().ljust(13)
            if colour:
                paint = _COLOURS.get(finding.classification, "")
                label = f"{paint}{label}{_RESET}"
            value = display_value(finding.id, finding.value, reveal=reveal)
            lines.append(f"  {label}{finding.name}: {value}")
    lines.append(f"Embedded preview: {'Yes' if inspection.facts.preview else 'No'}")
    if inspection.facts.preview:
        lines.append(
            "  " + _preview_detail(inspection) + ". The built-in profiles remove embedded previews."
        )
    lines.append("Metadata families: " + (", ".join(inspection.families()) or "(none)"))
    summary = inspection.summary()
    lines.extend(
        [
            "",
            "Summary:",
            f"  High: {summary['high']}",
            f"  Medium: {summary['medium']}",
            f"  Low: {summary['low']}",
            f"  Informational: {summary['informational']}",
            "",
            "Suggested action:",
            "  " + _suggestion(summary),
        ]
    )
    if inspection.limitations:
        lines.extend(["", "Limitations:"])
        lines.extend(f"  {item}" for item in inspection.limitations)
    if verbose:
        lines.extend(["", CLASSIFICATION_DISCLAIMER])
    return "\n".join(lines)


def _preview_detail(inspection: Inspection) -> str:
    facts = inspection.facts
    parts = ["stored separately from the main image" if facts.preview_separate else "embedded"]
    if facts.preview_bytes is not None:
        parts.append(f"about {facts.preview_bytes} bytes")
    if facts.preview_width and facts.preview_height:
        parts.append(f"{facts.preview_width} x {facts.preview_height}")
    return ", ".join(parts)


def _suggestion(summary: dict[str, int]) -> str:
    if summary["high"] or summary["medium"]:
        return "Clean using the public profile before sharing."
    if summary["low"]:
        return "Review the remaining metadata before sharing."
    return "No privacy-sensitive metadata was found."


def _aggregate(inspections: list[Inspection]) -> str:
    totals = dict.fromkeys(CLASSIFICATIONS, 0)
    for inspection in inspections:
        for name, count in inspection.summary().items():
            totals[name] += count
    return (
        "Batch summary:\n"
        f"  Files: {len(inspections)}\n"
        f"  High: {totals['high']}\n"
        f"  Medium: {totals['medium']}\n"
        f"  Low: {totals['low']}"
    )


def markdown_report(inspections: list[Inspection], *, reveal: bool) -> str:
    """Render a Markdown report."""
    lines = [
        "# Metadata Inspector",
        "",
        DISCLAIMER,
        "",
        f"Schema version: {SCHEMA_VERSION}",
        "",
    ]
    for inspection in inspections:
        lines.extend(
            [
                f"## {inspection.file}",
                "",
                f"- Format: {inspection.format}",
                f"- Status: {inspection.status}",
                f"- Backend: {inspection.backend}",
                "",
                "| Classification | Name | Value |",
                "| --- | --- | --- |",
            ]
        )
        for finding in inspection.findings:
            value = display_value(finding.id, finding.value, reveal=reveal).replace("|", "\\|")
            lines.append(f"| {finding.classification} | {finding.name} | {value} |")
        lines.append("")
    return "\n".join(lines)


def html_report(inspections: list[Inspection], *, reveal: bool) -> str:
    """Render a self-contained HTML report."""
    rows: list[str] = []
    for inspection in inspections:
        body = "".join(
            (
                f"<tr><td>{html.escape(finding.classification)}</td>"
                f"<td>{html.escape(finding.name)}</td>"
                "<td>"
                f"{html.escape(display_value(finding.id, finding.value, reveal=reveal))}"
                "</td></tr>"
            )
            for finding in inspection.findings
        )
        rows.append(
            f"<section><h2>{html.escape(inspection.file)}</h2>"
            f"<p>Format: {html.escape(inspection.format)} · "
            f"Status: {html.escape(inspection.status)} · "
            f"Backend: {html.escape(inspection.backend)}</p>"
            f"<table>{body}</table></section>"
        )
    style = (
        "body{font-family:sans-serif;margin:2rem;}table{border-collapse:collapse;}"
        "td,th{border:1px solid #ccc;padding:0.3rem 0.6rem;}"
    )
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        f"<title>Metadata Inspector</title><style>{style}</style></head><body>"
        "<h1>Metadata Inspector</h1>"
        f"<p>{html.escape(DISCLAIMER)}</p>" + "".join(rows) + "</body></html>\n"
    )


def csv_report(inspections: list[Inspection]) -> str:
    """Render one summary row per file."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "file",
            "format",
            "status",
            "high",
            "medium",
            "low",
            "informational",
            "backend",
        ]
    )
    for inspection in inspections:
        summary = inspection.summary()
        writer.writerow(
            [
                inspection.file,
                inspection.format,
                inspection.status,
                summary["high"],
                summary["medium"],
                summary["low"],
                summary["informational"],
                inspection.backend,
            ]
        )
    return buffer.getvalue()


def text_clean(result: CleanResult) -> str:
    """Render one cleaning result."""
    lines = [
        f"Clean: {result.source}",
        f"Profile: {result.profile}",
        f"Status: {result.status}",
        f"Verification: {result.verification.upper()}",
    ]
    if result.output:
        lines.append(f"Output: {result.output}")
    if result.removed:
        lines.append("Removed: " + ", ".join(result.removed))
    if result.preserved:
        lines.append("Preserved: " + ", ".join(result.preserved))
    if result.pixels_modified:
        lines.append("Pixels were modified because orientation was applied.")
    lines.extend(f"Warning: {warning}" for warning in result.warnings)
    lines.extend(f"Limitation: {item}" for item in result.limitations)
    lines.extend(f"Error: {item}" for item in result.errors)
    lines.append(DISCLAIMER)
    return "\n".join(lines) + "\n"


def compare_payload(left: Inspection, right: Inspection, *, reveal: bool) -> dict[str, object]:
    """Compare two inspections without treating a match as proof of identity."""
    left_map = {finding.id: finding for finding in left.findings}
    right_map = {finding.id: finding for finding in right.findings}
    exact = []
    different = []
    for key in sorted(set(left_map).intersection(right_map)):
        if left_map[key].family == "FILESYSTEM":
            continue
        one = display_value(key, left_map[key].value, reveal=reveal)
        two = display_value(key, right_map[key].value, reveal=reveal)
        item = {
            "id": key,
            "name": left_map[key].name,
            "match": "exact" if one == two else "different",
        }
        if one == two:
            exact.append(item)
        else:
            different.append(item)
    heuristic = _heuristic(left, right)
    return {
        "schema_version": SCHEMA_VERSION,
        "files": [left.file, right.file],
        "exact": exact,
        "different": different,
        "heuristic": heuristic,
        "disclaimer": COMPARE_DISCLAIMER,
    }


def _heuristic(left: Inspection, right: Inspection) -> list[dict[str, str]]:
    notes: list[dict[str, str]] = []
    left_times = {
        finding.value
        for finding in left.findings
        if "datetime" in finding.id or finding.id.endswith("timestamp")
    }
    right_times = {
        finding.value
        for finding in right.findings
        if "datetime" in finding.id or finding.id.endswith("timestamp")
    }
    if left_times and right_times and left_times != right_times:
        notes.append(
            {
                "kind": "timestamp",
                "match": "heuristic",
                "note": "Both files have timestamps, but the values are not identical.",
            }
        )
    return notes
