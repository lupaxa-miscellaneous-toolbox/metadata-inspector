"""Command-line interface for Metadata Inspector."""

from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .config import ConfigError, load_settings
from .discover import PathSafetyError, collect_files, output_path
from .engine import (
    clean_file,
    inspect_path,
    verify_paths,
)
from .formats_cmd import capability_report, format_text
from .models import (
    CLASSIFICATION_DISCLAIMER,
    COMPARE_DISCLAIMER,
    DISCLAIMER,
    EXIT_OK,
    EXIT_OPERATIONAL,
    EXIT_PARTIAL,
    EXIT_POLICY,
    EXIT_UNSUPPORTED,
    EXIT_USAGE,
    EXIT_VERIFICATION,
    SEVERITY_ORDER,
    Inspection,
    Profile,
    Settings,
)
from .policy import PRECEDENCE, builtin_profiles, profile_lines, should_remove
from .render import (
    compare_payload,
    csv_report,
    dumps_json,
    dumps_json_lines,
    html_report,
    inspection_disclaimer,
    inspection_payload,
    markdown_report,
    media_fact_lines,
    text_clean,
    text_inspections,
)
from .sanitize import display_value
from .version import get_version

COMMANDS = (
    "scan",
    "show",
    "explain",
    "clean",
    "verify",
    "compare",
    "report",
    "check",
    "formats",
    "profiles",
    "version",
)


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return EXIT_OK
    if args.verbose and args.quiet:
        print("pass only one of --verbose and --quiet", file=sys.stderr)
        return EXIT_USAGE
    try:
        settings = load_settings(Path(args.config) if args.config else None)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE
    if settings.backend != "python":
        print(
            "the ExifTool backend is not available for inspection or cleaning; "
            'set backend to "python"',
            file=sys.stderr,
        )
        return EXIT_UNSUPPORTED
    try:
        return _dispatch(args, settings)
    except PathSafetyError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_OPERATIONAL


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser, including help for every command."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--recursive", "-r", action="store_true")
    common.add_argument("--format", choices=["text", "json", "markdown", "html", "csv"])
    common.add_argument("--output", "-o")
    common.add_argument("--profile")
    common.add_argument("--verbose", "-v", action="store_true")
    common.add_argument("--quiet", "-q", action="store_true")
    common.add_argument("--no-colour", action="store_true")
    common.add_argument("--json", action="store_true")
    common.add_argument("--json-lines", action="store_true")
    common.add_argument("--config")
    common.add_argument(
        "--reveal", action="store_true", help="Show GPS coordinates and serial numbers."
    )
    common.add_argument("--workers", type=int)
    common.add_argument("--extensions", help="Comma-separated file extensions.")
    common.add_argument("--hidden", action="store_true")
    common.add_argument("--follow-symlinks", action="store_true")
    common.add_argument("--max-size", type=int)
    parser = argparse.ArgumentParser(
        prog="metadata-inspector",
        description=(
            "Inspect, identify, remove, and independently verify privacy-sensitive "
            "metadata embedded in photographs. " + DISCLAIMER
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", parents=[common], help="Inspect one or more photographs.")
    scan.add_argument("paths", nargs="+")
    show = sub.add_parser("show", parents=[common], help="Display the metadata inventory.")
    show.add_argument("path")
    show.add_argument("--family")
    explain = sub.add_parser(
        "explain", parents=[common], help="Explain metadata and privacy implications."
    )
    explain.add_argument("path")
    explain.add_argument("--field")
    clean = sub.add_parser("clean", parents=[common], help="Write cleaned copies of photographs.")
    clean.add_argument("paths", nargs="+")
    clean.add_argument("--dry-run", action="store_true")
    clean.add_argument("--force", action="store_true")
    clean.add_argument("--suffix")
    clean.add_argument("--apply-orientation", action="store_true")
    clean.add_argument("--in-place", action="store_true")
    clean.add_argument("--no-backup", action="store_true")
    verify = sub.add_parser(
        "verify", parents=[common], help="Independently verify metadata cleaning."
    )
    verify.add_argument("paths", nargs="+")
    compare = sub.add_parser(
        "compare", parents=[common], help="Compare metadata between photographs."
    )
    compare.add_argument("paths", nargs=2)
    report = sub.add_parser("report", parents=[common], help="Generate an inspection report.")
    report.add_argument("paths", nargs="+")
    check = sub.add_parser("check", parents=[common], help="Apply a privacy policy for scripts.")
    check.add_argument("paths", nargs="+")
    check.add_argument("--fail-on", choices=list(SEVERITY_ORDER))
    sub.add_parser("formats", parents=[common], help="Show supported formats and backends.")
    profiles = sub.add_parser("profiles", parents=[common], help="Show cleaning profiles.")
    profiles.add_argument("action", nargs="?", choices=["show"])
    profiles.add_argument("name", nargs="?")
    sub.add_parser("version", parents=[common], help="Show application and backend versions.")
    return parser


def _dispatch(args: argparse.Namespace, settings: Settings) -> int:
    command = str(args.command)
    if command == "version":
        return _version(args)
    if command == "formats":
        return _formats(args)
    if command == "profiles":
        return _profiles(args, settings)
    if command == "show":
        return _show(args, settings)
    if command == "explain":
        return _explain(args, settings)
    if command == "compare":
        return _compare(args, settings)
    if command == "verify":
        return _verify(args, settings)
    if command == "clean":
        return _clean(args, settings)
    if command == "check":
        return _check(args, settings)
    return _report_command(args, settings, policy=False)


def _version(args: argparse.Namespace) -> int:
    report = capability_report()
    payload = {
        "metadata-inspector": get_version(),
        "backend": report["backend"],
        "exiftool": report["exiftool"],
    }
    _emit(
        args,
        dumps_json(payload) + "\n",
        f"metadata-inspector {get_version()}\n{report['backend']}\n"
        f"ExifTool: {report['exiftool'] or 'not installed'}\n",
    )
    return EXIT_OK


def _formats(args: argparse.Namespace) -> int:
    report = capability_report()
    _emit(args, dumps_json(report) + "\n", format_text(report))
    return EXIT_OK


def _profiles(args: argparse.Namespace, settings: Settings) -> int:
    profiles = dict(builtin_profiles())
    profiles.update(settings.profiles)
    if args.action == "show":
        if not args.name or args.name not in profiles:
            print("name a profile to show", file=sys.stderr)
            return EXIT_USAGE
        profile = profiles[args.name]
        payload = {
            "name": profile.name,
            "description": profile.description,
            "precedence": PRECEDENCE,
        }
        _emit(args, dumps_json(payload) + "\n", "\n".join(profile_lines(profile)) + "\n")
        return EXIT_OK
    lines = [f"{name}: {profile.description}" for name, profile in profiles.items()]
    lines.append(PRECEDENCE)
    _emit(args, dumps_json({"profiles": list(profiles)}) + "\n", "\n".join(lines) + "\n")
    return EXIT_OK


def _show(args: argparse.Namespace, settings: Settings) -> int:
    max_file_size, max_video_size = size_limits(args, settings)
    inspection = inspect_path(
        Path(args.path), max_file_size=max_file_size, max_video_size=max_video_size
    )
    if args.json or args.format == "json":
        print(dumps_json(inspection_payload(inspection, reveal=_reveal(args, settings))))
        return _status_exit([inspection])
    family = args.family.upper() if args.family else None
    lines = [
        f"File: {inspection.file}",
        f"Format: {inspection.format}",
        f"Status: {inspection.status}",
    ]
    lines.extend(media_fact_lines(inspection))
    lines.append("")
    current = None
    for record in inspection.records:
        if family and record.family.upper() != family:
            continue
        if record.family != current:
            current = record.family
            lines.append(current)
        lines.append(f"  {record.field} ({record.tag}): {record.interpreted}")
        if record.raw != record.interpreted:
            lines.append(f"    raw: {record.raw}")
    if not lines[-1]:
        lines.append("No metadata records.")
    lines.append(inspection_disclaimer(inspection.format))
    print("\n".join(lines))
    return _status_exit([inspection])


def _explain(args: argparse.Namespace, settings: Settings) -> int:
    max_file_size, max_video_size = size_limits(args, settings)
    inspection = inspect_path(
        Path(args.path), max_file_size=max_file_size, max_video_size=max_video_size
    )
    chosen = inspection.findings
    if args.field:
        needle = args.field.lower()
        chosen = [
            finding
            for finding in inspection.findings
            if needle in {finding.field.lower(), finding.id.lower(), finding.name.lower()}
        ]
        if not chosen:
            print(f"no metadata field matched {args.field}", file=sys.stderr)
            return EXIT_USAGE
    blocks = [CLASSIFICATION_DISCLAIMER, ""]
    for finding in chosen:
        value = display_value(finding.id, finding.value, reveal=_reveal(args, settings))
        blocks.append(
            f"{finding.name}\n  Field: {finding.field}\n"
            f"  Classification: {finding.classification}\n"
            f"  Value: {value}\n  {finding.explanation}\n  {finding.action}"
        )
    blocks.append(inspection_disclaimer(inspection.format))
    text = "\n\n".join(blocks) + "\n"
    if args.json or args.format == "json":
        print(
            dumps_json([inspection_payload(inspection, reveal=_reveal(args, settings))["findings"]])
        )
    else:
        print(text, end="")
    return _status_exit([inspection])


def _compare(args: argparse.Namespace, settings: Settings) -> int:
    max_file_size, max_video_size = size_limits(args, settings)
    inspections = [
        inspect_path(Path(path), max_file_size=max_file_size, max_video_size=max_video_size)
        for path in args.paths
    ]
    payload = compare_payload(inspections[0], inspections[1], reveal=_reveal(args, settings))
    if args.json or args.format == "json":
        print(dumps_json(payload))
    else:
        print(f"Compare: {inspections[0].file} and {inspections[1].file}")
        exact = payload["exact"]
        different = payload["different"]
        if isinstance(exact, list):
            print("Exact matches:")
            for item in exact:
                if isinstance(item, dict):
                    print(f"  {item['name']}")
        if isinstance(different, list):
            print("Different values:")
            for item in different:
                if isinstance(item, dict):
                    print(f"  {item['name']}")
        print(COMPARE_DISCLAIMER)
    return _status_exit(inspections)


def _verify(args: argparse.Namespace, settings: Settings) -> int:
    if len(args.paths) not in {1, 2}:
        print(
            "verify takes the cleaned file, or the original and the cleaned file", file=sys.stderr
        )
        return EXIT_USAGE
    profile = _profile(args, settings, default="public")
    if isinstance(profile, int):
        return profile
    max_file_size, max_video_size = size_limits(args, settings)
    if len(args.paths) == 1:
        inspection = inspect_path(
            Path(args.paths[0]), max_file_size=max_file_size, max_video_size=max_video_size
        )
        prohibited = [
            finding.name for finding in inspection.findings if should_remove(finding, profile)
        ]
        status = "failed" if prohibited else "passed"
        if inspection.status != "completed":
            status = "incomplete" if inspection.status == "incomplete" else "unsupported"
        text = (
            f"Verification: {args.paths[0]}\nVerification: {status.upper()}\n"
            f"{inspection_disclaimer(inspection.format)}\n"
        )
        if prohibited:
            text = "Remaining prohibited metadata: " + ", ".join(prohibited) + "\n" + text
    else:
        status, removed, preserved, limits = verify_paths(
            Path(args.paths[0]),
            Path(args.paths[1]),
            profile,
            max_file_size=max_file_size,
            max_video_size=max_video_size,
        )
        text = (
            f"Verification: {args.paths[1]}\n"
            f"Removed: {', '.join(removed) or '(none)'}\n"
            "Preserved: "
            + (
                ", ".join(item for item in preserved if not item.startswith("Remaining:"))
                or "(none)"
            )
            + "\n"
            f"Verification: {status.upper()}\n{DISCLAIMER}\n"
        )
        if limits:
            text += "\n".join(limits) + "\n"
    if args.json or args.format == "json":
        print(dumps_json({"verification": status, "profile": profile.name}))
    else:
        print(text, end="")
    return _verification_exit(status)


def _clean(args: argparse.Namespace, settings: Settings) -> int:
    profile = _profile(args, settings, default=settings.profile)
    if isinstance(profile, int):
        return profile
    paths = _inputs(args, settings)
    if isinstance(paths, int):
        return paths
    output = Path(args.output).expanduser() if args.output else None
    as_directory = _output_is_directory(output, len(paths))
    if output is not None and as_directory:
        output.mkdir(parents=True, exist_ok=True)
    suffix = args.suffix or settings.suffix
    max_file_size, max_video_size = size_limits(args, settings)
    results = []
    for source in paths:
        if _skip_generated(source, suffix, output):
            continue
        destination = output_path(
            source, [Path(path) for path in args.paths], output, suffix, as_directory=as_directory
        )
        results.append(
            clean_file(
                source,
                destination,
                profile,
                max_file_size=max_file_size,
                max_video_size=max_video_size,
                dry_run=args.dry_run,
                force=args.force,
                apply_orientation=args.apply_orientation,
                in_place=args.in_place,
                backup=not args.no_backup,
            )
        )
    if not results:
        print("no photographs matched", file=sys.stderr)
        return EXIT_USAGE
    text = "".join(text_clean(result) for result in results)
    payload = [
        {
            "source": result.source,
            "output": result.output,
            "status": result.status,
            "verification": result.verification,
            "removed": result.removed,
            "warnings": result.warnings,
            "errors": result.errors,
        }
        for result in results
    ]
    _emit(args, dumps_json(payload) + "\n", text)
    statuses = {result.status for result in results}
    if statuses <= {"cleaned", "dry-run"}:
        return EXIT_OK
    if "cleaned" in statuses or "dry-run" in statuses:
        return EXIT_PARTIAL
    if statuses <= {"unsupported"}:
        return EXIT_UNSUPPORTED
    if any(result.verification == "failed" for result in results):
        return EXIT_VERIFICATION
    return EXIT_OPERATIONAL


def _check(args: argparse.Namespace, settings: Settings) -> int:
    profile = _profile(args, settings, default="public")
    if isinstance(profile, int):
        return profile
    inspections = _inspect_many(args, settings)
    if isinstance(inspections, int):
        return inspections
    violations = []
    problems = []
    for inspection in inspections:
        if inspection.status != "completed":
            problems.append(inspection.file)
            continue
        for finding in inspection.findings:
            if _violation(finding, profile, args.fail_on):
                violations.append(f"{inspection.file}: {finding.name} ({finding.classification})")
    payload = {
        "profile": profile.name,
        "violations": violations,
        "inspection_errors": problems,
        "results": [
            inspection_payload(item, reveal=_reveal(args, settings)) for item in inspections
        ],
    }
    text = "Privacy check\n" + "\n".join(violations or ["No policy violations."])
    if problems:
        text += "\nInspection errors:\n" + "\n".join(problems)
    text += "\n"
    _emit(args, dumps_json(payload) + "\n", text)
    if violations:
        return EXIT_POLICY
    if problems:
        return EXIT_OPERATIONAL
    return EXIT_OK


def _report_command(args: argparse.Namespace, settings: Settings, *, policy: bool) -> int:
    del policy
    inspections = _inspect_many(args, settings)
    if isinstance(inspections, int):
        return inspections
    kind = _kind(args, settings)
    reveal = _reveal(args, settings)
    if args.json_lines:
        rendered = dumps_json_lines(inspection_payload(item, reveal=reveal) for item in inspections)
    elif kind == "json" or args.json:
        rendered = (
            dumps_json(
                {
                    "schema_version": "1.0",
                    "results": [inspection_payload(item, reveal=reveal) for item in inspections],
                }
            )
            + "\n"
        )
    elif kind == "markdown":
        rendered = markdown_report(inspections, reveal=reveal)
    elif kind == "html":
        rendered = html_report(inspections, reveal=reveal)
    elif kind == "csv":
        rendered = csv_report(inspections)
    else:
        rendered = text_inspections(
            inspections,
            reveal=reveal,
            colour=_colour(args, settings),
            verbose=args.verbose,
        )
    if args.output and args.command == "report":
        destination = Path(args.output)
        destination.write_text(rendered, encoding="utf-8")
        if not args.quiet:
            print(f"Wrote {destination}", file=sys.stderr)
    elif not args.quiet or kind != "text":
        print(rendered, end="" if rendered.endswith("\n") else "\n")
    return _status_exit(inspections)


def _inspect_many(args: argparse.Namespace, settings: Settings) -> list[Inspection] | int:
    paths = _inputs(args, settings)
    if isinstance(paths, int):
        return paths
    workers = args.workers or settings.workers
    if workers < 1:
        print("--workers must be a positive integer", file=sys.stderr)
        return EXIT_USAGE
    max_file_size, max_video_size = size_limits(args, settings)

    def _one(path: Path) -> Inspection:
        if args.verbose and not (args.json or args.format == "json"):
            print(f"inspect {path}", file=sys.stderr)
        return inspect_path(path, max_file_size=max_file_size, max_video_size=max_video_size)

    if workers == 1 or len(paths) == 1:
        return [_one(path) for path in paths]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(_one, paths))


def _inputs(args: argparse.Namespace, settings: Settings) -> list[Path] | int:
    extensions = None
    if args.extensions:
        extensions = set()
        for item in str(args.extensions).split(","):
            token = item.strip().lower()
            if not token:
                continue
            extensions.add(token if token.startswith(".") else f".{token}")
    output = (
        Path(args.output).expanduser().resolve()
        if args.output and args.command == "clean"
        else None
    )
    paths = collect_files(
        [Path(path) for path in args.paths],
        recursive=args.recursive,
        follow_symlinks=args.follow_symlinks or settings.follow_symlinks,
        include_hidden=args.hidden or settings.include_hidden,
        extensions=extensions,
        max_depth=settings.max_depth,
        exclude=output if output and (output.is_dir() or args.recursive) else None,
    )
    if not paths:
        print("no photographs matched", file=sys.stderr)
        return EXIT_USAGE
    return paths


def _profile(args: argparse.Namespace, settings: Settings, *, default: str) -> Profile | int:
    name = args.profile or default
    profiles = dict(builtin_profiles())
    profiles.update(settings.profiles)
    if name not in profiles:
        print(f"unknown profile: {name}", file=sys.stderr)
        return EXIT_USAGE
    return profiles[name]


def _emit(args: argparse.Namespace, json_text: str, plain: str) -> None:
    if args.json or args.format == "json":
        print(json_text, end="" if json_text.endswith("\n") else "\n")
        return
    if not args.quiet:
        print(plain, end="" if plain.endswith("\n") else "\n")


def _kind(args: argparse.Namespace, settings: Settings) -> str:
    if args.json:
        return "json"
    return args.format or settings.report_format


def _reveal(args: argparse.Namespace, settings: Settings) -> bool:
    return bool(args.reveal or not settings.redact)


def _colour(args: argparse.Namespace, settings: Settings) -> bool:
    if args.no_colour or os.environ.get("NO_COLOR") or not settings.colour:
        return False
    return sys.stdout.isatty()


def size_limits(args: argparse.Namespace, settings: Settings) -> tuple[int, int]:
    """Return the photograph ceiling and the video ceiling."""
    if args.max_size:
        chosen = int(args.max_size)
        return chosen, chosen
    return settings.max_file_size, settings.max_video_size


def _output_is_directory(output: Path | None, count: int) -> bool:
    if output is None:
        return False
    if count > 1:
        return True
    if output.exists():
        return output.is_dir()
    return output.suffix == ""


def _skip_generated(source: Path, suffix: str, output: Path | None) -> bool:
    if output is not None and output.resolve() != source.parent.resolve():
        return False
    return source.stem.endswith(suffix)


def _violation(finding: object, profile: Profile, fail_on: str | None) -> bool:
    if not hasattr(finding, "classification"):
        return False
    from .models import Finding as FindingType

    if not isinstance(finding, FindingType):
        return False
    if should_remove(finding, profile) and finding.family != "FILESYSTEM":
        return True
    if fail_on is None:
        return False
    return SEVERITY_ORDER[finding.classification] >= SEVERITY_ORDER[fail_on]


def _status_exit(inspections: list[Inspection]) -> int:
    if not inspections:
        return EXIT_USAGE
    statuses = {item.status for item in inspections}
    if statuses == {"completed"}:
        return EXIT_OK
    if statuses <= {"unsupported"}:
        return EXIT_UNSUPPORTED
    if "completed" in statuses:
        return EXIT_PARTIAL
    if statuses <= {"error"}:
        return EXIT_OPERATIONAL
    return EXIT_PARTIAL if "incomplete" in statuses and len(statuses) > 1 else EXIT_OPERATIONAL


def _verification_exit(status: str) -> int:
    if status == "passed":
        return EXIT_OK
    if status == "failed":
        return EXIT_VERIFICATION
    if status == "unsupported":
        return EXIT_UNSUPPORTED
    return EXIT_OPERATIONAL


if __name__ == "__main__":
    raise SystemExit(main())
