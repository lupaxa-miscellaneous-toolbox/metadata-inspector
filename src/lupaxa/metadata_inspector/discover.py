"""Find photographs and build safe output paths."""

from __future__ import annotations

import os
from pathlib import Path

KNOWN_SUFFIXES = {".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".heic", ".heif"}


class PathSafetyError(ValueError):
    """An output path would escape the destination directory."""


def collect_files(
    inputs: list[Path],
    *,
    recursive: bool,
    follow_symlinks: bool,
    include_hidden: bool,
    extensions: set[str] | None,
    max_depth: int,
    exclude: Path | None,
) -> list[Path]:
    """Return photograph paths in a stable order."""
    found: list[Path] = []
    for raw in inputs:
        path = raw.expanduser()
        if path.is_symlink() and not follow_symlinks:
            found.append(path)
            continue
        if path.is_file():
            found.append(path)
            continue
        if not path.is_dir():
            found.append(path)
            continue
        found.extend(
            _walk(
                path,
                recursive=recursive,
                follow_symlinks=follow_symlinks,
                include_hidden=include_hidden,
                extensions=extensions,
                max_depth=max_depth,
                exclude=exclude,
            )
        )
    unique = sorted({item.resolve() if not item.is_symlink() else item for item in found}, key=str)
    return unique


def _walk(
    root: Path,
    *,
    recursive: bool,
    follow_symlinks: bool,
    include_hidden: bool,
    extensions: set[str] | None,
    max_depth: int,
    exclude: Path | None,
) -> list[Path]:
    allowed = extensions if extensions is not None else KNOWN_SUFFIXES
    results: list[Path] = []
    if not recursive:
        for child in root.iterdir():
            if _wanted(child, include_hidden, allowed, follow_symlinks, exclude):
                results.append(child)
        return results
    root_depth = len(root.resolve().parts)
    for current, dirs, files in os.walk(root, followlinks=follow_symlinks):
        current_path = Path(current)
        depth = len(current_path.resolve().parts) - root_depth
        if depth > max_depth:
            dirs.clear()
            continue
        dirs[:] = [name for name in dirs if include_hidden or not name.startswith(".")]
        if not follow_symlinks:
            dirs[:] = [name for name in dirs if not (current_path / name).is_symlink()]
        for name in files:
            candidate = current_path / name
            if _wanted(candidate, include_hidden, allowed, follow_symlinks, exclude):
                results.append(candidate)
    return results


def _wanted(
    path: Path,
    include_hidden: bool,
    extensions: set[str],
    follow_symlinks: bool,
    exclude: Path | None,
) -> bool:
    if not include_hidden and any(part.startswith(".") for part in path.parts[-1:]):
        return False
    if path.is_symlink() and not follow_symlinks:
        return True
    if exclude is not None:
        try:
            path.resolve().relative_to(exclude.resolve())
        except ValueError:
            pass
        else:
            return False
    return path.suffix.lower() in extensions


def output_path(
    source: Path,
    inputs: list[Path],
    output: Path | None,
    suffix: str,
    *,
    as_directory: bool,
) -> Path:
    """Choose an output path that stays inside the destination directory."""
    if output is None:
        return source.with_name(f"{source.stem}{suffix}{source.suffix}")
    if as_directory:
        relative = _relative(source, inputs)
        destination = (output / relative).with_name(f"{relative.stem}{suffix}{relative.suffix}")
        resolved = destination.resolve()
        if not resolved.is_relative_to(output.resolve()):
            raise PathSafetyError("output path escapes the output directory")
        return destination
    return output


def _relative(source: Path, inputs: list[Path]) -> Path:
    resolved = source.resolve()
    for raw in inputs:
        root = raw.expanduser()
        base = root.resolve() if root.is_dir() else root.resolve().parent
        try:
            relative = resolved.relative_to(base)
        except ValueError:
            continue
        if ".." in relative.parts:
            raise PathSafetyError("output path escapes the output directory")
        return relative
    return Path(source.name)
