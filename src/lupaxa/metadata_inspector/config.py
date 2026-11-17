"""TOML configuration and platform config paths."""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path

from .models import Profile, Settings
from .policy import builtin_profiles, validate_profile

_BOOL = {"true": True, "false": False, "yes": True, "no": False, "1": True, "0": False}


class ConfigError(ValueError):
    """The configuration file cannot be used."""


def user_config_path() -> Path:
    """Return the platform configuration file path."""
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
        return base / "metadata-inspector" / "config.toml"
    if sys.platform == "darwin":
        return (
            Path.home() / "Library" / "Application Support" / "metadata-inspector" / "config.toml"
        )
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "metadata-inspector" / "config.toml"


def load_settings(explicit: Path | None = None, *, use_user_config: bool = True) -> Settings:
    """Load defaults, then the user file, then an explicit file."""
    settings = Settings(profiles=builtin_profiles())
    if use_user_config:
        path = user_config_path()
        if path.is_file():
            settings = _apply(settings, _read_toml(path), path)
    if explicit is not None:
        if not explicit.is_file():
            raise ConfigError(f"configuration file not found: {explicit}")
        settings = _apply(settings, _read_toml(explicit), explicit)
    return settings


def _read_toml(path: Path) -> dict[str, object]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from exc
    try:
        loaded = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        line = getattr(exc, "lineno", "?")
        message = getattr(exc, "msg", str(exc))
        raise ConfigError(f"{path}:{line}: {message}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError(f"{path}: the configuration must be a TOML table")
    return loaded


def _apply(settings: Settings, data: dict[str, object], path: Path) -> Settings:
    profiles = dict(settings.profiles)
    raw_profiles = data.get("profiles", {})
    if raw_profiles is None:
        raw_profiles = {}
    if not isinstance(raw_profiles, dict):
        raise ConfigError(f"{path}: profiles must be a table")
    for name, body in raw_profiles.items():
        if name in {"metadata", "public", "anonymous", "minimal"}:
            raise ConfigError(f"{path}: profile {name} is built in and cannot be replaced")
        if not isinstance(body, dict):
            raise ConfigError(f"{path}: profile {name} must be a table")
        profile = _profile_from_table(str(name), body, path)
        validate_profile(profile)
        profiles[profile.name] = profile
    return Settings(
        profile=_text(data, "default_profile", settings.profile, path),
        suffix=_text(data, "default_suffix", settings.suffix, path),
        report_format=_choice(
            data,
            "default_report_format",
            settings.report_format,
            {"text", "json", "markdown", "html", "csv"},
            path,
        ),
        colour=_bool(data, "colour", settings.colour, path),
        max_file_size=_positive(data, "max_file_size", settings.max_file_size, path),
        max_depth=_positive(data, "max_depth", settings.max_depth, path),
        workers=_positive(data, "workers", settings.workers, path),
        follow_symlinks=_bool(data, "follow_symlinks", settings.follow_symlinks, path),
        backend=_choice(data, "backend", settings.backend, {"python", "exiftool"}, path),
        redact=_bool(data, "redact", settings.redact, path),
        include_hidden=_bool(data, "include_hidden", settings.include_hidden, path),
        profiles=profiles,
    )


def _profile_from_table(name: str, body: dict[str, object], path: Path) -> Profile:
    base = Profile(
        name=name, description=_text(body, "description", f"Custom profile {name}.", path)
    )
    return Profile(
        name=name,
        description=base.description,
        remove_families=_strings(body, "remove_families", path),
        remove_tags=_strings(body, "remove_tags", path),
        preserve_tags=_strings(body, "preserve_tags", path),
        remove_classifications=_strings(body, "remove_classifications", path),
        preserve_copyright=_bool(body, "preserve_copyright", False, path),
        preserve_orientation=_bool(body, "preserve_orientation", True, path),
        preserve_icc=_bool(body, "preserve_icc", True, path),
        remove_thumbnails=_bool(body, "remove_thumbnails", True, path),
        strict=_bool(body, "strict", True, path),
    )


def _text(data: dict[str, object], key: str, default: str, path: Path) -> str:
    if key not in data:
        return default
    value = data[key]
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{path}: {key} must be a non-empty string")
    return value.strip()


def _choice(
    data: dict[str, object],
    key: str,
    default: str,
    allowed: set[str],
    path: Path,
) -> str:
    value = _text(data, key, default, path)
    if value not in allowed:
        names = ", ".join(sorted(allowed))
        raise ConfigError(f"{path}: {key} must be one of: {names}")
    return value


def _bool(data: dict[str, object], key: str, default: bool, path: Path) -> bool:
    if key not in data:
        return default
    value = data[key]
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in _BOOL:
        return _BOOL[value.strip().lower()]
    raise ConfigError(f"{path}: {key} must be true or false")


def _positive(data: dict[str, object], key: str, default: int, path: Path) -> int:
    if key not in data:
        return default
    value = data[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigError(f"{path}: {key} must be a positive integer")
    return value


def _strings(data: dict[str, object], key: str, path: Path) -> frozenset[str]:
    if key not in data:
        return frozenset()
    value = data[key]
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ConfigError(f"{path}: {key} must be a list of strings")
    return frozenset(item.strip() for item in value)
