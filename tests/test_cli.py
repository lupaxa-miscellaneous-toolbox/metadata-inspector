"""Smoke tests for the metadata-inspector command."""

from __future__ import annotations

import pytest

from lupaxa.metadata_inspector.cli import main
from lupaxa.metadata_inspector.version import get_version


def test_version_command(capsys: pytest.CaptureFixture[str]) -> None:
    """``version`` prints the application name and the package version."""
    assert main(["version"]) == 0
    captured = capsys.readouterr()
    assert captured.out.startswith(f"metadata-inspector {get_version()}")
    assert "Pillow" in captured.out
    assert captured.err == ""


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    """``--version`` exits successfully and names the package version."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == f"metadata-inspector {get_version()}"
