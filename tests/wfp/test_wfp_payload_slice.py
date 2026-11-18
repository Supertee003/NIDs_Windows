"""Compile and exercise the exact pure-C payload-offset helper used by WFP."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / "tests" / "wfp" / "wfp_payload_slice_test.c"
INCLUDE = REPO / "drivers" / "wfp_callout"


def test_wfp_payload_slice_c_regression(tmp_path: Path) -> None:
    compiler = shutil.which("cc") or shutil.which("clang")
    if compiler:
        command = [compiler]
    else:
        zig = shutil.which("zig")
        if not zig:
            pytest.skip("requires cc, clang, or zig cc to compile the shared C helper")
        command = [zig, "cc"]

    executable = tmp_path / ("wfp_payload_slice.exe" if os.name == "nt" else "wfp_payload_slice")
    subprocess.run(
        [
            *command,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            f"-I{INCLUDE}",
            str(SOURCE),
            "-o",
            str(executable),
        ],
        check=True,
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    result = subprocess.run(
        [str(executable)],
        check=True,
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    assert "PASS (5 cases)" in result.stdout
