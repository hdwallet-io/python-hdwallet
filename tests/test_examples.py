#!/usr/bin/env python3

import os
import subprocess
import pytest
from pathlib import Path


# Discover all example scripts
EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
EXAMPLE_SCRIPTS = sorted(EXAMPLES_DIR.rglob("*.py"))

# Project root directory (for PYTHONPATH)
PROJECT_ROOT = Path(__file__).parent.parent


@pytest.mark.examples
@pytest.mark.parametrize("script_path", EXAMPLE_SCRIPTS, ids=lambda p: str(p.relative_to(EXAMPLES_DIR)))
def test_example_script_runs(script_path):
    """Test that example scripts execute without raising exceptions."""
    # Set PYTHONPATH to use local source instead of installed package
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)

    result = subprocess.run(
        ["python3", str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
        env=env
    )

    assert result.returncode == 0, (
        f"Script {script_path.name} failed with exit code {result.returncode}\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )
