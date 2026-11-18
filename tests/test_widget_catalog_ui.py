"""Actual first-party catalog DOM/controller contracts; no browser/device claims."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_text_only_catalog_actions_truth_navigation_and_late_responses():
    result = subprocess.run(['node', 'tests/widget_catalog_render.cjs'], cwd=ROOT,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
