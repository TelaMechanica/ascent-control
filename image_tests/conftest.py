"""Opt-in tests import the standalone source without installing a package."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'firmware/mode_a'))
