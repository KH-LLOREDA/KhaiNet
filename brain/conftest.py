"""Pytest configuration: ensure src/ is importable."""

import sys
from pathlib import Path

# Add brain/ root to sys.path so `src` package is importable
sys.path.insert(0, str(Path(__file__).parent))
