"""Pytest configuration: ensure pipeline/ root is importable as 'src'."""

import sys
from pathlib import Path

# Add pipeline/ root to sys.path so `from src.xxx import` resolves to pipeline/src/
_pipeline_root = str(Path(__file__).parent)
if _pipeline_root not in sys.path:
    sys.path.insert(0, _pipeline_root)
