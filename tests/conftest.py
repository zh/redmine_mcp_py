"""Shared pytest fixtures."""
import sys
from pathlib import Path

# Make the project root importable from tests/
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
