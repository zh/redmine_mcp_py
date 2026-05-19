"""Shared pytest fixtures.

Every test gets a fresh `InMemoryTokenStore` installed as the module-level
singleton. Production wires the store via FastAPI's lifespan event, but
`TestClient` doesn't trigger lifespan unless used as a context manager —
explicit setup is simpler and gives us per-test isolation for free.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the project root importable from tests/
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auth.token_store import InMemoryTokenStore, set_store, reset_store_for_tests  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_token_store():
    """Reset the in-memory store before and after every test."""
    set_store(InMemoryTokenStore())
    yield
    reset_store_for_tests()
