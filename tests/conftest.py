from __future__ import annotations

from pathlib import Path

import pytest

from palisade.models import ServerSurface

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def benign() -> ServerSurface:
    return ServerSurface.load(str(FIXTURES / "benign.json"))


@pytest.fixture
def poisoned() -> ServerSurface:
    return ServerSurface.load(str(FIXTURES / "poisoned.json"))


@pytest.fixture
def colliding() -> ServerSurface:
    return ServerSurface.load(str(FIXTURES / "colliding.json"))


@pytest.fixture(autouse=True)
def isolated_pin_store(tmp_path, monkeypatch):
    """Never touch the developer's real pin database during tests."""
    monkeypatch.setenv("PALISADE_HOME", str(tmp_path / "palisade-home"))
