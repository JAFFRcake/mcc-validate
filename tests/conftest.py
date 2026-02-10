"""Shared test fixtures for MCC Validator tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def valid_tier1() -> dict:
    return json.loads((FIXTURES_DIR / "valid_tier1.json").read_text(encoding="utf-8"))


@pytest.fixture
def valid_tier3() -> dict:
    return json.loads((FIXTURES_DIR / "valid_tier3.json").read_text(encoding="utf-8"))


@pytest.fixture
def invalid_missing_fields() -> dict:
    return json.loads((FIXTURES_DIR / "invalid_missing_fields.json").read_text(encoding="utf-8"))


@pytest.fixture
def invalid_tier_mismatch() -> dict:
    return json.loads((FIXTURES_DIR / "invalid_tier_mismatch.json").read_text(encoding="utf-8"))


@pytest.fixture
def composite_system() -> dict:
    return json.loads((FIXTURES_DIR / "composite_system.json").read_text(encoding="utf-8"))


@pytest.fixture
def components_dir() -> Path:
    return FIXTURES_DIR / "components"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR
