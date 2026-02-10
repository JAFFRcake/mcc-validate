"""Tests for the web-based validator."""

from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path

import pytest

flask = pytest.importorskip("flask")

from mcc_validate.web.app import create_app

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def client():
    """Flask test client."""
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestWebHealth:
    """Test health and index endpoints."""

    def test_health_endpoint(self, client) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_index_page(self, client) -> None:
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"MCC Certificate Validator" in resp.data
        assert b"drop" in resp.data.lower()


class TestWebValidation:
    """Test the /validate endpoint."""

    def test_validate_valid_certificate_html(self, client) -> None:
        cert_path = FIXTURES_DIR / "valid_tier1.json"
        with open(cert_path, "rb") as f:
            resp = client.post(
                "/validate?format=html",
                data={"certificate": (f, "cert.json")},
                content_type="multipart/form-data",
            )
        assert resp.status_code == 200
        assert b"VALID" in resp.data

    def test_validate_valid_certificate_json(self, client) -> None:
        cert_path = FIXTURES_DIR / "valid_tier1.json"
        with open(cert_path, "rb") as f:
            resp = client.post(
                "/validate?format=json",
                data={"certificate": (f, "cert.json")},
                content_type="multipart/form-data",
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["result"]["valid"] is True

    def test_validate_invalid_certificate(self, client) -> None:
        cert_path = FIXTURES_DIR / "invalid_missing_fields.json"
        with open(cert_path, "rb") as f:
            resp = client.post(
                "/validate?format=json",
                data={"certificate": (f, "cert.json")},
                content_type="multipart/form-data",
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["result"]["valid"] is False

    def test_validate_malformed_json(self, client) -> None:
        resp = client.post(
            "/validate",
            data={"certificate": (BytesIO(b"not json {{"), "bad.json")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 400

    def test_validate_json_body(self, client) -> None:
        cert_data = json.loads(
            (FIXTURES_DIR / "valid_tier1.json").read_text(encoding="utf-8")
        )
        resp = client.post(
            "/validate?format=json",
            json=cert_data,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "result" in data

    def test_validate_no_input(self, client) -> None:
        resp = client.post("/validate")
        assert resp.status_code == 400

    def test_validate_non_object(self, client) -> None:
        resp = client.post("/validate", json=[1, 2, 3])
        assert resp.status_code == 400

    def test_validate_tier3_certificate(self, client) -> None:
        cert_path = FIXTURES_DIR / "valid_tier3.json"
        with open(cert_path, "rb") as f:
            resp = client.post(
                "/validate?format=json",
                data={"certificate": (f, "cert.json")},
                content_type="multipart/form-data",
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "result" in data
