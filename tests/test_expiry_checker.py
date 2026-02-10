"""Tests for Layer 4: Lifecycle and temporal checks."""

from __future__ import annotations

import copy
from datetime import date, timedelta

from mcc_validate.core.expiry_checker import check_lifecycle
from mcc_validate.models import Severity, ValidationLayer


def _make_cert(
    issued: str | None = None,
    expires: str | None = None,
    tier: int = 1,
    datasets: list | None = None,
) -> dict:
    """Create a minimal certificate for lifecycle testing."""
    today = date.today()
    cert: dict = {
        "issued": issued or (today - timedelta(days=30)).isoformat(),
        "expires": expires or (today + timedelta(days=335)).isoformat(),
        "riskTier": tier,
        "trainingData": {
            "datasets": datasets or [],
        },
    }
    return cert


class TestExpiryChecker:
    """Test lifecycle and temporal validation."""

    def test_valid_certificate_passes(self) -> None:
        cert = _make_cert()
        result = check_lifecycle(cert)
        assert result.layer == ValidationLayer.LIFECYCLE
        assert not result.has_errors
        assert result.checks_passed >= 3  # not expired + not approaching + issued OK + issued < expires

    def test_expired_certificate(self) -> None:
        cert = _make_cert(expires=(date.today() - timedelta(days=10)).isoformat())
        result = check_lifecycle(cert)
        assert result.has_errors
        rule_ids = [f.rule_id for f in result.findings]
        assert "LIFE-001" in rule_ids

    def test_expiry_within_30_days(self) -> None:
        cert = _make_cert(expires=(date.today() + timedelta(days=15)).isoformat())
        result = check_lifecycle(cert)
        warnings = [f for f in result.findings if f.rule_id == "LIFE-002"]
        assert len(warnings) == 1
        assert "CRITICAL" in warnings[0].message

    def test_expiry_within_90_days(self) -> None:
        cert = _make_cert(expires=(date.today() + timedelta(days=60)).isoformat())
        result = check_lifecycle(cert)
        warnings = [f for f in result.findings if f.rule_id == "LIFE-002"]
        assert len(warnings) == 1
        assert "within 90 days" in warnings[0].message

    def test_expiry_far_away_no_warning(self) -> None:
        cert = _make_cert(expires=(date.today() + timedelta(days=200)).isoformat())
        result = check_lifecycle(cert)
        warnings = [f for f in result.findings if f.rule_id == "LIFE-002"]
        assert len(warnings) == 0

    def test_validity_period_too_long_tier2(self) -> None:
        """Tier 2 with >24 months validity."""
        today = date.today()
        cert = _make_cert(
            issued=today.isoformat(),
            expires=(today + timedelta(days=900)).isoformat(),
            tier=2,
        )
        result = check_lifecycle(cert)
        rule_ids = [f.rule_id for f in result.findings]
        assert "LIFE-003" in rule_ids

    def test_validity_period_ok_tier1(self) -> None:
        """Tier 1 with 24 months validity (within 36 month max)."""
        today = date.today()
        cert = _make_cert(
            issued=today.isoformat(),
            expires=(today + timedelta(days=720)).isoformat(),
            tier=1,
        )
        result = check_lifecycle(cert)
        life3 = [f for f in result.findings if f.rule_id == "LIFE-003"]
        assert len(life3) == 0

    def test_dsa_expired(self) -> None:
        datasets = [{
            "datasetName": "Test Dataset",
            "dataSharingAgreement": {
                "reference": "DSA-001",
                "expiryDate": (date.today() - timedelta(days=30)).isoformat(),
            },
        }]
        cert = _make_cert(datasets=datasets)
        result = check_lifecycle(cert)
        rule_ids = [f.rule_id for f in result.findings]
        assert "LIFE-004" in rule_ids
        dsa_finding = [f for f in result.findings if f.rule_id == "LIFE-004"][0]
        assert dsa_finding.severity == Severity.ERROR

    def test_dsa_expiring_soon(self) -> None:
        datasets = [{
            "datasetName": "Test Dataset",
            "dataSharingAgreement": {
                "reference": "DSA-001",
                "expiryDate": (date.today() + timedelta(days=30)).isoformat(),
            },
        }]
        cert = _make_cert(datasets=datasets)
        result = check_lifecycle(cert)
        warnings = [f for f in result.findings if f.rule_id == "LIFE-004" and f.severity == Severity.WARNING]
        assert len(warnings) == 1

    def test_dsa_valid(self) -> None:
        datasets = [{
            "datasetName": "Test Dataset",
            "dataSharingAgreement": {
                "reference": "DSA-001",
                "expiryDate": (date.today() + timedelta(days=365)).isoformat(),
            },
        }]
        cert = _make_cert(datasets=datasets)
        result = check_lifecycle(cert)
        dsa_findings = [f for f in result.findings if f.rule_id == "LIFE-004"]
        assert len(dsa_findings) == 0

    def test_issued_in_future(self) -> None:
        cert = _make_cert(issued=(date.today() + timedelta(days=30)).isoformat())
        result = check_lifecycle(cert)
        warnings = [f for f in result.findings if f.rule_id == "LIFE-005"]
        assert len(warnings) == 1

    def test_issued_before_expires(self) -> None:
        """issued >= expires should error."""
        today = date.today()
        cert = _make_cert(
            issued=today.isoformat(),
            expires=today.isoformat(),
        )
        result = check_lifecycle(cert)
        rule_ids = [f.rule_id for f in result.findings]
        assert "LIFE-006" in rule_ids

    def test_invalid_expires_date(self) -> None:
        cert = _make_cert(expires="not-a-date")
        result = check_lifecycle(cert)
        rule_ids = [f.rule_id for f in result.findings]
        assert "LIFE-001" in rule_ids

    def test_tier3_example_passes(self, valid_tier3: dict) -> None:
        """The ThoraxTriage-v3 example should pass lifecycle checks."""
        result = check_lifecycle(valid_tier3)
        assert not result.has_errors
        assert result.checks_passed >= 3
