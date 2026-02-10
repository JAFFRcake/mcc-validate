"""Layer 4: Temporal and lifecycle checks.

Validates certificate expiry, DSA expiry, tier-specific validity
periods, and approaching-expiry warnings.
"""

from __future__ import annotations

from datetime import date, timedelta

from mcc_validate.models import Finding, LayerResult, Severity, ValidationLayer

_TIER_MAX_MONTHS = {1: 36, 2: 24, 3: 12, 4: 12}


def check_lifecycle(certificate: dict) -> LayerResult:
    """Run all lifecycle and temporal checks against a certificate."""
    result = LayerResult(layer=ValidationLayer.LIFECYCLE)
    today = date.today()

    _check_certificate_expiry(certificate, today, result)
    _check_expiry_approaching(certificate, today, result)
    _check_validity_period(certificate, result)
    _check_dsa_expiry(certificate, today, result)
    _check_issued_not_future(certificate, today, result)
    _check_issued_before_expires(certificate, result)

    return result


def _parse_date(date_str: str) -> date | None:
    """Parse an ISO 8601 date string, returning None on failure."""
    try:
        return date.fromisoformat(date_str)
    except (ValueError, TypeError):
        return None


def _check_certificate_expiry(cert: dict, today: date, result: LayerResult) -> None:
    """Check if the certificate has expired."""
    expires_str = cert.get("expires", "")
    expires = _parse_date(expires_str)

    if expires is None:
        result.findings.append(Finding(
            rule_id="LIFE-001",
            layer=ValidationLayer.LIFECYCLE,
            severity=Severity.ERROR,
            message=f"Cannot parse expires date: '{expires_str}'",
            path="expires",
        ))
        return

    if expires < today:
        days_ago = (today - expires).days
        result.findings.append(Finding(
            rule_id="LIFE-001",
            layer=ValidationLayer.LIFECYCLE,
            severity=Severity.ERROR,
            message=f"Certificate EXPIRED {days_ago} day{'s' if days_ago != 1 else ''} ago (on {expires_str})",
            path="expires",
            reference="MCC-STD-001 §4",
            fix="Renew the certificate or issue a new version.",
        ))
    else:
        result.checks_passed += 1  # Not expired


def _check_expiry_approaching(cert: dict, today: date, result: LayerResult) -> None:
    """Warn when expiry is approaching (90 days, 30 days)."""
    expires_str = cert.get("expires", "")
    expires = _parse_date(expires_str)

    if expires is None or expires < today:
        return  # Already handled by _check_certificate_expiry

    days_remaining = (expires - today).days

    if days_remaining <= 30:
        result.findings.append(Finding(
            rule_id="LIFE-002",
            layer=ValidationLayer.LIFECYCLE,
            severity=Severity.WARNING,
            message=f"Certificate expires in {days_remaining} days (CRITICAL — within 30 days)",
            path="expires",
            fix="Begin certificate renewal process immediately.",
        ))
    elif days_remaining <= 90:
        result.findings.append(Finding(
            rule_id="LIFE-002",
            layer=ValidationLayer.LIFECYCLE,
            severity=Severity.WARNING,
            message=f"Certificate expires in {days_remaining} days (within 90 days)",
            path="expires",
            fix="Plan certificate renewal.",
        ))
    else:
        result.checks_passed += 1  # Expiry not imminent


def _check_validity_period(cert: dict, result: LayerResult) -> None:
    """Check that the validity period does not exceed the tier maximum."""
    issued_str = cert.get("issued", "")
    expires_str = cert.get("expires", "")
    tier = cert.get("riskTier", 1)

    issued = _parse_date(issued_str)
    expires = _parse_date(expires_str)

    if issued is None or expires is None:
        return  # Parse errors handled elsewhere

    max_months = _TIER_MAX_MONTHS.get(tier, 36)

    # Calculate months between issued and expires
    months = (expires.year - issued.year) * 12 + (expires.month - issued.month)
    if expires.day > issued.day:
        months += 1  # Partial month rounds up

    if months > max_months:
        result.findings.append(Finding(
            rule_id="LIFE-003",
            layer=ValidationLayer.LIFECYCLE,
            severity=Severity.ERROR,
            message=f"Validity period ({months} months) exceeds Tier {tier} maximum ({max_months} months)",
            path="expires",
            reference="MCC-STD-001 §4",
            fix=f"Set expires date within {max_months} months of issued date.",
        ))
    else:
        result.checks_passed += 1


def _check_dsa_expiry(cert: dict, today: date, result: LayerResult) -> None:
    """Check that data sharing agreements haven't expired."""
    datasets = cert.get("trainingData", {}).get("datasets", [])
    if not isinstance(datasets, list):
        return

    any_checked = False

    for i, ds in enumerate(datasets):
        dsa = ds.get("dataSharingAgreement")
        if not isinstance(dsa, dict):
            continue

        expiry_str = dsa.get("expiryDate", "")
        if not expiry_str:
            continue

        any_checked = True
        dsa_expiry = _parse_date(expiry_str)
        ds_name = ds.get("datasetName", f"dataset[{i}]")

        if dsa_expiry is None:
            result.findings.append(Finding(
                rule_id="LIFE-004",
                layer=ValidationLayer.LIFECYCLE,
                severity=Severity.WARNING,
                message=f"Cannot parse DSA expiryDate for '{ds_name}': '{expiry_str}'",
                path=f"trainingData.datasets[{i}].dataSharingAgreement.expiryDate",
            ))
            continue

        if dsa_expiry < today:
            days_ago = (today - dsa_expiry).days
            result.findings.append(Finding(
                rule_id="LIFE-004",
                layer=ValidationLayer.LIFECYCLE,
                severity=Severity.ERROR,
                message=f"Data sharing agreement for '{ds_name}' expired {days_ago} days ago (on {expiry_str})",
                path=f"trainingData.datasets[{i}].dataSharingAgreement.expiryDate",
                reference="MCC-STD-001 §5.4",
                fix="Renew the data sharing agreement or remove the dataset reference.",
            ))
        elif dsa_expiry < today + timedelta(days=90):
            days_remaining = (dsa_expiry - today).days
            result.findings.append(Finding(
                rule_id="LIFE-004",
                layer=ValidationLayer.LIFECYCLE,
                severity=Severity.WARNING,
                message=f"Data sharing agreement for '{ds_name}' expires in {days_remaining} days",
                path=f"trainingData.datasets[{i}].dataSharingAgreement.expiryDate",
                fix="Plan DSA renewal.",
            ))
        else:
            result.checks_passed += 1  # DSA still valid

    if not any_checked:
        pass  # No DSAs to check — not an error


def _check_issued_not_future(cert: dict, today: date, result: LayerResult) -> None:
    """Check that issued date is not in the future."""
    issued_str = cert.get("issued", "")
    issued = _parse_date(issued_str)

    if issued is None:
        return

    if issued > today:
        result.findings.append(Finding(
            rule_id="LIFE-005",
            layer=ValidationLayer.LIFECYCLE,
            severity=Severity.WARNING,
            message=f"Certificate issued date ({issued_str}) is in the future",
            path="issued",
            fix="Verify the issued date is correct.",
        ))
    else:
        result.checks_passed += 1


def _check_issued_before_expires(cert: dict, result: LayerResult) -> None:
    """Check that issued date is before expires date."""
    issued = _parse_date(cert.get("issued", ""))
    expires = _parse_date(cert.get("expires", ""))

    if issued is None or expires is None:
        return

    if issued >= expires:
        result.findings.append(Finding(
            rule_id="LIFE-006",
            layer=ValidationLayer.LIFECYCLE,
            severity=Severity.ERROR,
            message="Certificate issued date is not before expires date",
            path="issued",
            fix="Ensure issued < expires.",
        ))
    else:
        result.checks_passed += 1
