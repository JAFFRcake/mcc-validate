"""Layer 1: Structural JSON Schema validation against MCC-SCHEMA-001."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

import jsonschema
from jsonschema import Draft202012Validator, ValidationError

from mcc_validate.models import Finding, LayerResult, Severity, ValidationLayer


def _load_bundled_schema() -> dict:
    """Load the bundled MCC schema from the package."""
    schema_path = resources.files("mcc_validate") / "schemas" / "mcc-schema-v1.json"
    return json.loads(schema_path.read_text(encoding="utf-8"))


def _load_schema(schema_path: str | Path | None) -> dict:
    """Load schema from a custom path or fall back to the bundled schema."""
    if schema_path is not None:
        path = Path(schema_path)
        if not path.exists():
            raise FileNotFoundError(f"Schema file not found: {path}")
        return json.loads(path.read_text(encoding="utf-8"))
    return _load_bundled_schema()


def _error_to_path(error: ValidationError) -> str:
    """Convert a jsonschema validation error to a dotted JSON path."""
    parts = []
    for part in error.absolute_path:
        if isinstance(part, int):
            parts.append(f"[{part}]")
        else:
            if parts:
                parts.append(f".{part}")
            else:
                parts.append(str(part))
    return "".join(parts) or "(root)"


def validate_schema(
    certificate: dict,
    schema_path: str | Path | None = None,
) -> LayerResult:
    """Validate a certificate against the MCC JSON Schema.

    Returns a LayerResult with findings for any schema violations.
    """
    schema = _load_schema(schema_path)
    validator = Draft202012Validator(schema)
    result = LayerResult(layer=ValidationLayer.SCHEMA)

    errors = sorted(validator.iter_errors(certificate), key=lambda e: list(e.absolute_path))

    if not errors:
        # Count the number of properties that were validated
        # Approximate: count required + present optional fields across all levels
        result.checks_passed = _count_validated_fields(certificate, schema)
        return result

    for error in errors:
        path = _error_to_path(error)
        message = error.message

        # Simplify overly verbose jsonschema messages
        if len(message) > 200:
            message = message[:200] + "..."

        finding = Finding(
            rule_id="SCHEMA-001",
            layer=ValidationLayer.SCHEMA,
            severity=Severity.ERROR,
            message=message,
            path=path,
        )
        result.findings.append(finding)

    # Count checks that passed (total possible minus errors)
    total_checks = _count_validated_fields(certificate, schema)
    result.checks_passed = max(0, total_checks - len(errors))

    return result


def _count_validated_fields(certificate: dict, schema: dict) -> int:
    """Approximate the number of fields that were checked during validation."""
    count = 0

    def _count_obj(obj: object, schema_node: dict) -> None:
        nonlocal count
        if not isinstance(obj, dict):
            return

        props = schema_node.get("properties", {})
        defs = schema_node.get("$defs", {})

        for key, value in obj.items():
            count += 1  # field presence/type check
            prop_schema = props.get(key, {})

            # Resolve $ref
            ref = prop_schema.get("$ref", "")
            if ref and ref.startswith("#/$defs/"):
                def_name = ref.split("/")[-1]
                prop_schema = defs.get(def_name, prop_schema)

            if isinstance(value, dict):
                _count_obj(value, {**prop_schema, "$defs": defs})
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        items_schema = prop_schema.get("items", {})
                        item_ref = items_schema.get("$ref", "")
                        if item_ref and item_ref.startswith("#/$defs/"):
                            def_name = item_ref.split("/")[-1]
                            items_schema = defs.get(def_name, items_schema)
                        _count_obj(item, {**items_schema, "$defs": defs})
                    else:
                        count += 1

    _count_obj(certificate, schema)
    return count
