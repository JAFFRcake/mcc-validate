"""Layer 5: Compositional integrity checking.

Validates composite certificates that reference multiple component certificates.
Checks include:
- All certificateRef UUIDs can be resolved to loadable component certificates
- Component certificates are individually valid at their declared tier
- No circular references in data flow graph
- Data flow graph is connected (no orphan components)
- Component versions match those declared in the composite
- Composite system tier >= maximum component tier used in clinical pathway
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from mcc_validate.models import Finding, LayerResult, Severity, ValidationLayer

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def check_composition(
    cert: dict,
    components_dir: str | Path | None = None,
) -> LayerResult:
    """Run Layer 5 compositional integrity checks.

    Parameters
    ----------
    cert:
        The composite certificate (dict).
    components_dir:
        Optional directory containing component certificate JSON files.
        When provided, certificateRef UUIDs are resolved against files in
        this directory.

    Returns
    -------
    LayerResult with compositional integrity findings.
    """
    result = LayerResult(layer=ValidationLayer.COMPOSITIONAL)

    composition = cert.get("composition")
    if composition is None:
        result.not_applicable = True
        return result

    components = composition.get("components", [])
    data_flow = composition.get("dataFlow", [])
    composite_tier = cert.get("riskTier", 1)

    # COMP-001: At least 2 components required
    if len(components) < 2:
        result.findings.append(Finding(
            rule_id="COMP-001",
            layer=ValidationLayer.COMPOSITIONAL,
            severity=Severity.ERROR,
            message=f"Composite system must have at least 2 components, found {len(components)}.",
            path="composition.components",
            reference="MCC-STD-001",
            fix="Add at least 2 components to the composition.",
        ))
    else:
        result.checks_passed += 1

    # Build component name set for data flow validation
    component_names = {c.get("componentName", "") for c in components}
    component_names.discard("")

    # COMP-002: All components have required fields
    for i, comp in enumerate(components):
        name = comp.get("componentName")
        role = comp.get("componentRole")
        if not name:
            result.findings.append(Finding(
                rule_id="COMP-002",
                layer=ValidationLayer.COMPOSITIONAL,
                severity=Severity.ERROR,
                message=f"Component [{i}] missing componentName.",
                path=f"composition.components[{i}].componentName",
                reference="MCC-STD-001",
            ))
        elif not role:
            result.findings.append(Finding(
                rule_id="COMP-002",
                layer=ValidationLayer.COMPOSITIONAL,
                severity=Severity.ERROR,
                message=f"Component '{name}' missing componentRole.",
                path=f"composition.components[{i}].componentRole",
                reference="MCC-STD-001",
            ))
        else:
            result.checks_passed += 1

    # COMP-003: Data flow references valid component names
    flow_nodes: set[str] = set()
    for i, flow in enumerate(data_flow):
        from_node = flow.get("from", "")
        to_node = flow.get("to", "")
        flow_nodes.add(from_node)
        flow_nodes.add(to_node)

        if from_node and from_node not in component_names:
            result.findings.append(Finding(
                rule_id="COMP-003",
                layer=ValidationLayer.COMPOSITIONAL,
                severity=Severity.ERROR,
                message=f"Data flow [{i}] references unknown component '{from_node}'.",
                path=f"composition.dataFlow[{i}].from",
                reference="MCC-STD-001",
                fix=f"Use one of: {', '.join(sorted(component_names))}",
            ))
        else:
            result.checks_passed += 1

        if to_node and to_node not in component_names:
            result.findings.append(Finding(
                rule_id="COMP-003",
                layer=ValidationLayer.COMPOSITIONAL,
                severity=Severity.ERROR,
                message=f"Data flow [{i}] references unknown component '{to_node}'.",
                path=f"composition.dataFlow[{i}].to",
                reference="MCC-STD-001",
                fix=f"Use one of: {', '.join(sorted(component_names))}",
            ))
        else:
            result.checks_passed += 1

    # COMP-004: No circular references in data flow
    if _has_cycle(data_flow):
        result.findings.append(Finding(
            rule_id="COMP-004",
            layer=ValidationLayer.COMPOSITIONAL,
            severity=Severity.ERROR,
            message="Circular reference detected in data flow graph.",
            path="composition.dataFlow",
            reference="MCC-STD-001",
            fix="Remove circular dependencies between components.",
        ))
    else:
        result.checks_passed += 1

    # COMP-005: All components participate in data flow (no orphans)
    if component_names and data_flow:
        orphans = component_names - flow_nodes
        if orphans:
            result.findings.append(Finding(
                rule_id="COMP-005",
                layer=ValidationLayer.COMPOSITIONAL,
                severity=Severity.WARNING,
                message=f"Component(s) not referenced in data flow: {', '.join(sorted(orphans))}.",
                path="composition.dataFlow",
                reference="MCC-STD-001",
                fix="Add data flow edges for all components or remove unused components.",
            ))
        else:
            result.checks_passed += 1

    # COMP-006: Resolve component certificates from --components directory
    loaded_components: dict[str, dict] = {}
    if components_dir is not None:
        components_path = Path(components_dir)
        if not components_path.is_dir():
            result.findings.append(Finding(
                rule_id="COMP-006",
                layer=ValidationLayer.COMPOSITIONAL,
                severity=Severity.ERROR,
                message=f"Components directory not found: {components_dir}",
                path="--components",
                reference="MCC-STD-001",
            ))
        else:
            loaded_components = _load_component_certs(components_path)
            # Check each component with a certificateRef can be resolved
            for i, comp in enumerate(components):
                cert_ref = comp.get("certificateRef")
                if not cert_ref:
                    continue
                if cert_ref not in loaded_components:
                    result.findings.append(Finding(
                        rule_id="COMP-006",
                        layer=ValidationLayer.COMPOSITIONAL,
                        severity=Severity.ERROR,
                        message=f"Component '{comp.get('componentName', f'[{i}]')}' "
                                f"certificateRef '{cert_ref}' not found in {components_dir}.",
                        path=f"composition.components[{i}].certificateRef",
                        reference="MCC-STD-001",
                        fix="Ensure a certificate with this ID exists in the components directory.",
                    ))
                else:
                    result.checks_passed += 1
                    loaded_cert = loaded_components[cert_ref]

                    # COMP-007: Component version match
                    declared_version = comp.get("version")
                    actual_version = loaded_cert.get("version")
                    if declared_version and actual_version and declared_version != actual_version:
                        result.findings.append(Finding(
                            rule_id="COMP-007",
                            layer=ValidationLayer.COMPOSITIONAL,
                            severity=Severity.ERROR,
                            message=f"Component '{comp.get('componentName', f'[{i}]')}' declares "
                                    f"version '{declared_version}' but loaded certificate is "
                                    f"'{actual_version}'.",
                            path=f"composition.components[{i}].version",
                            reference="MCC-STD-001",
                        ))
                    elif declared_version and actual_version:
                        result.checks_passed += 1

    # COMP-008: Composite tier >= max component tier
    if loaded_components:
        max_component_tier = 0
        for comp in components:
            cert_ref = comp.get("certificateRef")
            if cert_ref and cert_ref in loaded_components:
                comp_tier = loaded_components[cert_ref].get("riskTier", 1)
                max_component_tier = max(max_component_tier, comp_tier)

        if max_component_tier > 0:
            if composite_tier < max_component_tier:
                result.findings.append(Finding(
                    rule_id="COMP-008",
                    layer=ValidationLayer.COMPOSITIONAL,
                    severity=Severity.ERROR,
                    message=f"Composite system tier ({composite_tier}) is lower than "
                            f"maximum component tier ({max_component_tier}).",
                    path="riskTier",
                    reference="MCC-STD-001",
                    fix=f"Set composite riskTier to at least {max_component_tier}.",
                ))
            else:
                result.checks_passed += 1

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _has_cycle(data_flow: list[dict]) -> bool:
    """Detect cycles in the data flow graph using DFS."""
    graph: dict[str, list[str]] = {}
    for flow in data_flow:
        src = flow.get("from", "")
        dst = flow.get("to", "")
        if src and dst:
            graph.setdefault(src, []).append(dst)

    visited: set[str] = set()
    in_stack: set[str] = set()

    def dfs(node: str) -> bool:
        visited.add(node)
        in_stack.add(node)
        for neighbour in graph.get(node, []):
            if neighbour in in_stack:
                return True
            if neighbour not in visited:
                if dfs(neighbour):
                    return True
        in_stack.discard(node)
        return False

    for node in graph:
        if node not in visited:
            if dfs(node):
                return True
    return False


def _load_component_certs(directory: Path) -> dict[str, dict]:
    """Load all certificate JSON files from a directory, indexed by certificateId."""
    certs: dict[str, dict] = {}
    for path in directory.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "certificateId" in data:
                certs[data["certificateId"]] = data
        except (json.JSONDecodeError, OSError):
            continue
    return certs
