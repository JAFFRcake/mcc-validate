"""HTML reporter — formatted audit report for regulatory submissions.

Uses Jinja2 if available for template rendering. Falls back to a simple
string-based renderer when Jinja2 is not installed (optional dependency).
"""

from __future__ import annotations

from datetime import UTC, datetime

from mcc_validate.models import (
    Finding,
    LayerResult,
    Severity,
    ValidationLayer,
    ValidationReport,
)

_LAYER_NAMES = {
    ValidationLayer.SCHEMA: "Schema Validation",
    ValidationLayer.TIER_COMPLIANCE: "Tier Compliance",
    ValidationLayer.CRYPTOGRAPHIC: "Cryptographic Verification",
    ValidationLayer.LIFECYCLE: "Lifecycle Checks",
    ValidationLayer.COMPOSITIONAL: "Compositional Integrity",
}

_TIER_LABELS = {1: "Low Risk", 2: "Moderate Risk", 3: "High Risk", 4: "Very High Risk"}


def render_report(report: ValidationReport) -> str:
    """Render a validation report as an HTML document."""
    try:
        return _render_jinja(report)
    except ImportError:
        return _render_builtin(report)


def _render_jinja(report: ValidationReport) -> str:
    """Render using Jinja2 templates."""
    from jinja2 import Environment

    env = Environment(autoescape=True)
    template = env.from_string(_JINJA_TEMPLATE)
    return template.render(
        report=report,
        layer_names=_LAYER_NAMES,
        tier_labels=_TIER_LABELS,
        timestamp=datetime.now(UTC).isoformat(),
        severity_class=_severity_css_class,
    )


def _render_builtin(report: ValidationReport) -> str:
    """Render using built-in string formatting (no Jinja2 dependency)."""
    timestamp = datetime.now(UTC).isoformat()
    tier_label = _TIER_LABELS.get(report.risk_tier, "Unknown")
    result_class = "pass" if report.is_valid else "fail"
    result_text = "VALID" if report.is_valid else "INVALID"

    layers_html = []
    for lr in report.layer_results:
        layer_name = _LAYER_NAMES.get(lr.layer, str(lr.layer))
        if lr.not_applicable:
            status = '<span class="status-skip">Not Applicable</span>'
        elif lr.skipped:
            reason = f" ({lr.skip_reason})" if lr.skip_reason else ""
            status = f'<span class="status-skip">Skipped{_esc(reason)}</span>'
        elif lr.has_errors:
            status = f'<span class="status-fail">{len(lr.errors)} error(s)</span>'
        else:
            status = f'<span class="status-pass">{lr.checks_passed} checks passed</span>'

        findings_html = ""
        if lr.findings:
            rows = []
            for f in lr.findings:
                css = _severity_css_class(f.severity)
                rows.append(
                    f"<tr>"
                    f'<td class="{css}">{_esc(f.severity.value.upper())}</td>'
                    f"<td>{_esc(f.rule_id)}</td>"
                    f"<td>{_esc(f.message)}</td>"
                    f"<td>{_esc(f.path)}</td>"
                    f"<td>{_esc(f.reference)}</td>"
                    f"</tr>"
                )
            findings_html = (
                '<table class="findings">'
                "<tr><th>Severity</th><th>Rule</th><th>Message</th><th>Path</th><th>Ref</th></tr>"
                + "\n".join(rows)
                + "</table>"
            )

        layers_html.append(
            f'<div class="layer">'
            f"<h3>Layer {lr.layer.value}: {_esc(layer_name)} — {status}</h3>"
            f"{findings_html}"
            f"</div>"
        )

    return _HTML_TEMPLATE.format(
        title=f"MCC Validation Report — {_esc(report.certificate_name)}",
        timestamp=_esc(timestamp),
        cert_id=_esc(report.certificate_id),
        cert_name=_esc(report.certificate_name),
        cert_version=_esc(report.certificate_version),
        tier=report.risk_tier,
        tier_label=_esc(tier_label),
        status=_esc(report.status),
        expires=_esc(report.expires),
        result_class=result_class,
        result_text=result_text,
        checks_passed=report.total_checks_passed,
        errors=report.total_errors,
        warnings=report.total_warnings,
        layers="\n".join(layers_html),
    )


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _severity_css_class(severity: Severity) -> str:
    return {
        Severity.ERROR: "severity-error",
        Severity.WARNING: "severity-warning",
        Severity.INFO: "severity-info",
    }[severity]


# ---------------------------------------------------------------------------
# Built-in HTML template (no Jinja2 required)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         max-width: 960px; margin: 40px auto; padding: 0 20px; color: #333; }}
  h1 {{ border-bottom: 3px solid #2563eb; padding-bottom: 12px; }}
  h2 {{ color: #1e40af; margin-top: 32px; }}
  h3 {{ margin: 16px 0 8px; }}
  .meta {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px;
           padding: 16px; margin: 16px 0; }}
  .meta td {{ padding: 4px 16px 4px 0; }}
  .meta th {{ text-align: left; padding: 4px 16px 4px 0; color: #64748b; font-weight: 500; }}
  .result {{ font-size: 1.3em; font-weight: bold; padding: 12px 20px; border-radius: 8px;
             margin: 24px 0; text-align: center; }}
  .result.pass {{ background: #dcfce7; color: #166534; border: 2px solid #86efac; }}
  .result.fail {{ background: #fee2e2; color: #991b1b; border: 2px solid #fca5a5; }}
  .layer {{ margin: 16px 0; padding: 12px 16px; background: #fafafa; border-radius: 6px;
            border-left: 4px solid #e2e8f0; }}
  .status-pass {{ color: #166534; font-weight: 600; }}
  .status-fail {{ color: #991b1b; font-weight: 600; }}
  .status-skip {{ color: #64748b; font-style: italic; }}
  .findings {{ width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 0.9em; }}
  .findings th {{ background: #f1f5f9; padding: 8px; text-align: left; border-bottom: 2px solid #cbd5e1; }}
  .findings td {{ padding: 6px 8px; border-bottom: 1px solid #e2e8f0; }}
  .severity-error {{ color: #dc2626; font-weight: 600; }}
  .severity-warning {{ color: #d97706; font-weight: 600; }}
  .severity-info {{ color: #2563eb; }}
  footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e8f0;
            color: #94a3b8; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>MCC Validation Report</h1>

<div class="meta">
<table>
  <tr><th>Certificate ID</th><td>{cert_id}</td></tr>
  <tr><th>Name</th><td>{cert_name} (v{cert_version})</td></tr>
  <tr><th>Risk Tier</th><td>{tier} ({tier_label})</td></tr>
  <tr><th>Status</th><td>{status}</td></tr>
  <tr><th>Expires</th><td>{expires}</td></tr>
</table>
</div>

<div class="result {result_class}">
  {result_text} &mdash; {checks_passed} checks passed, {errors} error(s), {warnings} warning(s)
</div>

<h2>Validation Layers</h2>
{layers}

<footer>
  Generated by MCC Validator v0.1.0 at {timestamp}
</footer>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Jinja2 template (used when jinja2 is installed)
# ---------------------------------------------------------------------------

_JINJA_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MCC Validation Report — {{ report.certificate_name }}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         max-width: 960px; margin: 40px auto; padding: 0 20px; color: #333; }
  h1 { border-bottom: 3px solid #2563eb; padding-bottom: 12px; }
  h2 { color: #1e40af; margin-top: 32px; }
  h3 { margin: 16px 0 8px; }
  .meta { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px;
           padding: 16px; margin: 16px 0; }
  .meta td { padding: 4px 16px 4px 0; }
  .meta th { text-align: left; padding: 4px 16px 4px 0; color: #64748b; font-weight: 500; }
  .result { font-size: 1.3em; font-weight: bold; padding: 12px 20px; border-radius: 8px;
             margin: 24px 0; text-align: center; }
  .result.pass { background: #dcfce7; color: #166534; border: 2px solid #86efac; }
  .result.fail { background: #fee2e2; color: #991b1b; border: 2px solid #fca5a5; }
  .layer { margin: 16px 0; padding: 12px 16px; background: #fafafa; border-radius: 6px;
            border-left: 4px solid #e2e8f0; }
  .status-pass { color: #166534; font-weight: 600; }
  .status-fail { color: #991b1b; font-weight: 600; }
  .status-skip { color: #64748b; font-style: italic; }
  .findings { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 0.9em; }
  .findings th { background: #f1f5f9; padding: 8px; text-align: left; border-bottom: 2px solid #cbd5e1; }
  .findings td { padding: 6px 8px; border-bottom: 1px solid #e2e8f0; }
  .severity-error { color: #dc2626; font-weight: 600; }
  .severity-warning { color: #d97706; font-weight: 600; }
  .severity-info { color: #2563eb; }
  footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e8f0;
            color: #94a3b8; font-size: 0.85em; }
</style>
</head>
<body>
<h1>MCC Validation Report</h1>

<div class="meta">
<table>
  <tr><th>Certificate ID</th><td>{{ report.certificate_id }}</td></tr>
  <tr><th>Name</th><td>{{ report.certificate_name }} (v{{ report.certificate_version }})</td></tr>
  <tr><th>Risk Tier</th><td>{{ report.risk_tier }} ({{ tier_labels.get(report.risk_tier, "Unknown") }})</td></tr>
  <tr><th>Status</th><td>{{ report.status }}</td></tr>
  <tr><th>Expires</th><td>{{ report.expires }}</td></tr>
</table>
</div>

{% if report.is_valid %}
<div class="result pass">
  VALID &mdash; {{ report.total_checks_passed }} checks passed, 0 error(s), {{ report.total_warnings }} warning(s)
</div>
{% else %}
<div class="result fail">
  INVALID &mdash; {{ report.total_checks_passed }} checks passed, {{ report.total_errors }} error(s), {{ report.total_warnings }} warning(s)
</div>
{% endif %}

<h2>Validation Layers</h2>
{% for lr in report.layer_results %}
<div class="layer">
  <h3>Layer {{ lr.layer.value }}: {{ layer_names.get(lr.layer, lr.layer.name) }}
  {% if lr.not_applicable %}
    &mdash; <span class="status-skip">Not Applicable</span>
  {% elif lr.skipped %}
    &mdash; <span class="status-skip">Skipped{% if lr.skip_reason %} ({{ lr.skip_reason }}){% endif %}</span>
  {% elif lr.has_errors %}
    &mdash; <span class="status-fail">{{ lr.errors|length }} error(s)</span>
  {% else %}
    &mdash; <span class="status-pass">{{ lr.checks_passed }} checks passed</span>
  {% endif %}
  </h3>
  {% if lr.findings %}
  <table class="findings">
    <tr><th>Severity</th><th>Rule</th><th>Message</th><th>Path</th><th>Ref</th></tr>
    {% for f in lr.findings %}
    <tr>
      <td class="{{ severity_class(f.severity) }}">{{ f.severity.value|upper }}</td>
      <td>{{ f.rule_id }}</td>
      <td>{{ f.message }}</td>
      <td>{{ f.path }}</td>
      <td>{{ f.reference }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}
</div>
{% endfor %}

<footer>
  Generated by MCC Validator v0.1.0 at {{ timestamp }}
</footer>
</body>
</html>
"""
