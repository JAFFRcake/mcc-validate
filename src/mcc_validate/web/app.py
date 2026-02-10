"""Flask application for the web-based MCC certificate validator."""

from __future__ import annotations

import json

from flask import Flask, jsonify, request, render_template_string

from mcc_validate import __version__
from mcc_validate.core import validate_certificate
from mcc_validate.reporters import html_reporter, json_reporter


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB limit

    @app.route("/")
    def index():  # type: ignore[no-untyped-def]
        return render_template_string(_INDEX_TEMPLATE, version=__version__)

    @app.route("/validate", methods=["POST"])
    def validate():  # type: ignore[no-untyped-def]
        # Accept file upload or JSON body
        if "certificate" in request.files:
            file = request.files["certificate"]
            try:
                cert_data = json.loads(file.read().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                return jsonify({"error": f"Invalid JSON: {e}"}), 400
        elif request.is_json:
            cert_data = request.get_json()
        else:
            return jsonify({"error": "No certificate provided"}), 400

        if not isinstance(cert_data, dict):
            return jsonify({"error": "Certificate must be a JSON object"}), 400

        report = validate_certificate(cert_data)

        # Determine response format
        response_format = request.args.get("format", "html")

        if response_format == "json":
            return jsonify(json.loads(json_reporter.render_report(report)))
        else:
            html = html_reporter.render_report(report)
            return html, 200, {"Content-Type": "text/html"}

    @app.route("/health")
    def health():  # type: ignore[no-untyped-def]
        return jsonify({"status": "ok", "version": __version__})

    return app


def main() -> None:
    """Entry point for mcc-validate-web."""
    app = create_app()
    app.run(host="127.0.0.1", port=8080)


_INDEX_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCC Certificate Validator</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                         "Helvetica Neue", Arial, sans-serif;
            max-width: 960px; margin: 40px auto; padding: 0 20px;
            color: #1e293b; background: #f8fafc;
        }
        h1 {
            font-size: 1.8em; border-bottom: 3px solid #2563eb;
            padding-bottom: 12px; margin-bottom: 8px;
        }
        .subtitle { color: #64748b; margin-bottom: 24px; }
        .drop-zone {
            border: 3px dashed #cbd5e1; border-radius: 12px;
            padding: 60px 20px; text-align: center; cursor: pointer;
            transition: all 0.2s; margin: 24px 0; background: #fff;
        }
        .drop-zone:hover, .drop-zone.dragover {
            border-color: #2563eb; background: #eff6ff;
        }
        .drop-zone p { font-size: 1.1em; color: #64748b; margin: 8px 0; }
        .drop-zone .browse {
            color: #2563eb; cursor: pointer; text-decoration: underline;
        }
        #result { margin-top: 24px; }
        .loading {
            text-align: center; padding: 20px; color: #64748b;
            font-style: italic;
        }
        .error-msg { color: #dc2626; padding: 16px; background: #fef2f2;
                     border-radius: 8px; border: 1px solid #fecaca; }
        footer {
            margin-top: 40px; padding-top: 16px;
            border-top: 1px solid #e2e8f0; color: #94a3b8;
            font-size: 0.85em;
        }
    </style>
</head>
<body>
    <h1>MCC Certificate Validator</h1>
    <p class="subtitle">Validate Model Context Certificates against MCC-STD-001.</p>

    <div class="drop-zone" id="dropZone">
        <p>Drag and drop a certificate JSON file here</p>
        <p>or <label class="browse" for="fileInput">browse files</label></p>
        <input type="file" id="fileInput" accept=".json" style="display:none">
    </div>

    <div id="result"></div>

    <footer>MCC Validator v{{ version }}</footer>

    <script>
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        const result = document.getElementById('result');

        dropZone.addEventListener('click', () => fileInput.click());
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault(); dropZone.classList.add('dragover');
        });
        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault(); dropZone.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) uploadFile(e.dataTransfer.files[0]);
        });
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) uploadFile(fileInput.files[0]);
        });

        async function uploadFile(file) {
            result.innerHTML = '<div class="loading">Validating...</div>';
            const formData = new FormData();
            formData.append('certificate', file);
            try {
                const resp = await fetch('/validate?format=html', {
                    method: 'POST', body: formData
                });
                if (!resp.ok) {
                    let msg = 'Unknown error';
                    try { msg = (await resp.json()).error; } catch(_) {}
                    result.innerHTML = '<div class="error-msg">Error: ' + msg + '</div>';
                } else {
                    result.innerHTML = await resp.text();
                }
            } catch (e) {
                result.innerHTML = '<div class="error-msg">Network error: ' + e.message + '</div>';
            }
        }
    </script>
</body>
</html>
"""
