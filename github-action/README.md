# MCC Validate GitHub Action

Validate Model Context Certificates against MCC-STD-001 in your CI/CD pipeline.

## Usage

### Basic validation with SARIF upload

```yaml
name: MCC Certificate Validation
on: [push, pull_request]

permissions:
  security-events: write  # Required for SARIF upload

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mcc-standard/mcc-validate/github-action@v1
        with:
          certificate: 'certificates/my-cert.json'
```

### Multiple certificates

```yaml
      - uses: mcc-standard/mcc-validate/github-action@v1
        with:
          certificate: 'certificates/*.json'
```

### Composite system with components

```yaml
      - uses: mcc-standard/mcc-validate/github-action@v1
        with:
          certificate: 'system-cert.json'
          components: './component-certs/'
```

### JSON output without SARIF upload

```yaml
      - uses: mcc-standard/mcc-validate/github-action@v1
        with:
          certificate: 'cert.json'
          format: 'json'
          upload-sarif: 'false'
```

### With custom config

```yaml
      - uses: mcc-standard/mcc-validate/github-action@v1
        with:
          certificate: 'cert.json'
          config: '.mcc-validate.yaml'
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `certificate` | Yes | — | Path or glob pattern to certificate JSON file(s) |
| `format` | No | `sarif` | Output format: `console`, `json`, `html`, `sarif` |
| `strict` | No | `true` | Treat warnings as errors |
| `components` | No | — | Directory containing component certificate files |
| `weights` | No | — | Path to model weight file for hash verification |
| `config` | No | — | Path to `.mcc-validate.yaml` config file |
| `python-version` | No | `3.11` | Python version to use |
| `upload-sarif` | No | `true` | Upload SARIF results to GitHub Code Scanning |
| `version` | No | latest | Version of mcc-validate to install |

## Outputs

| Output | Description |
|--------|-------------|
| `exit-code` | Exit code from validation (0=valid, 1=errors, 2=warnings) |
| `report-path` | Path to the generated report file |
| `valid` | Whether the certificate is valid (`true`/`false`) |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Valid — all checks pass |
| 1 | Invalid — one or more errors |
| 2 | Warnings — valid but with advisory findings |
| 3 | Input error — file not found, malformed JSON |
