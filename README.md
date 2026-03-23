# blackroad-security-audit

> BlackRoad Security - ublackroad security audit

Part of the [BlackRoad OS](https://blackroad.io) ecosystem — [BlackRoad-Security](https://github.com/BlackRoad-Security)

---

# blackroad-security-audit

Production-grade AST-based Python security scanner for the BlackRoad Security platform.

## Features

- 🔍 **AST Analysis** – Detects `eval()`/`exec()`, hardcoded secrets, SQL injection, `os.system()`, timing attacks
- 📄 **SARIF Output** – GitHub Code Scanning compatible SARIF 2.1.0 reports  
- 🌐 **HTML Reports** – Self-contained dark-theme HTML security reports
- ⚙️ **Config Scanner** – Scans `.env`, `.yaml`, `.ini`, `.toml` for secrets and misconfigurations
- 📊 **Risk Scoring** – 0-100 risk score with severity breakdown

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Text output (default)
python src/security_audit.py /path/to/project

# SARIF report (GitHub Code Scanning)
python src/security_audit.py . --format sarif --output results.sarif

# HTML report
python src/security_audit.py . --format html --output report.html

# JSON output
python src/security_audit.py . --format json

# Include config file scanning
python src/security_audit.py . --config

# Filter by severity
python src/security_audit.py . --severity HIGH
```

## Detected Vulnerabilities

| Category | Severity | CWE |
|----------|----------|-----|
| `eval()`/`exec()` calls | CRITICAL | CWE-95 |
| Hardcoded secrets | CRITICAL | CWE-798 |
| SQL injection (f-string/%) | HIGH | CWE-89 |
| `os.system()` / `subprocess` | HIGH | CWE-78 |
| Timing attack (direct comparison) | HIGH | CWE-208 |
| Debug mode enabled | MEDIUM | CWE-489 |
| Permissive CORS | HIGH | CWE-346 |

## Tests

```bash
pytest tests/ -v --cov=src
```

## Architecture

- `SecurityFinding` – dataclass with id, severity, category, file, line, description
- `SecurityVisitor` – AST node visitor implementing all detection rules
- `scan_python_code()` – recursive directory scanner
- `scan_config_files()` – config file secret detector
- `calculate_risk_score()` – weighted risk scoring (0-100)
- `generate_sarif_report()` – SARIF 2.1.0 compliant output
- `export_html_report()` – self-contained HTML with dark theme

## License

Proprietary – BlackRoad OS, Inc. All rights reserved.
