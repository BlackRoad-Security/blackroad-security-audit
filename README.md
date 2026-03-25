<!-- BlackRoad SEO Enhanced -->

# ulackroad security audit

> Part of **[BlackRoad OS](https://blackroad.io)** — Sovereign Computing for Everyone

[![BlackRoad OS](https://img.shields.io/badge/BlackRoad-OS-ff1d6c?style=for-the-badge)](https://blackroad.io)
[![BlackRoad Security](https://img.shields.io/badge/Org-BlackRoad-Security-2979ff?style=for-the-badge)](https://github.com/BlackRoad-Security)
[![License](https://img.shields.io/badge/License-Proprietary-f5a623?style=for-the-badge)](LICENSE)

**ulackroad security audit** is part of the **BlackRoad OS** ecosystem — a sovereign, distributed operating system built on edge computing, local AI, and mesh networking by **BlackRoad OS, Inc.**

## About BlackRoad OS

BlackRoad OS is a sovereign computing platform that runs AI locally on your own hardware. No cloud dependencies. No API keys. No surveillance. Built by [BlackRoad OS, Inc.](https://github.com/BlackRoad-OS-Inc), a Delaware C-Corp founded in 2025.

### Key Features
- **Local AI** — Run LLMs on Raspberry Pi, Hailo-8, and commodity hardware
- **Mesh Networking** — WireGuard VPN, NATS pub/sub, peer-to-peer communication
- **Edge Computing** — 52 TOPS of AI acceleration across a Pi fleet
- **Self-Hosted Everything** — Git, DNS, storage, CI/CD, chat — all sovereign
- **Zero Cloud Dependencies** — Your data stays on your hardware

### The BlackRoad Ecosystem
| Organization | Focus |
|---|---|
| [BlackRoad OS](https://github.com/BlackRoad-OS) | Core platform and applications |
| [BlackRoad OS, Inc.](https://github.com/BlackRoad-OS-Inc) | Corporate and enterprise |
| [BlackRoad AI](https://github.com/BlackRoad-AI) | Artificial intelligence and ML |
| [BlackRoad Hardware](https://github.com/BlackRoad-Hardware) | Edge hardware and IoT |
| [BlackRoad Security](https://github.com/BlackRoad-Security) | Cybersecurity and auditing |
| [BlackRoad Quantum](https://github.com/BlackRoad-Quantum) | Quantum computing research |
| [BlackRoad Agents](https://github.com/BlackRoad-Agents) | Autonomous AI agents |
| [BlackRoad Network](https://github.com/BlackRoad-Network) | Mesh and distributed networking |
| [BlackRoad Education](https://github.com/BlackRoad-Education) | Learning and tutoring platforms |
| [BlackRoad Labs](https://github.com/BlackRoad-Labs) | Research and experiments |
| [BlackRoad Cloud](https://github.com/BlackRoad-Cloud) | Self-hosted cloud infrastructure |
| [BlackRoad Forge](https://github.com/BlackRoad-Forge) | Developer tools and utilities |

### Links
- **Website**: [blackroad.io](https://blackroad.io)
- **Documentation**: [docs.blackroad.io](https://docs.blackroad.io)
- **Chat**: [chat.blackroad.io](https://chat.blackroad.io)
- **Search**: [search.blackroad.io](https://search.blackroad.io)

---


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
