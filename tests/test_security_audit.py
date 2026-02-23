"""Tests for blackroad-security-audit."""
import ast
import sys
import os
import tempfile
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from src.security_audit import (
    SecurityFinding, SecurityVisitor, scan_python_code,
    scan_config_files, calculate_risk_score, generate_sarif_report, export_html_report,
)


def write_py(content: str) -> str:
    tmp = tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False)
    tmp.write(content)
    tmp.close()
    return tmp.name


def write_dir(files: dict) -> str:
    d = tempfile.mkdtemp()
    for name, content in files.items():
        Path(d, name).write_text(content)
    return d


class TestSecurityVisitor:
    def _visit(self, code: str):
        tree = ast.parse(code)
        visitor = SecurityVisitor(code.splitlines(), "<test>")
        visitor.visit(tree)
        return visitor.findings

    def test_eval_detected(self):
        findings = self._visit("eval(input('x'))")
        assert any(f.category == "CODE_INJECTION" for f in findings)

    def test_exec_detected(self):
        findings = self._visit("exec('import os')")
        assert any(f.category == "CODE_INJECTION" for f in findings)

    def test_hardcoded_password(self):
        findings = self._visit("password = 'supersecret123'")
        assert any(f.category == "HARDCODED_SECRET" for f in findings)

    def test_os_system_detected(self):
        findings = self._visit("import os\nos.system('rm -rf /')")
        assert any(f.category == "COMMAND_INJECTION" for f in findings)

    def test_timing_attack(self):
        findings = self._visit("if password == 'abc': pass")
        assert any(f.category == "TIMING_ATTACK" for f in findings)

    def test_clean_code_no_findings(self):
        findings = self._visit("x = 1 + 2\nprint(x)")
        assert findings == []


class TestScanDirectory:
    def test_scan_python_code(self):
        d = write_dir({"bad.py": "eval(input())\napi_key = 'abc123xyz'"})
        findings = scan_python_code(d)
        assert len(findings) >= 1

    def test_scan_config_files(self):
        d = write_dir({".env": "DATABASE_PASSWORD=supersecret123\nDEBUG=True"})
        findings = scan_config_files(d)
        assert any(f.category in ("HARDCODED_SECRET", "DEBUG_ENABLED") for f in findings)

    def test_syntax_error_skipped(self):
        d = write_dir({"broken.py": "def foo(:\n    pass"})
        findings = scan_python_code(d)
        assert findings == []


class TestRiskScore:
    def test_empty_findings(self):
        score = calculate_risk_score([])
        assert score["score"] == 0
        assert score["level"] == "CLEAN"

    def test_critical_findings_high_score(self):
        f = SecurityFinding("id1", "CRITICAL", "CODE_INJECTION", "f.py", 1, "test")
        score = calculate_risk_score([f])
        assert score["score"] > 50

    def test_breakdown_counts(self):
        findings = [
            SecurityFinding("a", "HIGH", "cat", "f.py", 1, "d"),
            SecurityFinding("b", "LOW", "cat", "f.py", 2, "d"),
        ]
        score = calculate_risk_score(findings)
        assert score["breakdown"]["HIGH"] == 1
        assert score["breakdown"]["LOW"] == 1


class TestSarif:
    def test_sarif_structure(self):
        f = SecurityFinding("id1", "HIGH", "CODE_INJECTION", "main.py", 5,
                            "eval detected", rule_id="eval", cwe="CWE-95")
        sarif = generate_sarif_report([f])
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 1
        assert sarif["runs"][0]["results"][0]["level"] == "error"


class TestHtmlReport:
    def test_html_report_created(self, tmp_path):
        f = SecurityFinding("id1", "MEDIUM", "CAT", "f.py", 1, "desc")
        out = str(tmp_path / "report.html")
        path = export_html_report([f], out)
        assert Path(path).exists()
        content = Path(path).read_text()
        assert "MEDIUM" in content
        assert "BlackRoad Security Audit" in content
