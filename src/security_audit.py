"""
BlackRoad Security Audit - AST-based Python code security scanner.
Detects vulnerabilities: eval/exec, hardcoded secrets, SQL injection, os.system.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import re
import sys
import argparse
import textwrap
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}


@dataclass
class SecurityFinding:
    id: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str          # e.g. CODE_INJECTION, HARDCODED_SECRET ...
    file: str
    line: int
    description: str
    rule_id: str = ""
    snippet: str = ""
    cwe: str = ""
    remediation: str = ""

    def risk_weight(self) -> int:
        return SEVERITY_WEIGHTS.get(self.severity, 0)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────
# AST visitor
# ─────────────────────────────────────────────

class SecurityVisitor(ast.NodeVisitor):
    """Walk AST and collect security findings."""

    DANGEROUS_CALLS = {
        "eval": ("CODE_INJECTION", "CRITICAL",
                 "eval() executes arbitrary code – never use with untrusted input.",
                 "CWE-95", "Replace eval() with ast.literal_eval() or a whitelist."),
        "exec": ("CODE_INJECTION", "CRITICAL",
                 "exec() executes arbitrary code – extremely dangerous.",
                 "CWE-95", "Avoid exec(); use importlib or subprocess with fixed args."),
        "compile": ("CODE_INJECTION", "HIGH",
                    "compile() can generate executable bytecode from strings.",
                    "CWE-95", "Ensure source is never user-controlled."),
        "pickle.loads": ("DESERIALIZATION", "CRITICAL",
                         "pickle.loads() deserialises arbitrary objects.",
                         "CWE-502", "Use JSON or msgpack; never unpickle untrusted data."),
        "yaml.load": ("DESERIALIZATION", "HIGH",
                      "yaml.load() without Loader can execute arbitrary Python.",
                      "CWE-502", "Use yaml.safe_load() instead."),
        "__import__": ("CODE_INJECTION", "HIGH",
                       "__import__() with dynamic name is dangerous.",
                       "CWE-95", "Use importlib.import_module() with a whitelist."),
    }

    SYSTEM_CALLS = {"os.system", "os.popen", "subprocess.call",
                    "subprocess.run", "subprocess.Popen"}

    PASSWORD_NAMES = re.compile(
        r"(password|passwd|pwd|secret|api_key|apikey|token|auth_key|private_key)",
        re.IGNORECASE,
    )
    SQL_PATTERNS = [
        re.compile(r"(%s|format\(|f['\"].*\bSELECT\b.*WHERE)", re.IGNORECASE),
        re.compile(r"\bexecute\s*\(\s*['\"].*%", re.IGNORECASE),
    ]

    def __init__(self, source_lines: List[str], filename: str):
        self.findings: List[SecurityFinding] = []
        self.source_lines = source_lines
        self.filename = filename
        self._counter = 0

    # ── helpers ──────────────────────────────

    def _next_id(self) -> str:
        self._counter += 1
        h = hashlib.md5(f"{self.filename}{self._counter}".encode()).hexdigest()[:8]
        return f"SA-{h}"

    def _snippet(self, lineno: int) -> str:
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].rstrip()
        return ""

    def _add(self, severity: str, category: str, line: int,
             description: str, cwe: str = "", remediation: str = "", rule_id: str = "") -> None:
        self.findings.append(SecurityFinding(
            id=self._next_id(),
            severity=severity,
            category=category,
            file=self.filename,
            line=line,
            description=description,
            rule_id=rule_id or category.lower().replace("_", "-"),
            snippet=self._snippet(line),
            cwe=cwe,
            remediation=remediation,
        ))

    # ── visitors ─────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        name = self._call_name(node)
        if name in self.DANGEROUS_CALLS:
            cat, sev, desc, cwe, rem = self.DANGEROUS_CALLS[name]
            self._add(sev, cat, node.lineno, f"{name}() detected. {desc}", cwe, rem, name)
        elif name in self.SYSTEM_CALLS:
            self._add("HIGH", "COMMAND_INJECTION",
                      node.lineno,
                      f"{name}() can lead to command injection if args are user-supplied.",
                      "CWE-78",
                      "Use subprocess with a fixed list; never pass shell=True with untrusted data.")
        elif name in ("str.format", "format") or (
            isinstance(node.func, ast.Attribute) and node.func.attr == "format"
        ):
            self._check_sql_format(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        for target in node.targets:
            if isinstance(target, ast.Name) and self.PASSWORD_NAMES.search(target.id):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self._add(
                        "CRITICAL", "HARDCODED_SECRET", node.lineno,
                        f"Hardcoded secret in variable '{target.id}'.",
                        "CWE-798",
                        "Load secrets from environment variables or a secrets manager.",
                        "hardcoded-secret",
                    )
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:  # noqa: N802
        # f-strings used in SQL context
        src = self._snippet(node.lineno)
        for pat in self.SQL_PATTERNS:
            if pat.search(src):
                self._add(
                    "HIGH", "SQL_INJECTION", node.lineno,
                    "f-string or % formatting in SQL query – risk of SQL injection.",
                    "CWE-89",
                    "Use parameterised queries (cursor.execute(sql, params)).",
                    "sql-injection",
                )
                break
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:  # noqa: N802
        # Detect `if password == "literal"`
        for comparator in node.comparators:
            if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
                left = node.left
                if isinstance(left, ast.Name) and self.PASSWORD_NAMES.search(left.id):
                    self._add(
                        "HIGH", "TIMING_ATTACK", node.lineno,
                        f"Direct string comparison of '{left.id}' is vulnerable to timing attacks.",
                        "CWE-208",
                        "Use hmac.compare_digest() for secret comparison.",
                        "timing-attack",
                    )
        self.generic_visit(node)

    def _call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            cur = node.func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return ""

    def _check_sql_format(self, node: ast.Call) -> None:
        src = self._snippet(node.lineno)
        for pat in self.SQL_PATTERNS:
            if pat.search(src):
                self._add(
                    "HIGH", "SQL_INJECTION", node.lineno,
                    "String formatting in SQL query – possible SQL injection.",
                    "CWE-89",
                    "Use parameterised queries.",
                    "sql-injection",
                )
                break


# ─────────────────────────────────────────────
# Config file scanner
# ─────────────────────────────────────────────

CONFIG_SECRET_PATTERNS = [
    (re.compile(r"(?i)(password|passwd|secret|api_key|apikey|token)\s*[:=]\s*['\"]?([^\s'\"]+)['\"]?"),
     "HARDCODED_SECRET", "CRITICAL",
     "Potential hardcoded secret in config file.", "CWE-798"),
    (re.compile(r"(?i)(debug|DEBUG)\s*[:=]\s*(true|yes|1|on)"),
     "DEBUG_ENABLED", "MEDIUM",
     "Debug mode is enabled in configuration.", "CWE-489"),
    (re.compile(r"(?i)(allow_all_origins|cors_allow_all)\s*[:=]\s*(true|yes|1|\*)"),
     "PERMISSIVE_CORS", "HIGH",
     "CORS is configured to allow all origins.", "CWE-346"),
]


def scan_config_files(directory: str) -> List[SecurityFinding]:
    """Scan .env, .ini, .cfg, .yaml, .json config files for secrets/misconfig."""
    findings: List[SecurityFinding] = []
    extensions = {".env", ".ini", ".cfg", ".yaml", ".yml", ".json", ".toml", ".conf", ".properties"}
    counter = [0]
    path = Path(directory)

    def _next_id(fname: str) -> str:
        counter[0] += 1
        h = hashlib.md5(f"{fname}{counter[0]}".encode()).hexdigest()[:8]
        return f"CF-{h}"

    for fpath in path.rglob("*"):
        if fpath.suffix.lower() not in extensions:
            continue
        if any(p in fpath.parts for p in (".git", "__pycache__", "node_modules", ".venv", "venv")):
            continue
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for lineno, raw_line in enumerate(text.splitlines(), 1):
            line = raw_line.strip()
            if line.startswith("#") or line.startswith("//"):
                continue
            for pattern, category, severity, description, cwe in CONFIG_SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(SecurityFinding(
                        id=_next_id(str(fpath)),
                        severity=severity,
                        category=category,
                        file=str(fpath),
                        line=lineno,
                        description=description,
                        rule_id=category.lower().replace("_", "-"),
                        snippet=raw_line.rstrip(),
                        cwe=cwe,
                        remediation="Use environment variables or a secrets manager.",
                    ))
    return findings


# ─────────────────────────────────────────────
# Python source scanner
# ─────────────────────────────────────────────

def scan_python_code(directory: str) -> List[SecurityFinding]:
    """Scan all .py files under *directory* using AST analysis."""
    findings: List[SecurityFinding] = []
    path = Path(directory)
    for fpath in path.rglob("*.py"):
        if any(p in fpath.parts for p in (".git", "__pycache__", ".venv", "venv")):
            continue
        try:
            source = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        try:
            tree = ast.parse(source, filename=str(fpath))
        except SyntaxError:
            continue
        lines = source.splitlines()
        visitor = SecurityVisitor(lines, str(fpath))
        visitor.visit(tree)
        findings.extend(visitor.findings)
    return findings


# ─────────────────────────────────────────────
# Risk scoring
# ─────────────────────────────────────────────

def calculate_risk_score(findings: List[SecurityFinding]) -> Dict[str, Any]:
    """Return a risk summary dict with numeric score 0-100."""
    if not findings:
        return {"score": 0, "level": "CLEAN", "breakdown": {}, "total": 0}

    breakdown: Dict[str, int] = {}
    raw = 0
    for f in findings:
        breakdown[f.severity] = breakdown.get(f.severity, 0) + 1
        raw += f.risk_weight()

    # Normalise to 0-100; cap at 100
    max_possible = len(findings) * SEVERITY_WEIGHTS["CRITICAL"]
    score = min(100, int((raw / max_possible) * 100)) if max_possible else 0

    level = (
        "CRITICAL" if score >= 80 else
        "HIGH" if score >= 60 else
        "MEDIUM" if score >= 40 else
        "LOW" if score >= 20 else
        "INFO"
    )
    return {
        "score": score,
        "level": level,
        "raw": raw,
        "breakdown": breakdown,
        "total": len(findings),
    }


# ─────────────────────────────────────────────
# SARIF output
# ─────────────────────────────────────────────

def generate_sarif_report(findings: List[SecurityFinding]) -> Dict[str, Any]:
    """Generate a SARIF 2.1.0 report from findings."""
    rules: Dict[str, Any] = {}
    results = []

    for f in findings:
        rule_id = f.rule_id or f.category.lower()
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.category,
                "shortDescription": {"text": f.description[:80]},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.replace('CWE-','')}.html"
                if f.cwe else "https://blackroad.io/security",
                "properties": {"tags": [f.category, f.severity]},
            }
        results.append({
            "ruleId": rule_id,
            "level": {
                "CRITICAL": "error", "HIGH": "error",
                "MEDIUM": "warning", "LOW": "note", "INFO": "none",
            }.get(f.severity, "warning"),
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace("\\", "/")},
                    "region": {"startLine": f.line},
                }
            }],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "blackroad-security-audit",
                    "version": "1.0.0",
                    "informationUri": "https://blackroad.io",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


# ─────────────────────────────────────────────
# HTML report
# ─────────────────────────────────────────────

_SEVERITY_COLORS = {
    "CRITICAL": "#c0392b", "HIGH": "#e74c3c",
    "MEDIUM": "#e67e22", "LOW": "#f1c40f", "INFO": "#3498db",
}


def export_html_report(findings: List[SecurityFinding], output_path: str = "report.html") -> str:
    """Generate a self-contained HTML security report."""
    risk = calculate_risk_score(findings)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = ""
    for f in sorted(findings, key=lambda x: -x.risk_weight()):
        color = _SEVERITY_COLORS.get(f.severity, "#95a5a6")
        rows += f"""
        <tr>
          <td><code>{f.id}</code></td>
          <td style="color:{color};font-weight:bold">{f.severity}</td>
          <td>{f.category}</td>
          <td>{f.file}:{f.line}</td>
          <td>{f.description}</td>
          <td><code>{f.cwe}</code></td>
        </tr>"""

    html = textwrap.dedent(f"""<!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><title>Security Audit Report</title>
    <style>
      body{{font-family:sans-serif;margin:2rem;background:#0d1117;color:#c9d1d9}}
      h1{{color:#58a6ff}} table{{width:100%;border-collapse:collapse;margin-top:1rem}}
      th{{background:#161b22;padding:.5rem;text-align:left;color:#8b949e}}
      td{{padding:.45rem .5rem;border-bottom:1px solid #21262d;font-size:.85rem}}
      tr:hover{{background:#161b22}} .badge{{padding:.2rem .5rem;border-radius:4px;color:#fff}}
      .score{{font-size:3rem;font-weight:bold;color:{_SEVERITY_COLORS.get(risk['level'],'#58a6ff')}}}
    </style></head>
    <body>
    <h1>�� BlackRoad Security Audit Report</h1>
    <p>Generated: {ts}</p>
    <div class="score">{risk['score']}/100</div>
    <p>Risk Level: <strong>{risk['level']}</strong> | Findings: <strong>{risk['total']}</strong></p>
    <table><thead><tr>
      <th>ID</th><th>Severity</th><th>Category</th><th>Location</th>
      <th>Description</th><th>CWE</th>
    </tr></thead><tbody>{rows}</tbody></table>
    </body></html>""")

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="BlackRoad Security Audit – AST-based Python scanner")
    p.add_argument("directory", nargs="?", default=".", help="Directory to scan")
    p.add_argument("--format", choices=["text", "json", "sarif", "html"], default="text")
    p.add_argument("--output", "-o", default=None, help="Output file (default: stdout / report.*)")
    p.add_argument("--severity", choices=["ALL","CRITICAL","HIGH","MEDIUM","LOW"], default="ALL")
    p.add_argument("--config", action="store_true", help="Also scan config files")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    findings = scan_python_code(args.directory)
    if args.config:
        findings.extend(scan_config_files(args.directory))

    if args.severity != "ALL":
        order = list(SEVERITY_WEIGHTS.keys())
        cutoff = order.index(args.severity)
        findings = [f for f in findings if order.index(f.severity) <= cutoff]

    risk = calculate_risk_score(findings)

    if args.format == "json":
        output = json.dumps([f.to_dict() for f in findings], indent=2)
        if args.output:
            Path(args.output).write_text(output)
        else:
            print(output)
    elif args.format == "sarif":
        output = json.dumps(generate_sarif_report(findings), indent=2)
        dest = args.output or "results.sarif"
        Path(dest).write_text(output)
        print(f"SARIF report written to {dest}")
    elif args.format == "html":
        dest = args.output or "report.html"
        export_html_report(findings, dest)
        print(f"HTML report written to {dest}")
    else:
        print(f"\n{'='*60}")
        print("  BlackRoad Security Audit")
        print(f"{'='*60}")
        print(f"  Directory : {args.directory}")
        print(f"  Findings  : {risk['total']}")
        print(f"  Risk Score: {risk['score']}/100  [{risk['level']}]")
        print(f"{'='*60}\n")
        for f in sorted(findings, key=lambda x: -x.risk_weight()):
            print(f"  [{f.severity:<8}] {f.category} | {f.file}:{f.line}")
            print(f"             {f.description}")
            if f.cwe:
                print(f"             CWE: {f.cwe}")
            print()
    return 1 if any(f.severity in ("CRITICAL","HIGH") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
