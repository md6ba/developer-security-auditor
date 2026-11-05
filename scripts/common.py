#!/usr/bin/env python3
"""Shared helpers for the Developer Security Auditor scripts.

Standard library only. No network access, no writes outside the output directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "1.0.0"
SKILL_ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = SKILL_ROOT / "rules" / "catalog.json"
BOUNDARIES_PATH = SKILL_ROOT / "rules" / "security-boundaries.md"
TEMPLATES_DIR = SKILL_ROOT / "templates"

# Directories that must never be scanned for source-level findings.
DEFAULT_EXCLUDES = [
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "site-packages",
    "dist",
    "build",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "vendor",
    "third_party",
    "assets",
    "samples",
]

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
CONFIDENCE_ORDER = ["CONFIRMED", "PROBABLE", "POTENTIAL"]


@dataclass
class Finding:
    """One audit finding. Never holds a secret value."""

    finding_id: str
    rule_id: str
    title: str
    severity: str
    confidence: str
    component: str
    file_path: str
    line_start: int
    line_end: int
    explanation: str
    impact: str
    evidence: str
    remediation: str
    cwe: str = ""
    owasp: str = ""
    status: str = "UNVERIFIED - POTENTIALLY EXPOSED"
    commit: str = ""
    historical_only: bool = False
    occurrences: int = 1
    fingerprint: str = ""
    advisory: str = ""
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "schema_version": self.schema_version,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "component": self.component,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "explanation": self.explanation,
            "impact": self.impact,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "status": self.status,
            "commit": self.commit,
            "historical_only": self.historical_only,
            "occurrences": self.occurrences,
            "fingerprint": self.fingerprint,
            "advisory": self.advisory,
        }


def fingerprint(value: str) -> str:
    """Non-reversible identifier for a secret. Safe to publish."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]


def redact(value: str, keep: int = 4) -> str:
    """Return a publishable representation of a secret."""
    if not value:
        return "[EMPTY]"
    if len(value) <= keep * 2:
        return "[REDACTED]"
    return f"{value[:keep]}...[REDACTED]...{value[-keep:]} ({len(value)} chars)"


def describe_value(value: str) -> str:
    """Describe a secret without revealing it: length, charset class, fingerprint."""
    if not value:
        return "empty"
    charset = (
        "hex"
        if re.fullmatch(r"[0-9a-fA-F]+", value)
        else "base64ish"
        if re.fullmatch(r"[A-Za-z0-9_\-+/=]+", value)
        else "mixed"
    )
    return f"{len(value)} chars, {charset}, sha256:{fingerprint(value)}"


def load_catalog(path: Path | None = None) -> dict[str, Any]:
    p = path or CATALOG_PATH
    if not p.exists():
        raise SystemExit(f"rule catalog not found: {p}")
    with p.open(encoding="utf-8") as fh:
        catalog = json.load(fh)
    if catalog.get("schema_version") != SCHEMA_VERSION:
        print(
            f"WARNING: catalog schema_version {catalog.get('schema_version')!r} "
            f"!= supported {SCHEMA_VERSION!r}",
            file=sys.stderr,
        )
    return catalog


def catalog_rules(catalog: dict[str, Any], *, languages: Iterable[str] | None = None,
                  category: str | None = None) -> list[dict[str, Any]]:
    out = []
    for rule in catalog.get("rules", []):
        if category and rule.get("category") != category:
            continue
        if languages:
            langs = rule.get("languages", ["*"])
            if "*" not in langs and not (set(langs) & set(languages)):
                continue
        out.append(rule)
    return out


def which(tool: str) -> str | None:
    return shutil.which(tool)


def run_cmd(cmd: list[str], *, timeout: int = 300, cwd: Path | None = None) -> tuple[int, str, str]:
    """Run a command. Returns (returncode, stdout, stderr). Never raises."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return 127, "", f"executable not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except Exception as exc:  # pragma: no cover - defensive
        return 1, "", f"{type(exc).__name__}: {exc}"


def iter_files(root: Path, *, excludes: Iterable[str] | None = None,
               extensions: Iterable[str] | None = None) -> Iterable[Path]:
    """Yield files under root, skipping excluded directory names."""
    skip = set(excludes or []) | set(DEFAULT_EXCLUDES)
    exts = set(extensions) if extensions else None
    if not root.exists():
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if exts and p.suffix.lower() not in exts:
                continue
            yield p


def language_of(path: Path) -> str:
    return {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".php": "php",
        ".sol": "solidity",
        ".json": "json",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".md": "markdown",
        ".html": "html",
    }.get(path.suffix.lower(), "")


def now_iso() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev.upper())
    except ValueError:
        return len(SEVERITY_ORDER)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse identical findings (same rule, file, line, fingerprint)."""
    seen: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.rule_id, f.file_path, f.line_start, f.fingerprint)
        if key in seen:
            seen[key].occurrences += 1
        else:
            seen[key] = f
    return sorted(
        seen.values(),
        key=lambda x: (severity_rank(x.severity), x.rule_id, x.file_path, x.line_start),
    )


def emit(findings: list[Finding], output_dir: Path, *, prefix: str = "") -> dict[str, Any]:
    """Write a JSON findings file and return summary counts."""
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now_iso(),
        "finding_count": len(findings),
        "severity_counts": {
            s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER
        },
        "findings": [f.to_dict() for f in findings],
    }
    write_json(output_dir / f"{prefix}findings.json", payload)
    return payload
