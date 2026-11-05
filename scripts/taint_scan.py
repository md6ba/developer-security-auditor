#!/usr/bin/env python3
"""Module E enhancement — Taint-aware data-flow analysis.

Tracks user-controlled values from sources (request parameters, headers, form
fields, environment input) to dangerous sinks (SQL execution, shell execution,
file operations, template rendering, DOM sinks) within a single function.

This is a lightweight, pattern-based approximation of taint tracking. It does not
replace a full data-flow engine, and it reports POTENTIAL findings that must be
confirmed by reading the code.

Usage:
  python3 taint_scan.py --repo /path/to/repo --out ./out [--lang python,javascript]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import Finding, dedupe, emit, iter_files, language_of, write_json  # noqa: E402

# Sources: where untrusted input enters.
SOURCES = {
    "python": [
        r"request\.(args|form|json|values|files|headers|cookies)\b",
        r"request\.get_json\s*\(",
        r"request\.data\b",
        r"sys\.argv\b",
        r"input\s*\(",
        r"os\.environ\.get\s*\(",
        r"flask\.request\b",
    ],
    "javascript": [
        r"req\.(query|params|body|headers|cookies)\b",
        r"request\.(query|body|params)\b",
        r"process\.argv\b",
        r"location\.(search|hash|pathname)\b",
        r"document\.(cookie|referrer)\b",
        r"localStorage\.",
    ],
    "typescript": [
        r"req\.(query|params|body|headers|cookies)\b",
        r"process\.argv\b",
    ],
    "java": [
        r"request\.getParameter",
        r"@RequestParam",
        r"@PathVariable",
        r"@RequestBody",
        r"System\.getenv",
    ],
    "php": [
        r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\b",
        r"file_get_contents\s*\(\s*['\"]php://input",
    ],
}

# Sinks: where tainted data must not arrive.
SINKS = {
    "python": [
        (r"\bexecute\s*\(", "SQL execution"),
        (r"\bcursor\.execute\s*\(", "SQL execution"),
        (r"\bos\.system\s*\(", "shell execution"),
        (r"\bsubprocess\.(call|run|Popen)\s*\(", "shell execution"),
        (r"\bopen\s*\(", "file read/write"),
        (r"\beval\s*\(", "code evaluation"),
        (r"\bexec\s*\(", "code evaluation"),
        (r"\bpickle\.loads?\s*\(", "deserialization"),
        (r"\byaml\.load\s*\(", "deserialization"),
        (r"\brequests\.(get|post|put|delete)\s*\(", "outbound HTTP request"),
        (r"\brender_template_string\s*\(", "template rendering"),
    ],
    "javascript": [
        (r"\beval\s*\(", "code evaluation"),
        (r"\bnew Function\s*\(", "code evaluation"),
        (r"\binnerHTML\s*=", "DOM injection"),
        (r"\bouterHTML\s*=", "DOM injection"),
        (r"\bdocument\.write\s*\(", "DOM injection"),
        (r"\bchild_process\.(exec|execSync|spawn)\s*\(", "shell execution"),
        (r"\bdb\.(query|execute)\s*\(", "SQL execution"),
        (r"\.query\s*\(", "SQL execution"),
    ],
    "typescript": [
        (r"\beval\s*\(", "code evaluation"),
        (r"\binnerHTML\s*=", "DOM injection"),
        (r"\bchild_process\.(exec|execSync|spawn)\s*\(", "shell execution"),
    ],
    "java": [
        (r"\bRuntime\.getRuntime\(\)\.exec\s*\(", "shell execution"),
        (r"\bProcessBuilder\s*\(", "shell execution"),
        (r"\bcreateQuery\s*\(", "SQL execution"),
        (r"\bcreateNativeQuery\s*\(", "SQL execution"),
        (r"\bObjectInputStream\b", "deserialization"),
    ],
    "php": [
        (r"\bshell_exec\s*\(", "shell execution"),
        (r"\bexec\s*\(", "shell execution"),
        (r"\bsystem\s*\(", "shell execution"),
        (r"\beval\s*\(", "code evaluation"),
        (r"\bunserialize\s*\(", "deserialization"),
        (r"\$query\s*=.*\$_(GET|POST|REQUEST)", "SQL execution"),
    ],
}

# Variable assignment: name = <expr>
ASSIGN_RE = re.compile(r"^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+)$")


def function_blocks(text: str) -> list[tuple[int, list[str]]]:
    """Split Python-ish source into approximate function blocks (line ranges)."""
    blocks: list[tuple[int, list[str]]] = []
    current: list[str] = []
    start = 1
    for lineno, line in enumerate(text.splitlines(), start=1):
        if re.match(r"^\s*(def\s+|function\s+|class\s+|async\s+def\s+)", line):
            if current:
                blocks.append((start, current))
            current = [line]
            start = lineno
        elif current:
            if line.strip() and not line.startswith((" ", "\t", ")")):
                blocks.append((start, current))
                current = []
                start = lineno
            else:
                current.append(line)
    if current:
        blocks.append((start, current))
    return blocks


def analyse_block(lines: list[str], base_lineno: int, lang: str) -> list[dict]:
    """Return taint flows within one block."""
    tainted: dict[str, int] = {}
    flows: list[dict] = []
    src_patterns = [re.compile(p) for p in SOURCES.get(lang, [])]
    sink_patterns = [(re.compile(p), label) for p, label in SINKS.get(lang, [])]

    for offset, line in enumerate(lines):
        lineno = base_lineno + offset
        # sources
        for sp in src_patterns:
            m = sp.search(line)
            if m:
                # the variable being assigned, if any
                am = ASSIGN_RE.match(line)
                var = am.group(1) if am else None
                if var:
                    tainted[var] = lineno
                else:
                    tainted.setdefault(f"__inline_{lineno}", lineno)
                flows.append({
                    "kind": "source",
                    "line": lineno,
                    "variable": var or "(inline)",
                    "match": m.group(0),
                })
                break
        # propagation through assignment
        am = ASSIGN_RE.match(line)
        if am:
            var, expr = am.group(1), am.group(2)
            if any(name in expr for name in tainted) or any(
                sp.search(expr) for sp in src_patterns
            ):
                tainted.setdefault(var, lineno)
        # sinks
        for sp, label in sink_patterns:
            if sp.search(line):
                hit_vars = [
                    name for name in tainted
                    if name != f"__inline_{lineno}" and re.search(rf"\b{re.escape(name)}\b", line)
                ]
                inline_hit = f"__inline_{lineno}" in tainted
                if hit_vars or inline_hit:
                    flows.append({
                        "kind": "sink",
                        "line": lineno,
                        "label": label,
                        "variables": hit_vars or ["(inline)"],
                    })
    return flows


def scan_repo(repo: Path, langs: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_files(repo):
        lang = language_of(path)
        if langs and lang not in langs:
            continue
        if lang not in SOURCES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(repo))
        if rel.endswith(("AUDIT_REPORT.md", "SECURITY_AUDIT_REPORT.md")):
            continue
        for start, block in function_blocks(text):
            flows = analyse_block(block, start, lang)
            sources = [f for f in flows if f["kind"] == "source"]
            sinks = [f for f in flows if f["kind"] == "sink"]
            if not sources or not sinks:
                continue
            for sink in sinks:
                findings.append(
                    Finding(
                        finding_id="",
                        rule_id="TAINT-001",
                        title=f"Tainted data reaches {sink['label']}",
                        severity="HIGH",
                        confidence="POTENTIAL",
                        component=repo.name,
                        file_path=rel,
                        line_start=sink["line"],
                        line_end=sink["line"],
                        explanation=(
                            f"A user-controlled value flows from "
                            f"line {sources[0]['line']} ({sources[0]['match']}) to a "
                            f"{sink['label']} on line {sink['line']}."
                        ),
                        impact=(
                            "If the intermediate handling does not sanitise the value, this "
                            "is exploitable. Confirm by reading the function."
                        ),
                        evidence=(
                            f"source: {sources[0]['match']!r} -> sink: {sink['label']}; "
                            f"variables: {', '.join(sink['variables'])}"
                        ),
                        remediation=(
                            "Validate and sanitise the input at the boundary; use parameterised "
                            "queries, argument lists, or context-aware escaping."
                        ),
                        cwe="CWE-74",
                        owasp="A03:2021",
                    )
                )
    for i, f in enumerate(findings, start=1):
        f.finding_id = f"TAINT-{i:04d}"
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="Module E enhancement — taint-aware analysis")
    ap.add_argument("--repo", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--langs", default="")
    args = ap.parse_args()

    repo: Path = args.repo.resolve()
    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if not repo.exists():
        print(f"ERROR: repository not found: {repo}", file=sys.stderr)
        return 2

    langs = [x.strip() for x in args.langs.split(",") if x.strip()] or [
        "python", "javascript", "typescript", "java", "php"
    ]
    findings = dedupe(scan_repo(repo, langs))
    payload = emit(findings, out, prefix="taint-")
    write_json(
        out / "module-e-taint-status.json",
        {
            "module": "E-taint",
            "repo": str(repo),
            "languages": langs,
            "findings": payload["finding_count"],
            "note": "Taint findings are POTENTIAL and require manual confirmation.",
        },
    )

    print(f"Taint analysis complete: {payload['finding_count']} potential flow(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
