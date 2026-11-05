#!/usr/bin/env python3
"""Module B — Secret and credential exposure scan.

Runs gitleaks and trufflehog when available, then applies the local rule catalog
to the working tree. Every finding is redacted and fingerprinted; raw secret
values are never written anywhere.

Usage:
  python3 secret_scan.py --repo /path/to/repo --out ./out [--catalog rules/catalog.json]
                         [--langs python,javascript] [--no-gitleaks] [--no-trufflehog]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    Finding,
    catalog_rules,
    dedupe,
    describe_value,
    emit,
    fingerprint,
    iter_files,
    language_of,
    load_catalog,
    redact,
    run_cmd,
    which,
    write_json,
)

SECRET_EXTENSIONS = [
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".json", ".yml", ".yaml", ".env", ".ini", ".cfg", ".toml", ".md",
    ".txt", ".sh", ".ps1", ".sql", ".html", ".vue", ".sol", "",
    ".key", ".pem", ".p12", ".pfx", ".keystore", ".jks", ".crt", ".ppk",
]

CONFIG_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.development",
    "config.json", "config.yml", "config.yaml", "settings.py",
    "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
}


def scan_gitleaks(repo: Path, out_dir: Path) -> list[Finding]:
    """gitleaks over the working tree. Exit 1 means leaks found, not failure."""
    if not which("gitleaks"):
        return []
    report = out_dir / "gitleaks-working-tree.json"
    rc, stdout, stderr = run_cmd(
        [
            "gitleaks", "detect",
            "-s", str(repo),
            "-f", "json",
            "-r", str(report),
            "--no-banner", "--no-color", "--redact",
            "--no-git",
        ],
        timeout=600,
    )
    if rc not in (0, 1) or not report.exists():
        return []
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    findings: list[Finding] = []
    for i, leak in enumerate(data if isinstance(data, list) else [], start=1):
        match = leak.get("Match") or leak.get("Secret") or ""
        findings.append(
            Finding(
                finding_id=f"GL-{i:04d}",
                rule_id=leak.get("RuleID", "GLEAK"),
                title=f"gitleaks: {leak.get('RuleID', 'unknown rule')}",
                severity=_gitleaks_severity(leak.get("RuleID", "")),
                confidence="CONFIRMED",
                component=leak.get("Repo") or repo.name,
                file_path=leak.get("File", ""),
                line_start=int(leak.get("StartLine") or 0),
                line_end=int(leak.get("EndLine") or 0),
                explanation="gitleaks detected a credential-shaped value in the working tree.",
                impact="Exposed credential in a tracked or present file.",
                evidence=f"{leak.get('RuleID', '')} match, {describe_value(match)}",
                remediation="Remove the value, rotate it, and read it from the environment.",
                fingerprint=fingerprint(match),
            )
        )
    return findings


def _gitleaks_severity(rule_id: str) -> str:
    rid = rule_id.lower()
    if any(k in rid for k in ("private-key", "aws", "github", "stripe", "telegram")):
        return "CRITICAL"
    if any(k in rid for k in ("api-key", "token", "secret", "password", "jwt")):
        return "HIGH"
    return "MEDIUM"


def scan_trufflehog(repo: Path, out_dir: Path) -> list[Finding]:
    """trufflehog in non-verifying mode. Never enables verification."""
    if not which("trufflehog"):
        return []
    report = out_dir / "trufflehog-working-tree.json"
    rc, stdout, stderr = run_cmd(
        [
            "trufflehog", "filesystem",
            str(repo),
            "--json",
            "--no-update",
            "--no-verification",
            "--exclude-detectors=low-cred-check",
        ],
        timeout=600,
    )
    if rc not in (0, 1):
        return []
    findings: list[Finding] = []
    for i, line in enumerate(stdout.splitlines(), start=1):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        raw = str(rec.get("Raw") or rec.get("RawV2") or "")
        if not raw:
            continue
        det = rec.get("DetectorName") or rec.get("DetectorType") or "trufflehog"
        findings.append(
            Finding(
                finding_id=f"TH-{i:04d}",
                rule_id=f"TH-{det}".upper().replace(" ", "-")[:40],
                title=f"trufflehog: {det}",
                severity="HIGH",
                confidence="PROBABLE",
                component=repo.name,
                file_path=str(rec.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "")),
                line_start=int(rec.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0) or 0),
                line_end=0,
                explanation="trufflehog matched a credential-shaped value (verification disabled).",
                impact="Potentially exposed credential; not validated against any service.",
                evidence=f"{det}, {describe_value(raw)}",
                remediation="Treat as exposed: rotate the credential and remove it from the repository.",
                fingerprint=fingerprint(raw),
            )
        )
    return findings


def scan_catalog(repo: Path, rules: list[dict]) -> list[Finding]:
    """Apply catalog regex rules to the working tree."""
    findings: list[Finding] = []
    for path in iter_files(repo, extensions=SECRET_EXTENSIONS):
        rel = str(path.relative_to(repo))
        if rel.endswith("AUDIT_REPORT.md") or rel.endswith("SECURITY_AUDIT_REPORT.md"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lang = language_of(path) or "*"
        for rule in rules:
            if rule.get("languages") and "*" not in rule["languages"]:
                if lang not in rule["languages"]:
                    continue
            pattern = rule.get("pattern")
            if not pattern:
                continue
            try:
                rx = re.compile(pattern)
            except re.error:
                continue
            exclude = rule.get("exclude")
            ex_rx = re.compile(exclude) if exclude else None
            for lineno, line in enumerate(text.splitlines(), start=1):
                m = rx.search(line)
                if not m:
                    continue
                if ex_rx and ex_rx.search(line):
                    continue
                raw = m.group(0)
                findings.append(
                    Finding(
                        finding_id="",
                        rule_id=rule["id"],
                        title=rule["title"],
                        severity=rule.get("severity", "MEDIUM"),
                        confidence=rule.get("confidence", "PROBABLE"),
                        component=repo.name,
                        file_path=rel,
                        line_start=lineno,
                        line_end=lineno,
                        explanation=rule.get("note") or f"Pattern match for {rule['id']}.",
                        impact="Credential or sensitive configuration exposed in source.",
                        evidence=f"{rule['id']} match, {describe_value(raw)}",
                        remediation=rule.get("remediation", "Remove and rotate."),
                        cwe=rule.get("cwe", ""),
                        owasp=rule.get("owasp", ""),
                        fingerprint=fingerprint(raw),
                    )
                )
    # assign ids
    for i, f in enumerate(findings, start=1):
        f.finding_id = f"{f.rule_id}-{i:04d}"
    return findings


def check_env_files(repo: Path, rules: list[dict]) -> list[Finding]:
    """Explicitly inspect tracked .env files and config files."""
    findings: list[Finding] = []
    for path in iter_files(repo):
        rel = str(path.relative_to(repo))
        name = path.name
        if not (name.startswith(".env") or name in CONFIG_FILENAMES):
            continue
        if any(name.endswith(s) for s in (".example", ".sample", ".template")):
            continue
        if rel.endswith("AUDIT_REPORT.md"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        populated = 0
        for line in text.splitlines():
            if "=" in line and not line.strip().startswith("#"):
                _, _, value = line.partition("=")
                if value.strip():
                    populated += 1
        if name.startswith(".env"):
            findings.append(
                Finding(
                    finding_id="",
                    rule_id="SEC-ENV-001",
                    title="Committed environment file",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    component=repo.name,
                    file_path=rel,
                    line_start=1,
                    line_end=len(text.splitlines()),
                    explanation=(
                        f"A .env file is tracked in the repository with {populated} populated value(s)."
                    ),
                    impact="Environment files routinely carry credentials and are the most common leak vector.",
                    evidence=f"{populated} populated keys, names only: "
                             + ", ".join(
                                 sorted({l.split("=", 1)[0].strip() for l in text.splitlines()
                                         if "=" in l and not l.strip().startswith("#")})[:8]
                             ),
                    remediation="Remove the file, add it to .gitignore, and rotate its contents.",
                    cwe="CWE-798",
                    owasp="A07:2021",
                )
            )
    for i, f in enumerate(findings, start=1):
        f.finding_id = f"ENV-{i:04d}"
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="Module B — secret and credential exposure scan")
    ap.add_argument("--repo", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--catalog", type=Path, default=None)
    ap.add_argument("--langs", default="")
    ap.add_argument("--no-gitleaks", action="store_true")
    ap.add_argument("--no-trufflehog", action="store_true")
    ap.add_argument("--no-catalog", action="store_true")
    args = ap.parse_args()

    repo: Path = args.repo.resolve()
    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    if not repo.exists():
        print(f"ERROR: repository not found: {repo}", file=sys.stderr)
        return 2

    catalog = load_catalog(args.catalog)
    langs = [x.strip() for x in args.langs.split(",") if x.strip()] or None
    rules = catalog_rules(catalog, languages=langs)

    tool_status = {
        "gitleaks": bool(which("gitleaks")) and not args.no_gitleaks,
        "trufflehog": bool(which("trufflehog")) and not args.no_trufflehog,
        "catalog_rules": len(rules) if not args.no_catalog else 0,
    }

    findings: list[Finding] = []
    if tool_status["gitleaks"]:
        findings += scan_gitleaks(repo, out)
    if tool_status["trufflehog"]:
        findings += scan_trufflehog(repo, out)
    if not args.no_catalog:
        findings += scan_catalog(repo, rules)
        findings += check_env_files(repo, rules)

    findings = dedupe(findings)
    payload = emit(findings, out, prefix="")

    write_json(
        out / "module-b-status.json",
        {
            "module": "B",
            "repo": str(repo),
            "tools": tool_status,
            "findings": payload["finding_count"],
            "severity_counts": payload["severity_counts"],
            "note": "No credential was validated or used. All values are redacted and fingerprinted.",
        },
    )

    print(f"Module B complete: {payload['finding_count']} finding(s)")
    for sev, count in payload["severity_counts"].items():
        if count:
            print(f"  {sev}: {count}")
    if not tool_status["gitleaks"]:
        print("  NOTE: gitleaks unavailable — gitleaks coverage skipped")
    if not tool_status["trufflehog"]:
        print("  NOTE: trufflehog unavailable — trufflehog coverage skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
