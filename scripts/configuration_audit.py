#!/usr/bin/env python3
"""Module C — Access control and configuration audit.

Inspects configuration files and source for insecure defaults, excessive
permissions, and missing access controls. Distinguishes confirmed issues from
context-dependent ones. Never connects to external systems.

Usage:
  python3 configuration_audit.py --repo /path/to/repo --out ./out
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import Finding, dedupe, emit, iter_files, language_of, write_json  # noqa: E402

CONFIG_FILES = [
    ".env", ".env.local", ".env.production", ".env.development",
    "config.json", "config.yml", "config.yaml", "settings.py", "settings.json",
    "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
    "nginx.conf", "apache2.conf", "web.config", "Caddyfile",
    "kubernetes", "k8s", "terraform",
]

CHECKS = [
    {
        "id": "CFG-DEBUG-001",
        "title": "Debug mode enabled",
        "severity": "MEDIUM",
        "confidence": "PROBABLE",
        "cwe": "CWE-489",
        "owasp": "A05:2021",
        "pattern": r"(?i)(debug\s*=\s*true|DEBUG\s*=\s*['\"]?true|debug:\s*true|'debug'\s*:\s*true)",
        "note": "Debug mode leaks stack traces, environment details, and sometimes enables interactive consoles.",
        "remediation": "Disable debug mode in production configurations and builds.",
        "extensions": [".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env", ""],
    },
    {
        "id": "CFG-TLS-001",
        "title": "TLS verification disabled",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "cwe": "CWE-295",
        "owasp": "A07:2021",
        "pattern": r"(?i)(verify_ssl\s*=\s*false|rejectUnauthorized\s*:\s*false|verify\s*:\s*false|InsecureSkipVerify\s*:\s*true|--insecure\b|\s-k\s)",
        "note": "Disabling certificate verification exposes traffic to interception.",
        "remediation": "Enable certificate verification and install a proper CA bundle.",
        "extensions": [".py", ".js", ".ts", ".go", ".yml", ".yaml", ".sh", ""],
    },
    {
        "id": "CFG-CORS-001",
        "title": "CORS allows any origin",
        "severity": "MEDIUM",
        "confidence": "PROBABLE",
        "cwe": "CWE-942",
        "owasp": "A05:2021",
        "pattern": r"(?i)(Access-Control-Allow-Origin\s*:\s*\*|allow_origins\s*=\s*\[['\"]\*|origin\s*:\s*['\"]\*|corsorigins\s*=\s*\[['\"]\*)",
        "note": "A wildcard CORS policy lets any site call this API with the victim's cookies.",
        "remediation": "Restrict allowed origins to the actual trusted domains.",
        "extensions": [".py", ".js", ".ts", ".java", ".go", ".conf", ""],
    },
    {
        "id": "CFG-PERM-001",
        "title": "World-writable file permissions",
        "severity": "MEDIUM",
        "confidence": "PROBABLE",
        "cwe": "CWE-732",
        "owasp": "A05:2021",
        "pattern": r"(?i)(chmod\s+777|0o777|FileMode\s*:\s*0777|chmod\s+666)",
        "note": "World-writable files can be modified by any local user or process.",
        "remediation": "Use the least permissive mode; secrets should be 0600.",
        "extensions": [".py", ".sh", ".go", ".yml", ".yaml", ""],
    },
    {
        "id": "CFG-AUTH-001",
        "title": "Authentication appears disabled",
        "severity": "HIGH",
        "confidence": "POTENTIAL",
        "cwe": "CWE-306",
        "owasp": "A07:2021",
        "pattern": r"(?i)(auth\s*=\s*false|authentication\s*:\s*false|noauth\s*=\s*true|skip_auth|disable_auth|allow_anonymous\s*[:=]\s*true)",
        "note": "Verify in context: a disabled auth switch in a production path is a serious exposure.",
        "remediation": "Require authentication on every production route.",
        "extensions": [".py", ".js", ".ts", ".yml", ".yaml", ".json", ""],
    },
    {
        "id": "CFG-ADMIN-001",
        "title": "Default or weak admin credential",
        "severity": "HIGH",
        "confidence": "PROBABLE",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "pattern": r"(?i)(admin\s*[=:]\s*['\"]?(admin|password|123456|root|toor)|username\s*[=:]\s*['\"]admin['\"].*password\s*[=:]\s*['\"](admin|password|123456))",
        "note": "Default credentials are trivially guessable and frequently scanned for.",
        "remediation": "Remove default credentials and require a unique, strong secret.",
        "extensions": [".env", ".py", ".yml", ".yaml", ".json", ".ini", ""],
    },
    {
        "id": "CFG-ROOT-001",
        "title": "Container or pod runs as root",
        "severity": "MEDIUM",
        "confidence": "PROBABLE",
        "cwe": "CWE-250",
        "owasp": "A05:2021",
        "pattern": r"(?i)(^\s*USER\s+root\b|\buser:\s*root\b|runAsUser:\s*0|allowPrivilegeEscalation:\s*true)",
        "note": "Running as root increases the impact of any container escape.",
        "remediation": "Define a non-root USER and disable privilege escalation.",
        "extensions": ["", ".yml", ".yaml"],
    },
    {
        "id": "CFG-MOUNT-001",
        "title": "Docker socket or host path mounted into a container",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "cwe": "CWE-250",
        "owasp": "A05:2021",
        "pattern": r"(?i)(/var/run/docker\.sock|/host|privileged:\s*true|hostPID:\s*true|hostNetwork:\s*true)",
        "note": "Mounting the Docker socket or host namespaces effectively grants root on the host.",
        "remediation": "Remove the mount; use a dedicated builder or rootless runtime.",
        "extensions": [".yml", ".yaml", ""],
    },
    {
        "id": "CFG-SECRET-ENV-001",
        "title": "Secret stored in a plaintext config file",
        "severity": "HIGH",
        "confidence": "PROBABLE",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "pattern": r"(?i)^\s*[A-Z0-9_]*(SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*['\"]?[^\s'\"$]{6,}",
        "note": "Plaintext secrets in config files are exposed to anyone with repository or host access.",
        "remediation": "Move secrets to an environment variable or a secrets manager.",
        "extensions": [".env", ".ini", ".cfg", ".conf", ""],
    },
]


def scan_file(repo: Path, path: Path, check: dict) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rx = re.compile(check["pattern"])
    exclude = check.get("exclude")
    ex_rx = re.compile(exclude) if exclude else None
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        m = rx.search(line)
        if not m:
            continue
        if ex_rx and ex_rx.search(line):
            continue
        findings.append(
            Finding(
                finding_id="",
                rule_id=check["id"],
                title=check["title"],
                severity=check["severity"],
                confidence=check["confidence"],
                component=repo.name,
                file_path=str(path.relative_to(repo)),
                line_start=lineno,
                line_end=lineno,
                explanation=check["note"],
                impact="Insecure configuration increases the impact of an otherwise limited exposure.",
                evidence=f"{check['id']} match, value redacted",
                remediation=check["remediation"],
                cwe=check["cwe"],
                owasp=check["owasp"],
            )
        )
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="Module C — access control and configuration audit")
    ap.add_argument("--repo", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    repo: Path = args.repo.resolve()
    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if not repo.exists():
        print(f"ERROR: repository not found: {repo}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    for path in iter_files(repo):
        rel = str(path.relative_to(repo))
        name = path.name
        is_config = name in CONFIG_FILES or rel.startswith(("k8s/", "kubernetes/", "terraform/"))
        for check in CHECKS:
            exts = check.get("extensions")
            if exts is not None and path.suffix.lower() not in exts:
                continue
            fnames = check.get("filenames")
            if fnames and name not in fnames:
                continue
            if not is_config and not fnames and path.suffix.lower() not in (exts or []):
                continue
            findings.extend(scan_file(repo, path, check))

    findings = dedupe(findings)
    for i, f in enumerate(findings, start=1):
        if not f.finding_id:
            f.finding_id = f"{f.rule_id}-{i:04d}"
    payload = emit(findings, out, prefix="config-")
    write_json(
        out / "module-c-status.json",
        {
            "module": "C",
            "repo": str(repo),
            "checks": len(CHECKS),
            "findings": payload["finding_count"],
            "severity_counts": payload["severity_counts"],
            "note": "No external system was contacted. Context-dependent findings are marked POTENTIAL.",
        },
    )

    print(f"Module C complete: {payload['finding_count']} finding(s)")
    for sev, count in payload["severity_counts"].items():
        if count:
            print(f"  {sev}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
