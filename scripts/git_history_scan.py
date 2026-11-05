#!/usr/bin/env python3
"""Module G — Git and development workflow security.

Scans the full commit history of a repository for secrets, deleted-but-recoverable
credentials, and workflow problems. Read-only: the repository is never modified.

Usage:
  python3 git_history_scan.py --repo /path/to/repo --out ./out [--max-commits 2000]
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
    describe_value,
    fingerprint,
    load_catalog,
    run_cmd,
    which,
    write_json,
)

HISTORY_EXTENSIONS = [
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".json", ".yml", ".yaml", ".env", ".ini", ".cfg", ".toml", ".md",
    ".txt", ".sh", ".sql", ".html", ".vue", ".sol", "",
]

HISTORY_EXCLUDES = [
    ".git", ".venv", "venv", "node_modules", "site-packages", "__pycache__",
    "dist", "build", "vendor", "third_party", "assets",
]


def _git(repo: Path, *args: str, timeout: int = 300) -> tuple[int, str, str]:
    return run_cmd(["git", "-C", str(repo), *args], timeout=timeout)


def has_git(repo: Path) -> bool:
    return (repo / ".git").exists()


def all_branches(repo: Path) -> list[str]:
    rc, out, _ = _git(repo, "for-each-ref", "--format=%(refname:short)", "refs/remotes", "refs/heads")
    if rc != 0:
        return []
    return sorted({line.strip() for line in out.splitlines() if line.strip()})


def scan_history_secrets(repo: Path, out: Path, max_commits: int) -> list[Finding]:
    """Use gitleaks in git mode across the whole repository (all reachable commits)."""
    if not which("gitleaks"):
        return []
    report = out / "gitleaks-history.json"
    cmd = [
        "gitleaks", "detect",
        "-s", str(repo),
        "-f", "json",
        "-r", str(report),
        "--no-banner", "--no-color", "--redact",
        "--log-opts", f"-n {max_commits}",
    ]
    rc, _, _ = run_cmd(cmd, timeout=900)
    if rc not in (0, 1) or not report.exists():
        return []
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    findings: list[Finding] = []
    for i, leak in enumerate(data if isinstance(data, list) else [], start=1):
        raw = leak.get("Match") or leak.get("Secret") or ""
        commit = (leak.get("Commit") or "")[:12]
        findings.append(
            Finding(
                finding_id=f"GLH-{i:04d}",
                rule_id=leak.get("RuleID", "GLEAK-HISTORY"),
                title=f"gitleaks history: {leak.get('RuleID', 'unknown')}",
                severity="CRITICAL" if "private-key" in leak.get("RuleID", "").lower() else "HIGH",
                confidence="CONFIRMED",
                component=repo.name,
                file_path=leak.get("File", ""),
                line_start=int(leak.get("StartLine") or 0),
                line_end=int(leak.get("EndLine") or 0),
                explanation=(
                    "A credential-shaped value exists in git history. "
                    "Removing it from the current commit does not remove it from history."
                ),
                impact="Recoverable by anyone who clones the repository.",
                evidence=f"{leak.get('RuleID', '')}, {describe_value(raw)}",
                remediation="Rotate the credential and rewrite history, or treat it as permanently public.",
                cwe="CWE-798",
                owasp="A07:2021",
                commit=commit,
                historical_only=True,
                fingerprint=fingerprint(raw),
            )
        )
    return findings


def scan_deleted_files(repo: Path) -> list[Finding]:
    """Find files that were added and then deleted — a classic leak pattern."""
    rc, out, _ = _git(
        repo, "log", "--all", "--diff-filter=D", "--name-only", "--pretty=format:@@@%H"
    )
    if rc != 0:
        return []
    findings: list[Finding] = []
    commit = ""
    seen: set[str] = set()
    for line in out.splitlines():
        if line.startswith("@@@"):
            commit = line[3:][:12]
            continue
        name = line.strip()
        if not name or name in seen:
            continue
        seen.add(name)
        lower = name.lower()
        interesting = (
            ".env" in lower
            or lower.endswith((".pem", ".key", ".p12", ".pfx", ".keystore"))
            or "credential" in lower
            or "secret" in lower
            or "password" in lower
            or "id_rsa" in lower
        )
        if not interesting:
            continue
        # was it ever present?
        rc2, out2, _ = _git(repo, "log", "--all", "--oneline", "--", name)
        if rc2 != 0 or not out2.strip():
            continue
        findings.append(
            Finding(
                finding_id="",
                rule_id="SEC-GIT-DEL-001",
                title="Sensitive-named file deleted but recoverable",
                severity="HIGH",
                confidence="CONFIRMED",
                component=repo.name,
                file_path=name,
                line_start=0,
                line_end=0,
                explanation=(
                    "This file was committed and later deleted. Its content remains "
                    "recoverable from git history."
                ),
                impact="A secret removed from HEAD is still exposed to anyone who clones.",
                evidence=f"deleted in {commit or 'unknown'}, {len(out2.splitlines())} commit(s) touched it",
                remediation="Treat the content as public: rotate it and consider a history rewrite.",
                cwe="CWE-540",
                owasp="A05:2021",
                commit=commit,
                historical_only=True,
            )
        )
    for i, f in enumerate(findings, start=1):
        f.finding_id = f"DEL-{i:04d}"
    return findings


def scan_gitignore(repo: Path) -> list[Finding]:
    gi = repo / ".gitignore"
    if not gi.exists():
        return [
            Finding(
                finding_id="GI-0001",
                rule_id="SEC-CFG-006",
                title="No .gitignore present",
                severity="MEDIUM",
                confidence="CONFIRMED",
                component=repo.name,
                file_path=".gitignore",
                line_start=0,
                line_end=0,
                explanation="The repository has no .gitignore file.",
                impact="Secrets, virtual environments, and caches are easy to commit by accident.",
                evidence="file absent",
                remediation="Add a .gitignore covering .env, keys/, *.pem, *.key, __pycache__/, .venv/, node_modules/.",
                cwe="CWE-540",
                owasp="A05:2021",
            )
        ]
    try:
        text = gi.read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        text = ""
    missing = [
        token
        for token in (".env", "*.pem", "*.key", "keys/", "__pycache__/", "node_modules/", ".venv/")
        if token not in text
    ]
    if not missing:
        return []
    return [
        Finding(
            finding_id="GI-0002",
            rule_id="SEC-CFG-006",
            title=".gitignore is incomplete",
            severity="MEDIUM",
            confidence="CONFIRMED",
            component=repo.name,
            file_path=".gitignore",
            line_start=1,
            line_end=len(text.splitlines()),
            explanation="The .gitignore does not cover: " + ", ".join(missing),
            impact="Common secret and build artifacts can be committed accidentally.",
            evidence="missing entries: " + ", ".join(missing),
            remediation="Add the missing entries.",
            cwe="CWE-540",
            owasp="A05:2021",
        )
    ]


def scan_workflow(repo: Path) -> list[Finding]:
    findings: list[Finding] = []
    wf_dir = repo / ".github" / "workflows"
    if wf_dir.is_dir():
        for wf in sorted(wf_dir.glob("*.y*ml")):
            try:
                text = wf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = str(wf.relative_to(repo))
            if re.search(r"pull_request_target", text) and re.search(r"checkout.*ref", text, re.I):
                findings.append(
                    Finding(
                        finding_id="",
                        rule_id="SEC-CI-001",
                        title="Workflow uses pull_request_target with a checkout",
                        severity="HIGH",
                        confidence="PROBABLE",
                        component=repo.name,
                        file_path=rel,
                        line_start=0,
                        line_end=0,
                        explanation=(
                            "pull_request_target runs with repository secrets and writes permissions; "
                            "checking out untrusted PR code in that context is a known privilege path."
                        ),
                        impact="A malicious pull request could exfiltrate workflow secrets.",
                        evidence="pull_request_target + checkout detected",
                        remediation="Avoid checking out the PR head in a pull_request_target workflow.",
                        cwe="CWE-250",
                        owasp="A05:2021",
                    )
                )
            if re.search(r"secrets\.", text):
                findings.append(
                    Finding(
                        finding_id="",
                        rule_id="SEC-CI-002",
                        title="Workflow references repository secrets",
                        severity="INFORMATIONAL",
                        confidence="CONFIRMED",
                        component=repo.name,
                        file_path=rel,
                        line_start=0,
                        line_end=0,
                        explanation="The workflow consumes secrets. Confirm each is required and scoped.",
                        impact="Over-scoped secrets in CI are a common exfiltration target.",
                        evidence="secrets.* reference present",
                        remediation="Use the least-privilege secret and pin third-party actions by SHA.",
                        cwe="CWE-250",
                        owasp="A05:2021",
                    )
                )
    for i, f in enumerate(findings, start=1):
        f.finding_id = f"CI-{i:04d}"
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="Module G — git and workflow security")
    ap.add_argument("--repo", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--max-commits", type=int, default=2000)
    ap.add_argument("--no-gitleaks", action="store_true")
    args = ap.parse_args()

    repo: Path = args.repo.resolve()
    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    if not has_git(repo):
        print(f"ERROR: not a git repository: {repo}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    tools = {"gitleaks": bool(which("gitleaks")) and not args.no_gitleaks, "git": True}

    if tools["gitleaks"]:
        findings += scan_history_secrets(repo, out, args.max_commits)
    findings += scan_deleted_files(repo)
    findings += scan_gitignore(repo)
    findings += scan_workflow(repo)

    from common import dedupe, emit

    findings = dedupe(findings)
    payload = emit(findings, out, prefix="git-")

    write_json(
        out / "module-g-status.json",
        {
            "module": "G",
            "repo": str(repo),
            "tools": tools,
            "branches": all_branches(repo),
            "findings": payload["finding_count"],
            "severity_counts": payload["severity_counts"],
            "note": "History scanning is read-only. No credential was validated.",
        },
    )

    print(f"Module G complete: {payload['finding_count']} finding(s)")
    for sev, count in payload["severity_counts"].items():
        if count:
            print(f"  {sev}: {count}")
    if not tools["gitleaks"]:
        print("  NOTE: gitleaks unavailable — history secret scan skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
