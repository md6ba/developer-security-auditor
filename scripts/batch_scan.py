#!/usr/bin/env python3
"""Module G+ — batch scanning across many repositories.

Scans every Git repository found under a root directory, one output directory per
repository, plus a consolidated summary.

Safety:
  * read-only; audited repositories are never modified
  * repositories over the size ceiling are reported as skipped, not scanned
  * sequential by design; no parallel workers
  * no network calls; no credential use or validation

Usage:
  python3 batch_scan.py --root /path/to/repos --out /path/to/out
  python3 batch_scan.py --root /path/to/repos --out /path/to/out --size-ceiling-mb 100
  python3 batch_scan.py --root /path/to/repos --out /path/to/out --mode standard
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import now_iso, write_json  # noqa: E402

SCRIPTS = Path(__file__).resolve().parent

# The original batch script used a default ceiling of 100 MB. Kept as the default.
DEFAULT_SIZE_CEILING_MB = 100

MODES = {
    "quick": ["repository_inventory.py", "secret_scan.py"],
    "standard": [
        "repository_inventory.py", "secret_scan.py", "configuration_audit.py",
        "taint_scan.py", "git_history_scan.py",
    ],
    "secret-only": ["secret_scan.py", "git_history_scan.py"],
    "deep": [
        "repository_inventory.py", "secret_scan.py", "configuration_audit.py",
        "taint_scan.py", "git_history_scan.py", "honeytoken_gen.py",
        "diversify.py",
    ],
}


def discover_repos(root: Path) -> list[Path]:
    """Every directory that contains a .git entry, at any depth."""
    found: list[Path] = []
    for git_dir in root.rglob(".git"):
        if git_dir.is_dir():
            found.append(git_dir.parent)
    return sorted(found)


def dir_size_bytes(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file() and not p.is_symlink():
                total += p.stat().st_size
        except OSError:
            continue
    return total


def run_module(script: str, repo: Path, out: Path, extra: list[str]) -> tuple[int, str]:
    cmd = [sys.executable, str(SCRIPTS / script), "--repo", str(repo), "--out", str(out)]
    cmd.extend(extra)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        return r.returncode, (r.stderr or "").strip()
    except subprocess.TimeoutExpired:
        return -1, "timeout after 1800s"
    except FileNotFoundError as e:
        return -2, str(e)


def collect_findings(repo_out: Path) -> dict[str, int]:
    counts = {sev: 0 for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")}
    for name in ("findings.json", "config-findings.json", "taint-findings.json",
                 "git-findings.json"):
        p = repo_out / name
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for f in data.get("findings", []):
            sev = f.get("severity", "INFORMATIONAL")
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def main() -> int:
    ap = argparse.ArgumentParser(description="Batch security scan across repositories")
    ap.add_argument("--root", required=True, help="directory containing repositories")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--mode", default="standard", choices=sorted(MODES))
    ap.add_argument("--size-ceiling-mb", type=int, default=DEFAULT_SIZE_CEILING_MB,
                    help="skip repositories larger than this (default 100)")
    ap.add_argument("--max-repos", type=int, default=0,
                    help="0 = no limit (default)")
    ap.add_argument("--langs", default="python,javascript",
                    help="comma-separated languages for taint analysis")
    ap.add_argument("--skip-git-history", action="store_true",
                    help="do not scan git history")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    if not root.is_dir():
        print(f"ERROR: root directory not found: {root}", file=sys.stderr)
        return 2

    repos = discover_repos(root)
    if not repos:
        print(f"No Git repositories found under {root}")
        return 0

    ceiling = args.size_ceiling_mb * 1024 * 1024
    if args.max_repos > 0:
        repos = repos[:args.max_repos]

    modules = list(MODES[args.mode])
    if args.skip_git_history:
        modules = [m for m in modules if m != "git_history_scan.py"]

    print(f"Batch scan: {len(repos)} repository/ies under {root}")
    print(f"Mode: {args.mode} | modules: {', '.join(modules)}")
    print(f"Size ceiling: {args.size_ceiling_mb} MB")
    print()

    scanned: list[dict] = []
    skipped: list[dict] = []
    failed: list[dict] = []

    for i, repo in enumerate(repos, start=1):
        name = repo.name
        size = dir_size_bytes(repo)
        print(f"[{i}/{len(repos)}] {name} ({size / (1024 * 1024):.1f} MB)")

        if size > ceiling:
            print(f"  -> SKIPPED (over {args.size_ceiling_mb} MB ceiling)")
            skipped.append({"repository": name, "path": str(repo),
                            "size_bytes": size,
                            "reason": f"exceeds {args.size_ceiling_mb} MB ceiling"})
            continue

        repo_out = out / name
        repo_out.mkdir(parents=True, exist_ok=True)

        module_errors: list[dict] = []
        for mod in modules:
            extra: list[str] = []
            if mod == "taint_scan.py":
                extra = ["--langs", args.langs]
            if mod == "git_history_scan.py":
                extra = ["--no-gitleaks"] if not shutil_which("gitleaks") else []
            rc, err = run_module(mod, repo, repo_out, extra)
            if rc != 0:
                module_errors.append({"module": mod, "returncode": rc, "error": err[:400]})
                print(f"  -> {mod}: exit {rc} {err[:120]}")

        counts = collect_findings(repo_out)
        total = sum(counts.values())
        print(f"  -> {total} finding(s) "
              f"(H:{counts.get('HIGH', 0)} M:{counts.get('MEDIUM', 0)} "
              f"L:{counts.get('LOW', 0)})")

        entry = {
            "repository": name,
            "path": str(repo),
            "size_bytes": size,
            "findings_total": total,
            "severity_counts": counts,
            "modules_run": modules,
            "module_errors": module_errors,
        }
        if module_errors:
            failed.append(entry)
        scanned.append(entry)

    # ---- summary ----
    severity_totals = {sev: 0 for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW",
                                          "INFORMATIONAL")}
    for entry in scanned:
        for sev, n in entry["severity_counts"].items():
            severity_totals[sev] = severity_totals.get(sev, 0) + n

    worst = sorted(scanned, key=lambda e: (
        -e["severity_counts"].get("CRITICAL", 0),
        -e["severity_counts"].get("HIGH", 0),
        -e["findings_total"],
    ))

    summary = {
        "schema_version": "1.0.0",
        "generated_at": now_iso(),
        "root": str(root),
        "mode": args.mode,
        "size_ceiling_mb": args.size_ceiling_mb,
        "modules": modules,
        "repositories_found": len(repos),
        "repositories_scanned": len(scanned),
        "repositories_skipped": len(skipped),
        "repositories_with_errors": len(failed),
        "severity_totals": severity_totals,
        "findings_total": sum(severity_totals.values()),
        "scanned": scanned,
        "skipped": skipped,
        "errors": failed,
        "priority_order": [
            {"repository": e["repository"], "critical": e["severity_counts"].get("CRITICAL", 0),
             "high": e["severity_counts"].get("HIGH", 0),
             "total": e["findings_total"]}
            for e in worst
        ],
        "limitations": [
            "Skipped repositories were NOT scanned; their exposure is unknown.",
            "A finding means exposure, never that a credential is valid or active.",
            "Automated scanning does not replace a professional security audit.",
        ],
    }
    write_json(out / "batch-summary.json", summary)

    # human-readable summary
    lines = [
        f"Batch scan summary — {root}",
        f"Generated: {summary['generated_at']}",
        f"Mode: {args.mode} | Size ceiling: {args.size_ceiling_mb} MB",
        "",
        f"Repositories found:    {summary['repositories_found']}",
        f"Scanned:               {summary['repositories_scanned']}",
        f"Skipped (size):        {summary['repositories_skipped']}",
        f"With module errors:    {summary['repositories_with_errors']}",
        "",
        "Severity totals:",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        lines.append(f"  {sev:<14} {severity_totals.get(sev, 0)}")
    lines.append(f"  {'TOTAL':<14} {summary['findings_total']}")

    if worst:
        lines += ["", "Priority order (most urgent first):"]
        for e in worst[:10]:
            lines.append(
                f"  {e['repository']}: "
                f"{e['severity_counts'].get('CRITICAL', 0)}C / "
                f"{e['severity_counts'].get('HIGH', 0)}H / "
                f"{e['severity_counts'].get('MEDIUM', 0)}M / "
                f"{e['findings_total']} total"
            )

    if skipped:
        lines += ["", "Skipped (not scanned):"]
        for s in skipped:
            lines.append(f"  {s['repository']} ({s['size_bytes'] / (1024 * 1024):.1f} MB) — {s['reason']}")

    (out / "batch-summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print()
    print("\n".join(lines))
    return 0


def shutil_which(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None


if __name__ == "__main__":
    raise SystemExit(main())
