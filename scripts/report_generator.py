#!/usr/bin/env python3
"""Report generator — Module for output formats.

Reads findings JSON files and produces the four required deliverables:
  SECURITY_AUDIT_REPORT.md   (technical, reproducible)
  SECURITY_FINDINGS.json     (structured, no secret values)
  REMEDIATION_PLAN.md        (prioritised actions)
  EXECUTIVE_SUMMARY.md       (non-technical)

Bilingual: --lang fa (default) or en.

Usage:
  python3 report_generator.py --findings ./out --out ./report --repo /path --lang fa
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import SEVERITY_ORDER, now_iso, write_json  # noqa: E402

I18N = {
    "fa": {
        "title": "گزارش ممیزی امنیتی",
        "generated": "تاریخ تهیه",
        "repo": "مخزن",
        "mode": "حالت ممیزی",
        "summary": "خلاصه",
        "findings": "یافته‌ها",
        "severity": "شدت",
        "confidence": "اطمینان",
        "status": "وضعیت",
        "file": "فایل",
        "line": "خط",
        "commit": "کامیت",
        "explanation": "توضیح",
        "impact": "اثر امنیتی",
        "evidence": "شواهد",
        "remediation": "راه‌حل اصلاح",
        "cwe": "CWE",
        "owasp": "OWASP",
        "no_findings": "هیچ یافته‌ای گزارش نشده است.",
        "critical": "بحرانی",
        "high": "بالا",
        "medium": "متوسط",
        "low": "پایین",
        "informational": "اطلاعاتی",
        "remediation_plan": "برنامه‌ی اصلاح",
        "priority": "اولویت",
        "action": "اقدام",
        "owner": "مسئول",
        "effort": "ترتیب",
        "executive_summary": "خلاصه‌ی اجرایی",
        "what_we_found": "چه چیزی پیدا شد",
        "what_it_means": "معنای آن برای کسب‌وکار",
        "what_to_do": "اقدام بعدی",
        "disclaimer": (
            "این ممیزی خودکار جایگزین ممیزی امنیتی حرفه‌ای نیست. هیچ رمزی تست یا "
            "استفاده نشده است و هیچ مقدار محرمانه‌ای در این گزارش ثبت نشده است."
        ),
        "historical": "فقط تاریخیه",
        "present": "موجود در HEAD",
        "occurrences": "تکرار",
    },
    "en": {
        "title": "Security Audit Report",
        "generated": "Generated",
        "repo": "Repository",
        "mode": "Audit mode",
        "summary": "Summary",
        "findings": "Findings",
        "severity": "Severity",
        "confidence": "Confidence",
        "status": "Status",
        "file": "File",
        "line": "Line",
        "commit": "Commit",
        "explanation": "Explanation",
        "impact": "Security impact",
        "evidence": "Evidence",
        "remediation": "Remediation",
        "cwe": "CWE",
        "owasp": "OWASP",
        "no_findings": "No findings recorded.",
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "informational": "INFORMATIONAL",
        "remediation_plan": "Remediation Plan",
        "priority": "Priority",
        "action": "Action",
        "owner": "Owner",
        "effort": "Order",
        "executive_summary": "Executive Summary",
        "what_we_found": "What we found",
        "what_it_means": "What it means",
        "what_to_do": "What to do next",
        "disclaimer": (
            "Automated scanning does not replace a professional security audit. No credential "
            "was tested or used, and no secret value appears in this report."
        ),
        "historical": "historical only",
        "present": "present in HEAD",
        "occurrences": "Occurrences",
    },
}


def load_findings(findings_dir: Path) -> list[dict]:
    """Merge every findings JSON in the directory."""
    merged: dict[str, dict] = {}
    for path in sorted(findings_dir.glob("*findings*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and isinstance(data.get("findings"), list):
            for f in data["findings"]:
                fid = f.get("finding_id") or f"{f.get('rule_id')}-{f.get('file_path')}-{f.get('line_start')}"
                if fid in merged:
                    merged[fid]["occurrences"] = merged[fid].get("occurrences", 1) + 1
                else:
                    merged[fid] = f
    return sorted(
        merged.values(),
        key=lambda x: (
            SEVERITY_ORDER.index(x.get("severity", "INFORMATIONAL"))
            if x.get("severity", "INFORMATIONAL") in SEVERITY_ORDER
            else 99,
            x.get("rule_id", ""),
            x.get("file_path", ""),
        ),
    )


def counts(findings: list[dict]) -> dict:
    return {s: sum(1 for f in findings if f.get("severity") == s) for s in SEVERITY_ORDER}


def write_technical(path: Path, findings: list[dict], repo: str, mode: str, lang: str) -> None:
    t = I18N[lang]
    lines = [
        f"# {t['title']}",
        "",
        f"**{t['generated']}:** {now_iso()}  ",
        f"**{t['repo']}:** {repo}  ",
        f"**{t['mode']}:** {mode}",
        "",
        "---",
        "",
        f"## {t['summary']}",
        "",
        "| " + t["severity"] + " | " + t["findings"] + " |",
        "|---|---|",
    ]
    c = counts(findings)
    for sev in SEVERITY_ORDER:
        lines.append(f"| {t[sev.lower()]} | {c[sev]} |")
    lines += ["", f"**{t['findings']}:** {len(findings)}", "", "---", "", f"## {t['findings']}", ""]

    if not findings:
        lines.append(t["no_findings"])
    for f in findings:
        lines += [
            f"### {f.get('finding_id', '')} — {f.get('title', '')}",
            "",
            f"- **{t['severity']}:** {t.get(f.get('severity','').lower(), f.get('severity',''))}  ",
            f"- **{t['confidence']}:** {f.get('confidence','')}  ",
            f"- **{t['status']}:** {f.get('status','')}  ",
            f"- **{t['file']}:** `{f.get('file_path','')}`  ",
            f"- **{t['line']}:** {f.get('line_start','')}" + (f"–{f.get('line_end')}" if f.get('line_end') else "") + "  ",
        ]
        if f.get("commit"):
            lines.append(f"- **{t['commit']}:** `{f['commit']}`  ")
        lines += [
            f"- **{t['explanation']}:** {f.get('explanation','')}  ",
            f"- **{t['impact']}:** {f.get('impact','')}  ",
            f"- **{t['evidence']}:** {f.get('evidence','')}  ",
            f"- **{t['remediation']}:** {f.get('remediation','')}  ",
        ]
        if f.get("cwe"):
            lines.append(f"- **{t['cwe']}:** {f['cwe']}  ")
        if f.get("owasp"):
            lines.append(f"- **{t['owasp']}:** {f['owasp']}  ")
        lines.append("")

    lines += ["---", "", t["disclaimer"], ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_remediation(path: Path, findings: list[dict], lang: str) -> None:
    t = I18N[lang]
    order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFORMATIONAL": 5}
    lines = [
        f"# {t['remediation_plan']}",
        "",
        f"**{t['generated']}:** {now_iso()}",
        "",
        "| " + " | ".join([t["priority"], t["severity"], t["title"], t["action"], t["owner"]]) + " |",
        "|---|---|---|---|---|",
    ]
    for i, f in enumerate(sorted(findings, key=lambda x: order.get(x.get("severity"), 9)), start=1):
        title = f.get("title", "")
        action = f.get("remediation", "")
        lines.append(
            f"| P{i} | {t.get(f.get('severity','').lower(), f.get('severity',''))} | {title} | {action} | {f.get('component','')} |"
        )
    lines += ["", t["disclaimer"], ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_executive(path: Path, findings: list[dict], repo: str, lang: str) -> None:
    t = I18N[lang]
    c = counts(findings)
    critical_high = c["CRITICAL"] + c["HIGH"]
    lines = [
        f"# {t['executive_summary']}",
        "",
        f"**{t['repo']}:** {repo}  ",
        f"**{t['generated']}:** {now_iso()}",
        "",
        f"## {t['what_we_found']}",
        "",
        f"- {t['critical']}: {c['CRITICAL']}",
        f"- {t['high']}: {c['HIGH']}",
        f"- {t['medium']}: {c['MEDIUM']}",
        f"- {t['low']}: {c['LOW']}",
        f"- {t['informational']}: {c['INFORMATIONAL']}",
        "",
        f"## {t['what_it_means']}",
        "",
    ]
    if critical_high == 0:
        lines.append(
            "No critical or high severity issue was found by automated scanning. "
            "This does not mean the project is free of security risk."
            if lang == "en"
            else "ممیزی خودکار هیچ مشکل بحرانی یا با شدت بالا پیدا نکرد. این به معنای نبود ریسک امنیتی نیست."
        )
    else:
        lines.append(
            f"{critical_high} issue(s) require attention before release."
            if lang == "en"
            else f"{critical_high} مورد نیاز به توجه قبل از انتشار دارند."
        )
    lines += [
        "",
        f"## {t['what_to_do']}",
        "",
        "1. " + ("Rotate any credential reported as exposed." if lang == "en" else "هر رمزی که به‌عنوان درمعرض دید گزارش شده، چرخش داده شود."),
        "2. " + ("Remove secrets from git history or treat them as public." if lang == "en" else "رمزها از تاریخچه‌ی گیت حذف شوند یا به‌عنوان عمومی در نظر گرفته شوند."),
        "3. " + ("Fix configuration issues before the next release." if lang == "en" else "مشکلات پیکربندی قبل از انتشار بعدی رفع شوند."),
        "",
        t["disclaimer"],
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate the four audit deliverables")
    ap.add_argument("--findings", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--repo", default="")
    ap.add_argument("--mode", default="standard")
    ap.add_argument("--lang", default="fa", choices=["fa", "en"])
    args = ap.parse_args()

    findings_dir: Path = args.findings.resolve()
    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    findings = load_findings(findings_dir)
    write_json(out / "SECURITY_FINDINGS.json", {
        "schema_version": "1.0.0",
        "generated_at": now_iso(),
        "language": args.lang,
        "repository": args.repo,
        "mode": args.mode,
        "finding_count": len(findings),
        "severity_counts": counts(findings),
        "findings": findings,
        "secret_values_included": False,
    })
    write_technical(out / "SECURITY_AUDIT_REPORT.md", findings, args.repo, args.mode, args.lang)
    write_remediation(out / "REMEDIATION_PLAN.md", findings, args.lang)
    write_executive(out / "EXECUTIVE_SUMMARY.md", findings, args.repo, args.lang)

    print(f"Reports written to {out}")
    print(f"  findings: {len(findings)}  ({counts(findings)})")
    print(f"  language: {args.lang}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
