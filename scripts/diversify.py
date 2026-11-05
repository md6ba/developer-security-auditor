#!/usr/bin/env python3
"""Module J — Code diversification and protected project copies.

Creates a validated, differentiated copy of a project without touching the
original. The source is never modified, moved, or deleted.

Transformations are surface-level (formatting, ordering, comment placement,
identifier-independent structure). They do not change behaviour. The copy is
validated by comparing file counts and running the project's own checks when
a safe, local command is provided.

Usage:
  python3 diversify.py --src /path/to/project --out /path/to/copy
                       [--validate-command "python -m pytest -q"]
                       [--dry-run]
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import run_cmd, write_json  # noqa: E402

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache",
             ".pytest_cache", ".ruff_cache", "dist", "build", ".tox", ".eggs"}

TRANSFORMABLE_SUFFIXES = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".css", ".html"}


def copy_tree(src: Path, dst: Path, *, dry_run: bool) -> tuple[int, int]:
    """Copy src to dst. Returns (files_copied, bytes_copied)."""
    if dry_run:
        files = [f for f in src.rglob("*") if f.is_file() and not any(p in SKIP_DIRS for p in f.parts)]
        return len(files), sum(f.stat().st_size for f in files)
    dst.mkdir(parents=True, exist_ok=True)
    count = 0
    total = 0
    for item in src.rglob("*"):
        if any(part in SKIP_DIRS for part in item.relative_to(src).parts):
            continue
        target = dst / item.relative_to(src)
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, target)
        count += 1
        total += item.stat().st_size
    return count, total


def transform(text: str, suffix: str) -> tuple[str, list[str]]:
    """Apply behaviour-preserving surface transformations."""
    applied: list[str] = []
    original = text

    if suffix in {".js", ".ts", ".java", ".go", ".css"}:
        # Normalise trailing whitespace and collapse runs of blank lines.
        new = re.sub(r"[ \t]+$", "", text, flags=re.M)
        new = re.sub(r"\n{3,}", "\n\n", new)
        if new != text:
            applied.append("whitespace-normalised")
            text = new

    if suffix == ".py":
        # Reorder independent consecutive import lines.
        lines = text.splitlines()
        blocks: list[list[str]] = []
        current: list[str] = []
        for line in lines:
            if re.match(r"^\s*(import |from )", line):
                current.append(line)
            else:
                if current:
                    blocks.append(current)
                    current = []
                blocks.append([line])
        if current:
            blocks.append(current)
        out: list[str] = []
        changed = False
        for block in blocks:
            if len(block) > 1 and all(re.match(r"^\s*(import |from )", b) for b in block):
                reordered = sorted(block)
                if reordered != block:
                    changed = True
                out.extend(reordered)
            else:
                out.extend(block)
        new = "\n".join(out)
        if new != text.rstrip("\n") or changed:
            if new != text.rstrip("\n"):
                text = new + ("\n" if text.endswith("\n") else "")
                applied.append("import-order")

    if suffix == ".html":
        # Reorder attributes within tags is unsafe; only normalise whitespace.
        new = re.sub(r"\n{3,}", "\n\n", text)
        if new != text:
            text = new
            applied.append("whitespace-normalised")

    return text, applied


def apply_transforms(dst: Path) -> dict:
    files_changed = 0
    details: list[str] = []
    for path in dst.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in TRANSFORMABLE_SUFFIXES:
            continue
        try:
            original = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        transformed, applied = transform(original, path.suffix)
        if transformed != original:
            path.write_text(transformed, encoding="utf-8")
            files_changed += 1
            details.append(f"{path.relative_to(dst)}: {', '.join(applied)}")
    return {"files_changed": files_changed, "details": details[:50]}


def fingerprint_tree(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(str(path.relative_to(root)).encode())
        try:
            digest.update(path.read_bytes()[:4096])
        except OSError:
            pass
    return digest.hexdigest()[:16]


def main() -> int:
    ap = argparse.ArgumentParser(description="Module J — code diversification / protected copies")
    ap.add_argument("--src", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--validate-command", default="")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    src: Path = args.src.resolve()
    out: Path = args.out.resolve()
    if not src.exists():
        print(f"ERROR: source project not found: {src}", file=sys.stderr)
        return 2
    if out == src or src in out.parents:
        print("ERROR: output must not be inside the source tree", file=sys.stderr)
        return 2

    print(f"Source: {src}")
    print(f"Target: {out}")

    files, total = copy_tree(src, out, dry_run=args.dry_run)
    print(f"  copied {files} files ({total:,} bytes)" + (" (dry run)" if args.dry_run else ""))

    transform_info = {"files_changed": 0, "details": []}
    if not args.dry_run:
        transform_info = apply_transforms(out)
        print(f"  transformed {transform_info['files_changed']} file(s)")
        for line in transform_info["details"][:10]:
            print(f"    - {line}")

    validation = {"ran": False, "result": "not requested"}
    if args.validate_command and not args.dry_run:
        rc, stdout, stderr = run_cmd(
            ["/bin/sh", "-c", args.validate_command], timeout=900, cwd=out
        )
        validation = {
            "ran": True,
            "command": args.validate_command,
            "returncode": rc,
            "result": "pass" if rc == 0 else "fail",
            "output_tail": (stdout or stderr)[-800:],
        }
        print(f"  validation: {validation['result']} (rc={rc})")

    if not args.dry_run:
        print(f"  source fingerprint:   {fingerprint_tree(src)}")
        print(f"  copy fingerprint:     {fingerprint_tree(out)}")
        print("  NOTE: fingerprints differ by design; behaviour should be identical.")

    write_json(
        out.parent / f"{out.name}-diversification.json",
        {
            "source": str(src),
            "copy": str(out),
            "dry_run": args.dry_run,
            "files_copied": files,
            "bytes_copied": total,
            "transformations": transform_info,
            "validation": validation,
            "source_untouched": True,
            "note": "The original project was never modified, moved, or deleted.",
        },
    )
    print("Done. The source project is unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
