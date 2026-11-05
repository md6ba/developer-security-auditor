#!/usr/bin/env python3
"""Validate the rule catalog.

Checks structure, schema version, duplicate IDs, required fields, and that every
regex pattern compiles. Exits non-zero on any error so a bad catalog cannot be
used silently.

Usage:
  python3 rule_validate.py [--catalog rules/catalog.json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import CATALOG_PATH, SCHEMA_VERSION  # noqa: E402

REQUIRED_FIELDS = ["id", "title", "category", "severity", "confidence", "cwe", "owasp", "remediation"]
VALID_SEVERITY = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
VALID_CONFIDENCE = {"CONFIRMED", "PROBABLE", "POTENTIAL"}
VALID_CATEGORY = {
    "secret_exposure", "configuration", "code", "git_workflow", "web3",
    "dependency", "crypto", "architecture",
}


def validate(catalog: dict) -> list[str]:
    errors: list[str] = []
    warnings: list[str] = []

    if catalog.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {SCHEMA_VERSION!r}, got {catalog.get('schema_version')!r}"
        )

    rules = catalog.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append("rules must be a non-empty list")
        return errors

    seen_ids: set[str] = set()
    for i, rule in enumerate(rules, start=1):
        where = f"rule #{i}"
        if not isinstance(rule, dict):
            errors.append(f"{where}: not an object")
            continue
        rid = rule.get("id", f"<missing-{i}>")
        where = f"rule {rid}"

        for field in REQUIRED_FIELDS:
            if not rule.get(field):
                errors.append(f"{where}: missing required field {field!r}")

        if rid in seen_ids:
            errors.append(f"{where}: duplicate id")
        seen_ids.add(rid)

        if rule.get("severity") and rule["severity"] not in VALID_SEVERITY:
            errors.append(f"{where}: invalid severity {rule['severity']!r}")
        if rule.get("confidence") and rule["confidence"] not in VALID_CONFIDENCE:
            errors.append(f"{where}: invalid confidence {rule['confidence']!r}")
        if rule.get("category") and rule["category"] not in VALID_CATEGORY:
            errors.append(f"{where}: invalid category {rule['category']!r}")

        pattern = rule.get("pattern")
        if pattern is not None:
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f"{where}: pattern does not compile: {exc}")

        exclude = rule.get("exclude")
        if exclude:
            try:
                re.compile(exclude)
            except re.error as exc:
                errors.append(f"{where}: exclude pattern does not compile: {exc}")

        if not pattern and not rule.get("paths") and not rule.get("note"):
            warnings.append(f"{where}: no pattern and no paths — rule may never fire")

    return errors, warnings  # type: ignore[return-value]


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate the rule catalog")
    ap.add_argument("--catalog", type=Path, default=CATALOG_PATH)
    args = ap.parse_args()

    if not args.catalog.exists():
        print(f"ERROR: catalog not found: {args.catalog}", file=sys.stderr)
        return 2

    try:
        catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ERROR: catalog is not valid JSON: {exc}", file=sys.stderr)
        return 2

    errors, warnings = validate(catalog)

    for w in warnings:
        print(f"WARNING: {w}")
    for e in errors:
        print(f"ERROR: {e}")

    print()
    print(f"rules: {len(catalog.get('rules', []))}")
    print(f"errors: {len(errors)}  warnings: {len(warnings)}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
