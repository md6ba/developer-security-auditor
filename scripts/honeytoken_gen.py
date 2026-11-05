#!/usr/bin/env python3
"""Module I — Defensive deception artifacts (honeytokens, fake routes).

Generates clearly-labelled deception artifacts for a web project the user owns
or is authorised to test: honeytokens, fake API routes, signed capture tokens,
and a local investigation view template.

The skill generates artifacts only. It never deploys anything and never creates
real credentials. Every generated token is deterministically fake and labelled.

Usage:
  python3 honeytoken_gen.py --project /path/to/web-project --out ./deception
                           [--count 8] [--lang python|nodejs|nginx]
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import now_iso, write_json  # noqa: E402

FAKE_PREFIX = "HONEY"
LABEL = "HONEYTOKEN — SYNTHETIC — NOT A REAL CREDENTIAL"


def make_token(index: int, kind: str, secret_key: bytes) -> dict:
    """Create a synthetic token that is clearly fake and HMAC-signed."""
    random_part = secrets.token_hex(12)
    body = f"{FAKE_PREFIX}:{kind}:{index}:{random_part}".encode()
    signature = hmac.new(secret_key, body, hashlib.sha256).hexdigest()[:24]
    value = f"{FAKE_PREFIX.lower()}_{kind.lower()}_{random_part}.{signature}"
    return {
        "index": index,
        "kind": kind,
        "value": value,
        "label": LABEL,
        "signature": signature,
        "note": "Synthetic value. If it appears outside this project, an intrusion is likely.",
    }


def generate(count: int) -> tuple[list[dict], str]:
    secret_key = secrets.token_bytes(32)
    kinds = ["apikey", "bearer", "webhook", "dbpassword", "session", "rpctoken"]
    tokens = [make_token(i, kinds[i % len(kinds)], secret_key) for i in range(1, count + 1)]
    verification_key = hashlib.sha256(secret_key).hexdigest()[:16]
    return tokens, verification_key


def fake_routes(language: str) -> str:
    if language == "python":
        return '''"""Synthetic decoy routes. Deploy only in an authorised environment.

Every route logs the request and returns a realistic-looking but worthless response.
"""
from flask import Blueprint, request, jsonify

decoy = Blueprint("decoy", __name__)
TRIGGER_LOG = "decoy-triggers.log"


def _log(trigger: str) -> None:
    with open(TRIGGER_LOG, "a", encoding="utf-8") as fh:
        fh.write(f"{request.remote_addr}\\t{trigger}\\t{request.path}\\n")


@decoy.route("/api/v1/admin/backup", methods=["GET"])
def admin_backup():
    _log("admin-backup-route")
    return jsonify({"status": "ok", "backup_id": "dummy"}), 200


@decoy.route("/.env.bak", methods=["GET"])
def env_backup():
    _log("env-backup-route")
    return "HONEYTOKEN=synthetic\\n", 200
'''
    if language == "nginx":
        return '''# Synthetic decoy routes. Deploy only in an authorised environment.
# Each location logs the hit and returns a realistic-looking response.

location = /api/v1/admin/backup {
    access_log /var/log/nginx/decoy.log;
    return 200 '{"status":"ok","backup_id":"dummy"}';
    add_header Content-Type application/json;
}

location = /.env.bak {
    access_log /var/log/nginx/decoy.log;
    return 200 'HONEYTOKEN=synthetic\\n';
}
'''
    return '''// Synthetic decoy routes. Deploy only in an authorised environment.
const express = require('express');
const fs = require('fs');
const router = express.Router();
const TRIGGER_LOG = 'decoy-triggers.log';

function log(trigger) {
  fs.appendFileSync(TRIGGER_LOG, `${request.ip}\\t${trigger}\\t${request.path}\\n`);
}

router.get('/api/v1/admin/backup', (req, res) => {
  log('admin-backup-route');
  res.json({ status: 'ok', backup_id: 'dummy' });
});

router.get('/.env.bak', (req, res) => {
  log('env-backup-route');
  res.type('text/plain').send('HONEYTOKEN=synthetic\\n');
});

module.exports = router;
'''


def investigation_view(tokens: list[dict], verification_key: str) -> str:
    lines = [
        "# Local Investigation View — decoy triggers",
        "",
        f"Generated: {now_iso()}",
        f"Verification key (for signature checking): `{verification_key}`",
        "",
        "This file is a template. It lists every synthetic token and the routes that",
        "log their use. It is never deployed and contains no real credentials.",
        "",
        "## Synthetic tokens",
        "",
        "| # | Kind | Value | Signature |",
        "|---|------|-------|-----------|",
    ]
    for t in tokens:
        lines.append(f"| {t['index']} | {t['kind']} | `{t['value']}` | `{t['signature']}` |")
    lines += [
        "",
        "## How to use",
        "",
        "1. Deploy the generated decoy routes in an authorised environment.",
        "2. Place selected synthetic tokens in plausible locations (a config file, a log,",
        "   a wiki page) — never in a real secret store.",
        "3. Monitor the trigger log. Any hit means someone touched a location they should",
        "   not have reached.",
        "4. Verify a token's authenticity with its signature before acting on an alert.",
        "",
        "## Boundaries",
        "",
        "- These tokens are synthetic and worthless. They are not credentials.",
        "- Deploy only where you have authorisation to run deception tooling.",
        "- Some jurisdictions restrict honeytokens; confirm before use.",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Module I — defensive deception artifacts")
    ap.add_argument("--project", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--count", type=int, default=8)
    ap.add_argument("--lang", default="python", choices=["python", "nodejs", "nginx"])
    args = ap.parse_args()

    project: Path = args.project.resolve()
    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if not project.exists():
        print(f"ERROR: project not found: {project}", file=sys.stderr)
        return 2

    tokens, verification_key = generate(args.count)

    write_json(out / "honeytokens.json", {
        "label": LABEL,
        "generated_at": now_iso(),
        "verification_key": verification_key,
        "count": len(tokens),
        "tokens": tokens,
        "note": "Synthetic values only. Never deploy real credentials as honeytokens.",
    })

    routes = out / f"decoy-routes.{ 'py' if args.lang == 'python' else 'js' if args.lang == 'nodejs' else 'conf' }"
    routes.write_text(fake_routes(args.lang), encoding="utf-8")

    (out / "INVESTIGATION_VIEW.md").write_text(
        investigation_view(tokens, verification_key), encoding="utf-8"
    )

    print(f"Generated {len(tokens)} synthetic honeytoken(s)")
    print(f"  tokens:     {out / 'honeytokens.json'}")
    print(f"  decoy routes: {routes}")
    print(f"  investigation view: {out / 'INVESTIGATION_VIEW.md'}")
    print()
    print("These are synthetic and worthless. Deploy only where authorised.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
