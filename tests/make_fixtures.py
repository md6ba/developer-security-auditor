#!/usr/bin/env python3
"""Build synthetic vulnerable repositories for the test suite.

Everything created here is synthetic: fake secrets, intentionally weak code,
and deliberately insecure configuration. Nothing in this directory is real,
sensitive, or authorised for anything beyond local testing.

Usage:
  python3 make_fixtures.py [--root ./fixtures]
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

# Synthetic credentials. These are fake by construction and are never valid.
DUMMY_OPENWEATHER_KEY = "synthetic-openweather-key-000000"
DUMMY_TELEGRAM_TOKEN = "123456789:AAEhBOweik6ad9r_QXMENQjcrGbqCr4K-4c8"
DUMMY_AWS_KEY = "AKIAZQ7XW3VBNM2PQRST"
DUMMY_STRIPE_KEY = "synthetic_stripe_key_0000000000000000"
DUMMY_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnyAlYv6MqB0LwCNQ8 pl aceh older
-----END RSA PRIVATE KEY-----"""

SQLI_APP = '''"""Synthetic vulnerable app — used only for testing."""
import sqlite3


def get_user(request):
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    # VULNERABLE: string concatenation into SQL
    return conn.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall()


def run_command(request):
    cmd = request.args.get("cmd")
    # VULNERABLE: shell interpolation
    import subprocess
    return subprocess.call(f"echo {cmd}", shell=True)
'''

INSECURE_SETTINGS = '''"""Synthetic insecure settings."""
DEBUG = True
SECRET_KEY = "hardcoded-jwt-secret-change-me"
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "app",
        "USER": "root",
        "PASSWORD": "synthetic-db-password",
        "HOST": "db.internal.example",
        "PORT": "5432",
    }
}
EMAIL_HOST_PASSWORD = "synthetic-email-app-password"
'''

HONEYPAGE = '''<!DOCTYPE html>
<html>
<body>
<script>
    const apiKey = "''' + DUMMY_OPENWEATHER_KEY + '''";
    const apiUrl = "https://api.openweathermap.org/data/2.5/weather?units=metric&q=";
    function render(userInput) {
        // VULNERABLE: DOM XSS
        document.getElementById("out").innerHTML = userInput;
    }
</script>
</body>
</html>
'''

SOLIDITY_VULN = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SyntheticVault {
    address public owner;
    uint256 public totalSupply;

    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
        _mint(owner, totalSupply);
    }

    function setFeeRecipient(address _feeRecipient) external onlyOwner {
        feeRecipient = _feeRecipient;
    }

    function _transfer(address sender, address recipient, uint256 amount) internal override {
        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
'''

DOCKER_COMPOSE = '''services:
  web:
    build: .
    user: root
    privileged: true
    environment:
      - DATABASE_URL=postgres://root:synthetic-db-password@db:5432/app
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
'''


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def git_init(repo: Path) -> None:
    subprocess.run(["git", "init", "-q", str(repo)], check=False)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "fixture@example.invalid"], check=False)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Fixture"], check=False)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=False)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "initial"], check=False)


def build_python_repo(root: Path) -> Path:
    repo = root / "python-vulnerable"
    if repo.exists():
        shutil.rmtree(repo)
    write(repo / "app.py", SQLI_APP)
    write(repo / "settings.py", INSECURE_SETTINGS)
    write(repo / ".env", "SECRET_KEY=synthetic-env-secret\nAPI_KEY=synthetic-api-key-123456\n")
    write(repo / "Dockerfile", "FROM python:3.12\nUSER root\nWORKDIR /app\nCOPY . .\n")
    write(repo / "requirements.txt", "flask==3.0.0\nrequests==2.31.0\n")
    git_init(repo)
    return repo


def build_web_repo(root: Path) -> Path:
    repo = root / "web-vulnerable"
    if repo.exists():
        shutil.rmtree(repo)
    write(repo / "index.html", HONEYPAGE)
    write(repo / "package.json", '{"name":"synthetic","version":"1.0.0","dependencies":{"express":"4.18.2"}}')
    write(repo / ".gitignore", "node_modules/\n")
    git_init(repo)
    return repo


def build_solidity_repo(root: Path) -> Path:
    repo = root / "solidity-vulnerable"
    if repo.exists():
        shutil.rmtree(repo)
    write(repo / "SyntheticVault.sol", SOLIDITY_VULN)
    write(repo / "hardhat.config.js", "module.exports = { solidity: '0.8.0' };\n")
    write(repo / ".gitignore", "node_modules/\n")
    git_init(repo)
    return repo


def build_history_repo(root: Path) -> Path:
    """A repo whose secret was deleted but remains in history."""
    repo = root / "history-leak"
    if repo.exists():
        shutil.rmtree(repo)
    write(repo / ".env", f"BOT_TOKEN={DUMMY_TELEGRAM_TOKEN}\nAPI_KEY={DUMMY_AWS_KEY}\nSTRIPE_KEY={DUMMY_STRIPE_KEY}\n")
    git_init(repo)
    (repo / ".env").unlink()
    write(repo / ".gitignore", ".env\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=False)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "remove .env"], check=False)
    return repo


def build_compose_repo(root: Path) -> Path:
    repo = root / "compose-insecure"
    if repo.exists():
        shutil.rmtree(repo)
    write(repo / "docker-compose.yml", DOCKER_COMPOSE)
    write(repo / "app.py", "print('synthetic')\n")
    git_init(repo)
    return repo


def main() -> int:
    ap = argparse.ArgumentParser(description="Build synthetic vulnerable fixtures")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent / "fixtures")
    args = ap.parse_args()

    root: Path = args.root.resolve()
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    repos = [
        build_python_repo(root),
        build_web_repo(root),
        build_solidity_repo(root),
        build_history_repo(root),
        build_compose_repo(root),
    ]

    print(f"Fixtures created under {root}")
    for r in repos:
        print(f"  {r.name}")
    print()
    print("All credentials in these fixtures are synthetic and invalid by construction.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
