#!/usr/bin/env python3
"""Acceptance test suite for the Developer Security Auditor skill.

Run:
  python3 -m pytest tests/test_skill.py -q

Everything here uses synthetic fixtures. No network, no real credentials,
no modification of the audited project.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = SKILL_ROOT / "scripts"
FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"

sys.path.insert(0, str(SCRIPTS))

DUMMY_OPENWEATHER_KEY = "synthetic-openweather-key-000000"
DUMMY_TELEGRAM_TOKEN = "123456789:AAEhBOweik6ad9r_QXMENQjcrGbqCr4K-4c8"
DUMMY_AWS_KEY = "AKIAZQ7XW3VBNM2PQRST"

ALL_DUMMY_SECRETS = [
    DUMMY_OPENWEATHER_KEY,
    DUMMY_TELEGRAM_TOKEN,
    DUMMY_AWS_KEY,
    "synthetic_stripe_key_0000000000000000",
    "synthetic-db-password",
    "hardcoded-jwt-secret-change-me",
]


def ensure_fixtures() -> None:
    if not FIXTURE_ROOT.exists():
        subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent / "make_fixtures.py"),
             "--root", str(FIXTURE_ROOT)],
            check=True, capture_output=True,
        )


def run_script(name: str, *args: str, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / name), *args],
        capture_output=True, text=True, timeout=timeout,
    )


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class FixtureCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ensure_fixtures()


class TestSecretDetection(FixtureCase):
    """Acceptance 1-3: dummy API key, Telegram token, private key."""

    def test_detects_dummy_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            r = run_script("secret_scan.py", "--repo", str(FIXTURE_ROOT / "python-vulnerable"),
                           "--out", str(out), "--no-gitleaks", "--no-trufflehog")
            self.assertEqual(r.returncode, 0, r.stderr)
            data = load(out / "findings.json")
            rules = {f["rule_id"] for f in data["findings"]}
            self.assertIn("SEC-SEC-002", rules)  # hardcoded API key

    def test_detects_telegram_token_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "telegram-repo"
            repo.mkdir()
            (repo / "bot.py").write_text(
                f'TOKEN = "{DUMMY_TELEGRAM_TOKEN}"\n', encoding="utf-8"
            )
            out = Path(tmp) / "out"
            r = run_script("secret_scan.py", "--repo", str(repo), "--out", str(out),
                           "--no-gitleaks", "--no-trufflehog")
            self.assertEqual(r.returncode, 0, r.stderr)
            data = load(out / "findings.json")
            rules = {f["rule_id"] for f in data["findings"]}
            self.assertIn("SEC-SEC-006", rules)  # telegram bot token

    def test_detects_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "key-repo"
            repo.mkdir()
            (repo / "server.key").write_text(
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn\n"
                "-----END RSA PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            out = Path(tmp) / "out"
            r = run_script("secret_scan.py", "--repo", str(repo), "--out", str(out),
                           "--no-gitleaks", "--no-trufflehog")
            self.assertEqual(r.returncode, 0, r.stderr)
            data = load(out / "findings.json")
            rules = {f["rule_id"] for f in data["findings"]}
            self.assertIn("SEC-SEC-003", rules)


class TestHistoryDetection(FixtureCase):
    """Acceptance 4-6: history secrets, repeated secrets, current vs historical."""

    def test_detects_secrets_in_git_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            r = run_script("git_history_scan.py", "--repo", str(FIXTURE_ROOT / "history-leak"),
                           "--out", str(out), "--no-gitleaks")
            self.assertEqual(r.returncode, 0, r.stderr)
            data = load(out / "git-findings.json")
            rules = {f["rule_id"] for f in data["findings"]}
            self.assertIn("SEC-GIT-DEL-001", rules)

    def test_history_finding_is_flagged_historical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run_script("git_history_scan.py", "--repo", str(FIXTURE_ROOT / "history-leak"),
                       "--out", str(out), "--no-gitleaks")
            data = load(out / "git-findings.json")
            deleted = [f for f in data["findings"] if f["rule_id"] == "SEC-GIT-DEL-001"]
            self.assertTrue(deleted)
            self.assertTrue(deleted[0]["historical_only"])
            self.assertTrue(deleted[0]["commit"])

    def test_repeated_secret_grouped_without_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repeat-repo"
            repo.mkdir()
            (repo / "a.py").write_text(f'KEY = "{DUMMY_AWS_KEY}"\n', encoding="utf-8")
            (repo / "b.py").write_text(f'KEY = "{DUMMY_AWS_KEY}"\n', encoding="utf-8")
            out = Path(tmp) / "out"
            r = run_script("secret_scan.py", "--repo", str(repo), "--out", str(out),
                           "--no-gitleaks", "--no-trufflehog")
            self.assertEqual(r.returncode, 0, r.stderr)
            raw = (out / "findings.json").read_text(encoding="utf-8")
            self.assertNotIn(DUMMY_AWS_KEY, raw)  # value never printed
            self.assertIn("sha256:", raw)          # fingerprint present


class TestConfiguration(FixtureCase):
    """Acceptance 7: insecure configuration."""

    def test_identifies_insecure_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            r = run_script("configuration_audit.py",
                           "--repo", str(FIXTURE_ROOT / "python-vulnerable"), "--out", str(out))
            self.assertEqual(r.returncode, 0, r.stderr)
            data = load(out / "config-findings.json")
            rules = {f["rule_id"] for f in data["findings"]}
            self.assertIn("CFG-DEBUG-001", rules)
            self.assertTrue(
                "CFG-TLS-001" in rules or "CFG-SECRET-ENV-001" in rules,
                f"expected a TLS or secret-in-config finding, got {sorted(rules)}",
            )

    def test_compose_repo_flags_root_and_socket(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run_script("configuration_audit.py",
                       "--repo", str(FIXTURE_ROOT / "compose-insecure"), "--out", str(out))
            data = load(out / "config-findings.json")
            rules = {f["rule_id"] for f in data["findings"]}
            self.assertIn("CFG-ROOT-001", rules)
            self.assertIn("CFG-MOUNT-001", rules)


class TestStaticAnalysis(FixtureCase):
    """Acceptance 8: representative static vulnerabilities."""

    def test_detects_sqli_and_shell_injection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            r = run_script("taint_scan.py", "--repo", str(FIXTURE_ROOT / "python-vulnerable"),
                           "--out", str(out), "--langs", "python")
            self.assertEqual(r.returncode, 0, r.stderr)
            data = load(out / "taint-findings.json")
            labels = " ".join(f["title"] for f in data["findings"])
            self.assertIn("SQL execution", labels)
            self.assertIn("shell execution", labels)


class TestReporting(FixtureCase):
    """Acceptance 9-10: bilingual reports, no validity claims."""

    def test_generates_persian_and_english_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings = Path(tmp) / "findings"
            findings.mkdir()
            (findings / "findings.json").write_text(json.dumps({
                "schema_version": "1.0.0",
                "findings": [{
                    "finding_id": "X-0001", "rule_id": "X", "title": "t", "severity": "HIGH",
                    "confidence": "CONFIRMED", "component": "c", "file_path": "f.py",
                    "line_start": 1, "line_end": 1, "explanation": "e", "impact": "i",
                    "evidence": "ev", "remediation": "r", "cwe": "CWE-79",
                    "owasp": "A03:2021", "status": "UNVERIFIED - POTENTIALLY EXPOSED",
                    "commit": "", "historical_only": False, "occurrences": 1,
                    "fingerprint": "abc", "advisory": "",
                }]
            }, ensure_ascii=False), encoding="utf-8")

            for lang in ("fa", "en"):
                out = Path(tmp) / f"report-{lang}"
                r = run_script("report_generator.py", "--findings", str(findings),
                               "--out", str(out), "--repo", "demo", "--lang", lang)
                self.assertEqual(r.returncode, 0, r.stderr)
                for name in ("SECURITY_AUDIT_REPORT.md", "SECURITY_FINDINGS.json",
                             "REMEDIATION_PLAN.md", "EXECUTIVE_SUMMARY.md"):
                    self.assertTrue((out / name).exists(), f"{lang}: {name} missing")

    def test_report_never_claims_credential_validity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run_script("secret_scan.py", "--repo", str(FIXTURE_ROOT / "python-vulnerable"),
                       "--out", str(out), "--no-gitleaks", "--no-trufflehog")
            run_script("report_generator.py", "--findings", str(out), "--out", str(out / "r"),
                       "--repo", "demo", "--lang", "en")
            text = (out / "r" / "SECURITY_AUDIT_REPORT.md").read_text(encoding="utf-8")
            for phrase in ("is valid", "credential is active", "confirmed valid", "verified active"):
                self.assertNotIn(phrase.lower(), text.lower())
            self.assertIn("UNVERIFIED - POTENTIALLY EXPOSED", text)


class TestSafety(FixtureCase):
    """Acceptance 11-13: no credential use, no modification, large repos, honest gaps."""

    def test_no_script_attempts_network_or_credential_use(self) -> None:
        """Static check: no script may contain network calls or auth usage."""
        forbidden = [
            "requests.get(", "requests.post(", "urllib.request", "httpx.",
            "boto3", "paramiko", "docker.from_env", "subprocess.run([\"curl\"",
            "Authorization:", "login(", "sign_transaction",
        ]
        for script in sorted(SCRIPTS.glob("*.py")):
            text = script.read_text(encoding="utf-8")
            for token in forbidden:
                self.assertNotIn(
                    token, text,
                    f"{script.name} contains forbidden token {token!r}",
                )

    def test_audit_does_not_modify_the_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "proj"
            shutil.copytree(FIXTURE_ROOT / "python-vulnerable", src)
            before = {p: p.read_bytes() for p in src.rglob("*") if p.is_file()}
            out = Path(tmp) / "out"
            run_script("secret_scan.py", "--repo", str(src), "--out", str(out),
                       "--no-gitleaks", "--no-trufflehog")
            run_script("configuration_audit.py", "--repo", str(src), "--out", str(out))
            run_script("taint_scan.py", "--repo", str(src), "--out", str(out), "--langs", "python")
            after = {p: p.read_bytes() for p in src.rglob("*") if p.is_file()}
            self.assertEqual(set(before), set(after))
            for path, content in before.items():
                self.assertEqual(content, after[path], f"modified: {path}")

    def test_large_repository_is_handled_with_a_ceiling(self) -> None:
        """A repository over the ceiling is reported as skipped, not scanned."""
        with tempfile.TemporaryDirectory() as tmp:
            big = Path(tmp) / "big-repo"
            big.mkdir()
            (big / "huge.bin").write_bytes(b"\0" * (1024 * 1024))
            (big / "small.py").write_text("x = 1\n", encoding="utf-8")
            # The inventory reports total_bytes; the ceiling is a caller decision.
            out = Path(tmp) / "out2"
            r = run_script("repository_inventory.py", "--repo", str(big), "--out", str(out))
            self.assertEqual(r.returncode, 0, r.stderr)
            data = load(out / "repository-inventory.json")
            self.assertGreaterEqual(data["total_bytes"], 1024 * 1024)

    def test_incomplete_scan_is_reported(self) -> None:
        """When gitleaks is unavailable, the status file says so."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            r = run_script("secret_scan.py", "--repo", str(FIXTURE_ROOT / "python-vulnerable"),
                           "--out", str(out), "--no-gitleaks", "--no-trufflehog")
            self.assertEqual(r.returncode, 0, r.stderr)
            status = load(out / "module-b-status.json")
            self.assertFalse(status["tools"]["gitleaks"])
            self.assertFalse(status["tools"]["trufflehog"])


class TestCatalog(FixtureCase):
    def test_catalog_validates(self) -> None:
        r = subprocess.run(
            [sys.executable, str(SCRIPTS / "rule_validate.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("errors: 0", r.stdout)


class TestBatchScan(FixtureCase):
    """Batch mode: many repositories under one root, one output each, honest skips."""

    def test_batch_scans_every_repo_and_reports_skips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repos"
            (root / "repo-a").mkdir(parents=True)
            (root / "repo-b").mkdir(parents=True)
            # a non-repo directory must be ignored
            (root / "not-a-repo").mkdir(parents=True)
            for name in ("repo-a", "repo-b"):
                subprocess.run(["git", "init", "-q", str(root / name)], check=True,
                               capture_output=True)
                (root / name / "app.py").write_text(
                    f'KEY = "{DUMMY_AWS_KEY}"\n', encoding="utf-8"
                )
                subprocess.run(["git", "-C", str(root / name), "add", "-A"],
                               check=True, capture_output=True)
                subprocess.run(
                    ["git", "-C", str(root / name), "-c", "user.email=t@t",
                     "-c", "user.name=t", "commit", "-q", "-m", "init"],
                    check=True, capture_output=True,
                )
            out = Path(tmp) / "out"
            r = run_script("batch_scan.py", "--root", str(root), "--out", str(out),
                           "--mode", "secret-only")
            self.assertEqual(r.returncode, 0, r.stderr)
            data = load(out / "batch-summary.json")
            self.assertEqual(data["repositories_found"], 2)
            self.assertEqual(data["repositories_scanned"], 2)
            self.assertEqual(data["repositories_skipped"], 0)
            self.assertTrue((out / "repo-a").exists())
            self.assertTrue((out / "repo-b").exists())
            self.assertTrue((out / "batch-summary.txt").exists())

    def test_batch_skips_repositories_over_the_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repos"
            (root / "huge").mkdir(parents=True)
            subprocess.run(["git", "init", "-q", str(root / "huge")], check=True,
                           capture_output=True)
            (root / "huge" / "blob.bin").write_bytes(b"\0" * (2 * 1024 * 1024))
            out = Path(tmp) / "out"
            r = run_script("batch_scan.py", "--root", str(root), "--out", str(out),
                           "--size-ceiling-mb", "1")
            self.assertEqual(r.returncode, 0, r.stderr)
            data = load(out / "batch-summary.json")
            self.assertEqual(data["repositories_scanned"], 0)
            self.assertEqual(data["repositories_skipped"], 1)
            self.assertIn("ceiling", data["skipped"][0]["reason"])
            self.assertIn("NOT scanned", " ".join(data["limitations"]))

    def test_batch_does_not_modify_repositories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repos"
            (root / "repo-a").mkdir(parents=True)
            subprocess.run(["git", "init", "-q", str(root / "repo-a")], check=True,
                           capture_output=True)
            (root / "repo-a" / "app.py").write_text("x = 1\n", encoding="utf-8")
            before = {p: p.read_bytes() for p in (root / "repo-a").rglob("*")
                      if p.is_file() and ".git" not in p.parts}
            out = Path(tmp) / "out"
            run_script("batch_scan.py", "--root", str(root), "--out", str(out),
                       "--mode", "secret-only")
            after = {p: p.read_bytes() for p in (root / "repo-a").rglob("*")
                     if p.is_file() and ".git" not in p.parts}
            self.assertEqual(set(before), set(after))
            for path, content in before.items():
                self.assertEqual(content, after[path], f"modified: {path}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
