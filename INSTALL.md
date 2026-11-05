# Installation

## Requirements

| Requirement | Mandatory | Notes |
|-------------|-----------|-------|
| Python 3.10+ | **Yes** | Standard library only. No `pip install` needed. |
| `git` | For history scans | Any recent version. |
| `gitleaks` | Strongly recommended | The primary secret scanner. |
| `trufflehog` | Optional | Secondary secret scanner, non-verifying mode only. |
| `bandit` | Optional | Python static analysis. |

**No external API credentials are required.** The tool is local-first and makes no
network calls of its own.

## Install as a Hermes skill

Copy the skill directory into the Hermes skills tree:

```
cp -r developer-security-auditor ~/.hermes/profiles/<profile>/skills/security/
```

Then verify:

```
python3 ~/.hermes/profiles/<profile>/skills/security/developer-security-auditor/scripts/rule_validate.py
```

Expected output: `errors: 0`.

## Install for training distribution

The skill is self-contained. Distribute the directory as-is:

```
developer-security-auditor/
├── SKILL.md
├── rules/
├── references/
├── scripts/
├── templates/
├── tests/
└── samples/
```

Recipients need only Python 3.10+ and, ideally, `gitleaks`. Everything else degrades
gracefully and is reported as uncovered.

## Verify the installation

```
cd developer-security-auditor
python3 scripts/rule_validate.py
python3 tests/make_fixtures.py --root /tmp/dsa-fixtures
python3 -m unittest discover -s tests -p "test_*.py"
```

All tests should pass. They use only synthetic fixtures and make no network calls.

## First audit

```
python3 scripts/repository_inventory.py --repo /path/to/project --out ./audit-out
python3 scripts/secret_scan.py --repo /path/to/project --out ./audit-out
python3 scripts/configuration_audit.py --repo /path/to/project --out ./audit-out
python3 scripts/taint_scan.py --repo /path/to/project --out ./audit-out
python3 scripts/report_generator.py --findings ./audit-out --out ./report --repo my-project --lang fa
```

## Optional tool installation

`gitleaks`:

```
# Debian/Ubuntu
sudo apt install gitleaks

# or download a release binary from the gitleaks project and place it on PATH
```

`trufflehog`:

```
# Download a release binary from the trufflehog project and place it on PATH
```

`bandit`:

```
pip install bandit
```

If a tool is missing, the corresponding module reports **uncovered** rather than
pretending the check ran.

## Security boundaries

Read `rules/security-boundaries.md` before the first audit. The rules are non-negotiable:
public or authorised targets only, no credential use or validation, read-only operation,
and no secret values in any output.
