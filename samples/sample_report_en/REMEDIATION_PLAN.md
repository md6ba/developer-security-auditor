# Remediation Plan

**Generated:** 2026-11-05T06:46:03Z

| Priority | Severity | Security Audit Report | Action | Owner |
|---|---|---|---|---|
| P1 | HIGH | Secret stored in a plaintext config file | Move secrets to an environment variable or a secrets manager. | python-vulnerable |
| P2 | HIGH | Secret stored in a plaintext config file | Move secrets to an environment variable or a secrets manager. | python-vulnerable |
| P3 | HIGH | Committed environment file | Remove the file, add it to .gitignore, and rotate its contents. | python-vulnerable |
| P4 | HIGH | Hardcoded password assignment | Read the value from an environment variable or a secrets manager. | python-vulnerable |
| P5 | HIGH | Hardcoded API key assignment | Move the key to an environment variable or a secrets manager and rotate it. | python-vulnerable |
| P6 | HIGH | Shell command built by interpolation | Pass arguments as a list and never through a shell; validate against an allowlist. | python-vulnerable |
| P7 | HIGH | Tainted data reaches SQL execution | Validate and sanitise the input at the boundary; use parameterised queries, argument lists, or context-aware escaping. | python-vulnerable |
| P8 | HIGH | Tainted data reaches shell execution | Validate and sanitise the input at the boundary; use parameterised queries, argument lists, or context-aware escaping. | python-vulnerable |
| P9 | HIGH | gitleaks: generic-api-key | Remove the value, rotate it, and read it from the environment. | python-vulnerable |
| P10 | MEDIUM | Debug mode enabled | Disable debug mode in production configurations and builds. | python-vulnerable |
| P11 | MEDIUM | Container or pod runs as root | Define a non-root USER and disable privilege escalation. | python-vulnerable |
| P12 | MEDIUM | Debug mode enabled | Disable debug mode in production builds and deployments. | python-vulnerable |
| P13 | MEDIUM | Container runs as root | Add a non-root USER instruction and drop capabilities. | python-vulnerable |

Automated scanning does not replace a professional security audit. No credential was tested or used, and no secret value appears in this report.
