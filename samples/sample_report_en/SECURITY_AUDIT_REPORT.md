# Security Audit Report

**Generated:** 2026-11-05T06:46:03Z  
**Repository:** demo-project  
**Audit mode:** standard

---

## Summary

| Severity | Findings |
|---|---|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 4 |
| LOW | 0 |
| INFORMATIONAL | 0 |

**Findings:** 13

---

## Findings

### CFG-SECRET-ENV-001-0001 — Secret stored in a plaintext config file

- **Severity:** HIGH  
- **Confidence:** PROBABLE  
- **Status:** UNVERIFIED - POTENTIALLY EXPOSED  
- **File:** `.env`  
- **Line:** 1–1  
- **Explanation:** Plaintext secrets in config files are exposed to anyone with repository or host access.  
- **Security impact:** Insecure configuration increases the impact of an otherwise limited exposure.  
- **Evidence:** CFG-SECRET-ENV-001 match, value redacted  
- **Remediation:** Move secrets to an environment variable or a secrets manager.  
- **CWE:** CWE-798  
- **OWASP:** A07:2021  

### CFG-SECRET-ENV-001-0002 — Secret stored in a plaintext config file

- **Severity:** HIGH  
- **Confidence:** PROBABLE  
- **Status:** UNVERIFIED - POTENTIALLY EXPOSED  
- **File:** `.env`  
- **Line:** 2–2  
- **Explanation:** Plaintext secrets in config files are exposed to anyone with repository or host access.  
- **Security impact:** Insecure configuration increases the impact of an otherwise limited exposure.  
- **Evidence:** CFG-SECRET-ENV-001 match, value redacted  
- **Remediation:** Move secrets to an environment variable or a secrets manager.  
- **CWE:** CWE-798  
- **OWASP:** A07:2021  

### ENV-0001 — Committed environment file

- **Severity:** HIGH  
- **Confidence:** CONFIRMED  
- **Status:** UNVERIFIED - POTENTIALLY EXPOSED  
- **File:** `.env`  
- **Line:** 1–2  
- **Explanation:** A .env file is tracked in the repository with 2 populated value(s).  
- **Security impact:** Environment files routinely carry credentials and are the most common leak vector.  
- **Evidence:** 2 populated keys, names only: API_KEY, SECRET_KEY  
- **Remediation:** Remove the file, add it to .gitignore, and rotate its contents.  
- **CWE:** CWE-798  
- **OWASP:** A07:2021  

### SEC-SEC-001-0003 — Hardcoded password assignment

- **Severity:** HIGH  
- **Confidence:** PROBABLE  
- **Status:** UNVERIFIED - POTENTIALLY EXPOSED  
- **File:** `settings.py`  
- **Line:** 14–14  
- **Explanation:** Pattern match for SEC-SEC-001.  
- **Security impact:** Credential or sensitive configuration exposed in source.  
- **Evidence:** SEC-SEC-001 match, 41 chars, mixed, sha256:80f8b038844e  
- **Remediation:** Read the value from an environment variable or a secrets manager.  
- **CWE:** CWE-798  
- **OWASP:** A07:2021  

### SEC-SEC-002-0004 — Hardcoded API key assignment

- **Severity:** HIGH  
- **Confidence:** PROBABLE  
- **Status:** UNVERIFIED - POTENTIALLY EXPOSED  
- **File:** `settings.py`  
- **Line:** 3–3  
- **Explanation:** Pattern match for SEC-SEC-002.  
- **Security impact:** Credential or sensitive configuration exposed in source.  
- **Evidence:** SEC-SEC-002 match, 45 chars, mixed, sha256:a7de5fde655e  
- **Remediation:** Move the key to an environment variable or a secrets manager and rotate it.  
- **CWE:** CWE-798  
- **OWASP:** A07:2021  

### SEC-SRC-002-0002 — Shell command built by interpolation

- **Severity:** HIGH  
- **Confidence:** PROBABLE  
- **Status:** UNVERIFIED - POTENTIALLY EXPOSED  
- **File:** `app.py`  
- **Line:** 16–16  
- **Explanation:** Pattern match for SEC-SRC-002.  
- **Security impact:** Credential or sensitive configuration exposed in source.  
- **Evidence:** SEC-SRC-002 match, 18 chars, mixed, sha256:9883ddc3f622  
- **Remediation:** Pass arguments as a list and never through a shell; validate against an allowlist.  
- **CWE:** CWE-78  
- **OWASP:** A03:2021  

### TAINT-0001 — Tainted data reaches SQL execution

- **Severity:** HIGH  
- **Confidence:** POTENTIAL  
- **Status:** UNVERIFIED - POTENTIALLY EXPOSED  
- **File:** `app.py`  
- **Line:** 9–9  
- **Explanation:** A user-controlled value flows from line 6 (request.args) to a SQL execution on line 9.  
- **Security impact:** If the intermediate handling does not sanitise the value, this is exploitable. Confirm by reading the function.  
- **Evidence:** source: 'request.args' -> sink: SQL execution; variables: name  
- **Remediation:** Validate and sanitise the input at the boundary; use parameterised queries, argument lists, or context-aware escaping.  
- **CWE:** CWE-74  
- **OWASP:** A03:2021  

### TAINT-0002 — Tainted data reaches shell execution

- **Severity:** HIGH  
- **Confidence:** POTENTIAL  
- **Status:** UNVERIFIED - POTENTIALLY EXPOSED  
- **File:** `app.py`  
- **Line:** 16–16  
- **Explanation:** A user-controlled value flows from line 13 (request.args) to a shell execution on line 16.  
- **Security impact:** If the intermediate handling does not sanitise the value, this is exploitable. Confirm by reading the function.  
- **Evidence:** source: 'request.args' -> sink: shell execution; variables: cmd  
- **Remediation:** Validate and sanitise the input at the boundary; use parameterised queries, argument lists, or context-aware escaping.  
- **CWE:** CWE-74  
- **OWASP:** A03:2021  

### GL-0001 — gitleaks: generic-api-key

- **Severity:** HIGH  
- **Confidence:** CONFIRMED  
- **Status:** UNVERIFIED - POTENTIALLY EXPOSED  
- **File:** `/tmp/dsa-fixtures/python-vulnerable/.env`  
- **Line:** 2–2  
- **Explanation:** gitleaks detected a credential-shaped value in the working tree.  
- **Security impact:** Exposed credential in a tracked or present file.  
- **Evidence:** generic-api-key match, 16 chars, base64ish, sha256:57be4d279116  
- **Remediation:** Remove the value, rotate it, and read it from the environment.  

### CFG-DEBUG-001-0003 — Debug mode enabled

- **Severity:** MEDIUM  
- **Confidence:** PROBABLE  
- **Status:** UNVERIFIED - POTENTIALLY EXPOSED  
- **File:** `settings.py`  
- **Line:** 2–2  
- **Explanation:** Debug mode leaks stack traces, environment details, and sometimes enables interactive consoles.  
- **Security impact:** Insecure configuration increases the impact of an otherwise limited exposure.  
- **Evidence:** CFG-DEBUG-001 match, value redacted  
- **Remediation:** Disable debug mode in production configurations and builds.  
- **CWE:** CWE-489  
- **OWASP:** A05:2021  

### CFG-ROOT-001-0004 — Container or pod runs as root

- **Severity:** MEDIUM  
- **Confidence:** PROBABLE  
- **Status:** UNVERIFIED - POTENTIALLY EXPOSED  
- **File:** `Dockerfile`  
- **Line:** 2–2  
- **Explanation:** Running as root increases the impact of any container escape.  
- **Security impact:** Insecure configuration increases the impact of an otherwise limited exposure.  
- **Evidence:** CFG-ROOT-001 match, value redacted  
- **Remediation:** Define a non-root USER and disable privilege escalation.  
- **CWE:** CWE-250  
- **OWASP:** A05:2021  

### SEC-CFG-001-0005 — Debug mode enabled

- **Severity:** MEDIUM  
- **Confidence:** PROBABLE  
- **Status:** UNVERIFIED - POTENTIALLY EXPOSED  
- **File:** `settings.py`  
- **Line:** 2–2  
- **Explanation:** Pattern match for SEC-CFG-001.  
- **Security impact:** Credential or sensitive configuration exposed in source.  
- **Evidence:** SEC-CFG-001 match, 12 chars, mixed, sha256:3e0894397f19  
- **Remediation:** Disable debug mode in production builds and deployments.  
- **CWE:** CWE-489  
- **OWASP:** A05:2021  

### SEC-CFG-005-0001 — Container runs as root

- **Severity:** MEDIUM  
- **Confidence:** PROBABLE  
- **Status:** UNVERIFIED - POTENTIALLY EXPOSED  
- **File:** `Dockerfile`  
- **Line:** 2–2  
- **Explanation:** Pattern match for SEC-CFG-005.  
- **Security impact:** Credential or sensitive configuration exposed in source.  
- **Evidence:** SEC-CFG-005 match, 9 chars, mixed, sha256:afa9c1eeee8b  
- **Remediation:** Add a non-root USER instruction and drop capabilities.  
- **CWE:** CWE-250  
- **OWASP:** A05:2021  

---

Automated scanning does not replace a professional security audit. No credential was tested or used, and no secret value appears in this report.
