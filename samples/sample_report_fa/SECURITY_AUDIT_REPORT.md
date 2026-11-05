# گزارش ممیزی امنیتی

**تاریخ تهیه:** 2026-11-05T06:46:03Z  
**مخزن:** demo-project  
**حالت ممیزی:** standard

---

## خلاصه

| شدت | یافته‌ها |
|---|---|
| بحرانی | 0 |
| بالا | 9 |
| متوسط | 4 |
| پایین | 0 |
| اطلاعاتی | 0 |

**یافته‌ها:** 13

---

## یافته‌ها

### CFG-SECRET-ENV-001-0001 — Secret stored in a plaintext config file

- **شدت:** بالا  
- **اطمینان:** PROBABLE  
- **وضعیت:** UNVERIFIED - POTENTIALLY EXPOSED  
- **فایل:** `.env`  
- **خط:** 1–1  
- **توضیح:** Plaintext secrets in config files are exposed to anyone with repository or host access.  
- **اثر امنیتی:** Insecure configuration increases the impact of an otherwise limited exposure.  
- **شواهد:** CFG-SECRET-ENV-001 match, value redacted  
- **راه‌حل اصلاح:** Move secrets to an environment variable or a secrets manager.  
- **CWE:** CWE-798  
- **OWASP:** A07:2021  

### CFG-SECRET-ENV-001-0002 — Secret stored in a plaintext config file

- **شدت:** بالا  
- **اطمینان:** PROBABLE  
- **وضعیت:** UNVERIFIED - POTENTIALLY EXPOSED  
- **فایل:** `.env`  
- **خط:** 2–2  
- **توضیح:** Plaintext secrets in config files are exposed to anyone with repository or host access.  
- **اثر امنیتی:** Insecure configuration increases the impact of an otherwise limited exposure.  
- **شواهد:** CFG-SECRET-ENV-001 match, value redacted  
- **راه‌حل اصلاح:** Move secrets to an environment variable or a secrets manager.  
- **CWE:** CWE-798  
- **OWASP:** A07:2021  

### ENV-0001 — Committed environment file

- **شدت:** بالا  
- **اطمینان:** CONFIRMED  
- **وضعیت:** UNVERIFIED - POTENTIALLY EXPOSED  
- **فایل:** `.env`  
- **خط:** 1–2  
- **توضیح:** A .env file is tracked in the repository with 2 populated value(s).  
- **اثر امنیتی:** Environment files routinely carry credentials and are the most common leak vector.  
- **شواهد:** 2 populated keys, names only: API_KEY, SECRET_KEY  
- **راه‌حل اصلاح:** Remove the file, add it to .gitignore, and rotate its contents.  
- **CWE:** CWE-798  
- **OWASP:** A07:2021  

### SEC-SEC-001-0003 — Hardcoded password assignment

- **شدت:** بالا  
- **اطمینان:** PROBABLE  
- **وضعیت:** UNVERIFIED - POTENTIALLY EXPOSED  
- **فایل:** `settings.py`  
- **خط:** 14–14  
- **توضیح:** Pattern match for SEC-SEC-001.  
- **اثر امنیتی:** Credential or sensitive configuration exposed in source.  
- **شواهد:** SEC-SEC-001 match, 41 chars, mixed, sha256:80f8b038844e  
- **راه‌حل اصلاح:** Read the value from an environment variable or a secrets manager.  
- **CWE:** CWE-798  
- **OWASP:** A07:2021  

### SEC-SEC-002-0004 — Hardcoded API key assignment

- **شدت:** بالا  
- **اطمینان:** PROBABLE  
- **وضعیت:** UNVERIFIED - POTENTIALLY EXPOSED  
- **فایل:** `settings.py`  
- **خط:** 3–3  
- **توضیح:** Pattern match for SEC-SEC-002.  
- **اثر امنیتی:** Credential or sensitive configuration exposed in source.  
- **شواهد:** SEC-SEC-002 match, 45 chars, mixed, sha256:a7de5fde655e  
- **راه‌حل اصلاح:** Move the key to an environment variable or a secrets manager and rotate it.  
- **CWE:** CWE-798  
- **OWASP:** A07:2021  

### SEC-SRC-002-0002 — Shell command built by interpolation

- **شدت:** بالا  
- **اطمینان:** PROBABLE  
- **وضعیت:** UNVERIFIED - POTENTIALLY EXPOSED  
- **فایل:** `app.py`  
- **خط:** 16–16  
- **توضیح:** Pattern match for SEC-SRC-002.  
- **اثر امنیتی:** Credential or sensitive configuration exposed in source.  
- **شواهد:** SEC-SRC-002 match, 18 chars, mixed, sha256:9883ddc3f622  
- **راه‌حل اصلاح:** Pass arguments as a list and never through a shell; validate against an allowlist.  
- **CWE:** CWE-78  
- **OWASP:** A03:2021  

### TAINT-0001 — Tainted data reaches SQL execution

- **شدت:** بالا  
- **اطمینان:** POTENTIAL  
- **وضعیت:** UNVERIFIED - POTENTIALLY EXPOSED  
- **فایل:** `app.py`  
- **خط:** 9–9  
- **توضیح:** A user-controlled value flows from line 6 (request.args) to a SQL execution on line 9.  
- **اثر امنیتی:** If the intermediate handling does not sanitise the value, this is exploitable. Confirm by reading the function.  
- **شواهد:** source: 'request.args' -> sink: SQL execution; variables: name  
- **راه‌حل اصلاح:** Validate and sanitise the input at the boundary; use parameterised queries, argument lists, or context-aware escaping.  
- **CWE:** CWE-74  
- **OWASP:** A03:2021  

### TAINT-0002 — Tainted data reaches shell execution

- **شدت:** بالا  
- **اطمینان:** POTENTIAL  
- **وضعیت:** UNVERIFIED - POTENTIALLY EXPOSED  
- **فایل:** `app.py`  
- **خط:** 16–16  
- **توضیح:** A user-controlled value flows from line 13 (request.args) to a shell execution on line 16.  
- **اثر امنیتی:** If the intermediate handling does not sanitise the value, this is exploitable. Confirm by reading the function.  
- **شواهد:** source: 'request.args' -> sink: shell execution; variables: cmd  
- **راه‌حل اصلاح:** Validate and sanitise the input at the boundary; use parameterised queries, argument lists, or context-aware escaping.  
- **CWE:** CWE-74  
- **OWASP:** A03:2021  

### GL-0001 — gitleaks: generic-api-key

- **شدت:** بالا  
- **اطمینان:** CONFIRMED  
- **وضعیت:** UNVERIFIED - POTENTIALLY EXPOSED  
- **فایل:** `/tmp/dsa-fixtures/python-vulnerable/.env`  
- **خط:** 2–2  
- **توضیح:** gitleaks detected a credential-shaped value in the working tree.  
- **اثر امنیتی:** Exposed credential in a tracked or present file.  
- **شواهد:** generic-api-key match, 16 chars, base64ish, sha256:57be4d279116  
- **راه‌حل اصلاح:** Remove the value, rotate it, and read it from the environment.  

### CFG-DEBUG-001-0003 — Debug mode enabled

- **شدت:** متوسط  
- **اطمینان:** PROBABLE  
- **وضعیت:** UNVERIFIED - POTENTIALLY EXPOSED  
- **فایل:** `settings.py`  
- **خط:** 2–2  
- **توضیح:** Debug mode leaks stack traces, environment details, and sometimes enables interactive consoles.  
- **اثر امنیتی:** Insecure configuration increases the impact of an otherwise limited exposure.  
- **شواهد:** CFG-DEBUG-001 match, value redacted  
- **راه‌حل اصلاح:** Disable debug mode in production configurations and builds.  
- **CWE:** CWE-489  
- **OWASP:** A05:2021  

### CFG-ROOT-001-0004 — Container or pod runs as root

- **شدت:** متوسط  
- **اطمینان:** PROBABLE  
- **وضعیت:** UNVERIFIED - POTENTIALLY EXPOSED  
- **فایل:** `Dockerfile`  
- **خط:** 2–2  
- **توضیح:** Running as root increases the impact of any container escape.  
- **اثر امنیتی:** Insecure configuration increases the impact of an otherwise limited exposure.  
- **شواهد:** CFG-ROOT-001 match, value redacted  
- **راه‌حل اصلاح:** Define a non-root USER and disable privilege escalation.  
- **CWE:** CWE-250  
- **OWASP:** A05:2021  

### SEC-CFG-001-0005 — Debug mode enabled

- **شدت:** متوسط  
- **اطمینان:** PROBABLE  
- **وضعیت:** UNVERIFIED - POTENTIALLY EXPOSED  
- **فایل:** `settings.py`  
- **خط:** 2–2  
- **توضیح:** Pattern match for SEC-CFG-001.  
- **اثر امنیتی:** Credential or sensitive configuration exposed in source.  
- **شواهد:** SEC-CFG-001 match, 12 chars, mixed, sha256:3e0894397f19  
- **راه‌حل اصلاح:** Disable debug mode in production builds and deployments.  
- **CWE:** CWE-489  
- **OWASP:** A05:2021  

### SEC-CFG-005-0001 — Container runs as root

- **شدت:** متوسط  
- **اطمینان:** PROBABLE  
- **وضعیت:** UNVERIFIED - POTENTIALLY EXPOSED  
- **فایل:** `Dockerfile`  
- **خط:** 2–2  
- **توضیح:** Pattern match for SEC-CFG-005.  
- **اثر امنیتی:** Credential or sensitive configuration exposed in source.  
- **شواهد:** SEC-CFG-005 match, 9 chars, mixed, sha256:afa9c1eeee8b  
- **راه‌حل اصلاح:** Add a non-root USER instruction and drop capabilities.  
- **CWE:** CWE-250  
- **OWASP:** A05:2021  

---

این ممیزی خودکار جایگزین ممیزی امنیتی حرفه‌ای نیست. هیچ رمزی تست یا استفاده نشده است و هیچ مقدار محرمانه‌ای در این گزارش ثبت نشده است.
