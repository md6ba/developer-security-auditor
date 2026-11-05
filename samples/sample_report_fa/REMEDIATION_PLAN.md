# برنامه‌ی اصلاح

**تاریخ تهیه:** 2026-11-05T06:46:03Z

| اولویت | شدت | گزارش ممیزی امنیتی | اقدام | مسئول |
|---|---|---|---|---|
| P1 | بالا | Secret stored in a plaintext config file | Move secrets to an environment variable or a secrets manager. | python-vulnerable |
| P2 | بالا | Secret stored in a plaintext config file | Move secrets to an environment variable or a secrets manager. | python-vulnerable |
| P3 | بالا | Committed environment file | Remove the file, add it to .gitignore, and rotate its contents. | python-vulnerable |
| P4 | بالا | Hardcoded password assignment | Read the value from an environment variable or a secrets manager. | python-vulnerable |
| P5 | بالا | Hardcoded API key assignment | Move the key to an environment variable or a secrets manager and rotate it. | python-vulnerable |
| P6 | بالا | Shell command built by interpolation | Pass arguments as a list and never through a shell; validate against an allowlist. | python-vulnerable |
| P7 | بالا | Tainted data reaches SQL execution | Validate and sanitise the input at the boundary; use parameterised queries, argument lists, or context-aware escaping. | python-vulnerable |
| P8 | بالا | Tainted data reaches shell execution | Validate and sanitise the input at the boundary; use parameterised queries, argument lists, or context-aware escaping. | python-vulnerable |
| P9 | بالا | gitleaks: generic-api-key | Remove the value, rotate it, and read it from the environment. | python-vulnerable |
| P10 | متوسط | Debug mode enabled | Disable debug mode in production configurations and builds. | python-vulnerable |
| P11 | متوسط | Container or pod runs as root | Define a non-root USER and disable privilege escalation. | python-vulnerable |
| P12 | متوسط | Debug mode enabled | Disable debug mode in production builds and deployments. | python-vulnerable |
| P13 | متوسط | Container runs as root | Add a non-root USER instruction and drop capabilities. | python-vulnerable |

این ممیزی خودکار جایگزین ممیزی امنیتی حرفه‌ای نیست. هیچ رمزی تست یا استفاده نشده است و هیچ مقدار محرمانه‌ای در این گزارش ثبت نشده است.
