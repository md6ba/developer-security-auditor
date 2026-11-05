# OWASP References

Mapping between the audit's findings and the OWASP Top 10 (2021) and ASVS controls.
Use these identifiers in reports so a finding can be traced to a public standard.

## OWASP Top 10 (2021)

| ID | Name | Typical rule categories |
|----|------|-------------------------|
| A01:2021 | Broken Access Control | `SEC-SRC-003`, `SEC-WEB3-001`, `CFG-AUTH-001` |
| A02:2021 | Cryptographic Failures | `SEC-SRC-006`, `SEC-SRC-007`, `CFG-TLS-001` |
| A03:2021 | Injection | `SEC-SRC-001`, `SEC-SRC-002`, `SEC-SRC-008`, `TAINT-001` |
| A04:2021 | Insecure Design | architecture findings, `SEC-WEB3-001` |
| A05:2021 | Security Misconfiguration | `SEC-CFG-*`, `CFG-*`, `SEC-CFG-006` |
| A06:2021 | Vulnerable and Outdated Components | dependency findings |
| A07:2021 | Identification and Authentication Failures | `SEC-SEC-*`, `SEC-ENV-001`, `CFG-AUTH-001` |
| A08:2021 | Software and Data Integrity Failures | `SEC-SRC-005`, CI findings |
| A09:2021 | Security Logging and Monitoring Failures | missing logging of auth events |
| A10:2021 | Server-Side Request Forgery | `SEC-SRC-008` |

## OWASP ASVS (selected)

| Control | Area | When to cite |
|---------|------|--------------|
| V1.5 | Architecture | trust-boundary findings, missing defence-in-depth |
| V2.1 | Authentication | password storage, default credentials |
| V2.2 | Session Management | session secrets, weak randomness |
| V3.1 | Session Management | JWT signing secrets |
| V4.1 | Access Control | missing authorization checks |
| V5.1 | Validation | input handling |
| V5.2 | Validation | taint flows |
| V5.3 | Validation | output encoding (DOM XSS) |
| V6.1 | Cryptography | weak algorithms |
| V6.2 | Cryptography | key management, private keys |
| V7.1 | Error Handling | debug mode, information disclosure |
| V9.1 | Communication | TLS verification |
| V10.1 | Malicious | deserialization |
| V12.1 | File Resources | path traversal |
| V13.1 | API | SSRF |
| V14.1 | Configuration | insecure defaults, permissions |

## How to use in a report

1. Cite the **most specific** control, not the whole category.
2. If a finding maps to no control, say so — do not force a mapping.
3. Keep the identifier in its original form (`A03:2021`, `V5.2`).
4. Never claim ASVS compliance; the mapping is a reference, not a certification.
