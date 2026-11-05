# CWE Mapping

CWE identifiers used by the rule catalog, with the meaning of each in this audit's
context. Identifiers are always reported in their original form.

| CWE | Name | When it applies |
|-----|------|-----------------|
| CWE-22 | Path Traversal | user input reaches a file path |
| CWE-74 | Injection (general) | taint flow to a dangerous sink |
| CWE-78 | OS Command Injection | shell execution with interpolated input |
| CWE-79 | Cross-Site Scripting | user input reaches DOM sinks |
| CWE-89 | SQL Injection | input concatenated into SQL |
| CWE-250 | Execution with Unnecessary Privileges | root containers, over-scoped permissions |
| CWE-269 | Improper Privilege Management | owner concentration in contracts |
| CWE-295 | Improper Certificate Validation | TLS verification disabled |
| CWE-306 | Missing Authentication | auth switch disabled |
| CWE-327 | Use of a Broken Crypto Algorithm | MD5/SHA1 for security purposes |
| CWE-338 | Use of Cryptographically Weak PRNG | `Math.random`, `random.random` for tokens |
| CWE-489 | Active Debug Code | debug mode enabled |
| CWE-502 | Deserialization of Untrusted Data | pickle, yaml.load, unserialize |
| CWE-540 | Inclusion of Sensitive Information in Source Code | committed secrets, history leaks |
| CWE-732 | Incorrect Permission Assignment | world-writable files, root containers |
| CWE-798 | Use of Hard-coded Credentials | the majority of secret-exposure rules |
| CWE-841 | Improper Enforcement of Behavioral Workflow | unchecked external calls |
| CWE-918 | Server-Side Request Forgery | user input controls an outbound URL |
| CWE-942 | Permissive Cross-Domain Policy | wildcard CORS |

## Rules for assigning CWE

1. **Assign at most one primary CWE per finding.** Add a secondary only when the
   finding genuinely spans two weakness classes, and say why.
2. **Never assign CWE-798 to a placeholder.** A value like `your-secret-key` is a
   configuration anti-pattern (CWE-540), not a live credential.
3. **Never assign a CWE to a false positive.** If a hit is not a real weakness, it
   gets no identifier.
4. **If no CWE fits, leave it empty** rather than stretching a definition.
