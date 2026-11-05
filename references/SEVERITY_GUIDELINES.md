# Severity Guidelines

Five levels. Severity describes the **security impact if the finding is real**.
It never describes how confident the scanner is — that is the confidence field.

| Level | Meaning | Examples |
|-------|---------|----------|
| CRITICAL | Direct, unauthenticated access to funds, data, or infrastructure; no mitigating control | a live private key; a root database credential; a contract key that can move funds |
| HIGH | Exploitable with modest effort, or a credential that grants significant access | SQL injection; a committed API key; TLS verification disabled; wildcard CORS with credentials |
| MEDIUM | Requires a specific condition, or the impact is limited | debug mode in production; weak hash in a security path; incomplete `.gitignore` |
| LOW | Defence-in-depth, hygiene, or very limited impact | missing security headers; committed `__pycache__`; informational disclosure |
| INFORMATIONAL | Not a vulnerability; context the owner should know | forks of upstream code; brand accounts; centralisation notes |

## Confidence (separate axis)

| Level | Meaning |
|-------|---------|
| CONFIRMED | The pattern matched and the context supports it. A human can verify directly. |
| PROBABLE | Strong signal, but one contextual condition must hold. |
| POTENTIAL | Plausible, needs manual reading before it is a finding. |

**A finding's severity is capped by its confidence.** A `POTENTIAL` taint flow is
reported at most as MEDIUM until a human confirms it.

## CVSS 4.0

Map to CVSS only when you can populate the vector honestly:

- If any metric is unknown, **do not assign a score**. State "CVSS: not assignable —
  <missing metric>".
- Never inflate a score to make a report look thorough.
- Record the vector string alongside the score.

## Findings vs. risks vs. false positives

Every finding is one of:

1. **Confirmed** — verifiable in the artifact, no interpretation needed.
2. **Probable** — one assumption must hold; state it.
3. **Potential** — needs manual review; say what would confirm it.
4. **False positive** — matched the pattern but is not a weakness. Record it so the
   same hit is not reported again.
5. **Requires manual verification** — cannot be decided from the artifact alone.

## Anti-inflation rules

1. Do not raise severity because a finding is embarrassing or because the owner
   would react strongly.
2. Do not report the same issue twice under different rules — deduplicate by
   rule, file, and line.
3. Do not report a placeholder as a live credential. Report the anti-pattern.
4. Do not report a public identifier (contract address, project ID) as a secret.
5. When in doubt, lower the severity and raise the confidence caveat.
