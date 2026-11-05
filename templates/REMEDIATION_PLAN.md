# Remediation Plan — {{repository}}

**Generated:** {{generated_at}}
**Total findings:** {{count_total}}

| Priority | Severity | Finding | Action | Owner |
|----------|----------|---------|--------|-------|
| P1 | CRITICAL | {{title}} | {{action}} | {{owner}} |
| P2 | HIGH | {{title}} | {{action}} | {{owner}} |
| P3 | MEDIUM | {{title}} | {{action}} | {{owner}} |
| P4 | LOW | {{title}} | {{action}} | {{owner}} |

---

## Immediate (before any release)

{{immediate_actions}}

## Short term

{{short_term_actions}}

## Ongoing

- Add a pre-commit secret scanner.
- Add CI checks that fail on CRITICAL and HIGH findings.
- Review `.gitignore` coverage whenever a new file type is introduced.
- Schedule a manual review for every finding marked `POTENTIAL`.

---

> Rotation is mandatory for anything that was committed, even if it was later deleted.
