# Git Security Checklist

Applied by Module G. Focus: what the repository reveals, and what remains
recoverable even after removal.

## Tracked sensitive files

- [ ] `.env` or `.env.*` present and tracked
- [ ] Private keys: `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.keystore`
- [ ] Cloud credential files: `service-account*.json`, `credentials.json`, `id_rsa*`
- [ ] Database dumps: `*.sql`, `*.dump`, `*.bak`
- [ ] Logs: `*.log` with tokens, session identifiers, or personal data
- [ ] Build artifacts containing embedded secrets: `dist/`, `build/`, `out/`

## .gitignore coverage

- [ ] `.env` and `.env.*` ignored (with `!.env.example` if a template is shipped)
- [ ] `keys/`, `*.pem`, `*.key` ignored
- [ ] `__pycache__/`, `*.pyc` ignored
- [ ] `.venv/`, `venv/`, `node_modules/` ignored
- [ ] `*.db`, `*.sqlite3`, `*.db-wal`, `*.db-shm` ignored
- [ ] The `.gitignore` actually exists

## History exposure

- [ ] Was a sensitive file ever committed and then deleted? (Check
      `git log --all --diff-filter=D --name-only`.)
- [ ] Are secrets present in any historical commit? (Use gitleaks in git mode.)
- [ ] Does the repository have a history rewrite requirement, or should the
      secret simply be treated as public?

## Workflow and CI

- [ ] Do workflows use `pull_request_target` with a checkout of the PR head?
- [ ] Are secrets referenced in workflows, and are they scoped to the minimum?
- [ ] Are third-party actions pinned by SHA rather than a moving tag?
- [ ] Is a required review or status check configured before merge?
- [ ] Are protected branches used for release paths?
- [ ] Can a forked PR write to the repository or trigger a privileged workflow?

## Commit hygiene

- [ ] Are commits authored by a consistent, attributable identity?
- [ ] Are merge commits carrying internal hostnames or URLs?
- [ ] Do commit messages reference an internal issue tracker by name?
- [ ] Are generated files committed that should not be?

## Remediation expectations

1. **Removing a file is not remediation.** The content stays in history. State
   this explicitly in the report.
2. **Rotation is mandatory for anything that was committed**, even if deleted.
3. A history rewrite (`filter-repo`) is an option, but it rewrites shared history
   and must be the owner's decision. Present it, do not perform it.
4. Report the commit hash where the secret first appeared — it is the evidence
   an owner needs.
