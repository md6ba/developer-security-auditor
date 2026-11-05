# Known Limitations

Be honest about these when reporting. An audit that claims more than it did is worse
than one that admits its gaps.

## Detection limits

1. **Pattern matching is not a full parser.** The catalog uses regular expressions.
   It misses obfuscated, concatenated, or dynamically constructed secrets, and it can
   produce false positives in minified or generated code.
2. **Taint analysis is approximate.** `taint_scan.py` performs function-local,
   pattern-based tracking. It does not follow data across functions, classes, or files,
   and it cannot reason about sanitisation it does not recognise. Every taint finding is
   `POTENTIAL`.
3. **No semantic understanding.** The tool cannot tell whether a value is a live
   credential, a test fixture, a documentation example, or a placeholder. It reports
   what matches; a person decides.
4. **Secret validation is impossible by design.** The tool never tests a credential.
   A finding means "this value is exposed", never "this value works".
5. **Web3 analysis is source-level.** No contract is deployed, queried, or interacted
   with. Proxy patterns, upgrade mechanisms, and on-chain state cannot be fully assessed.
6. **Dependency auditing is not automated.** The inventory lists manifests; actual
   vulnerability lookup requires an external scanner, which is not bundled.

## Coverage limits

7. **Missing tools reduce coverage.** When `gitleaks`, `trufflehog`, or `bandit` is
   absent, the corresponding checks do not run. The report states this explicitly.
8. **History scanning has a commit ceiling.** `--max-commits` bounds the work; a very
   large history may be partially scanned, and the report must say so.
9. **Huge repositories need a size ceiling.** Repositories over the caller's limit are
   reported as skipped, not scanned.
10. **Only files reachable from the working tree are scanned.** Submodules, vendored
    repositories, and LFS pointers may not be followed.
11. **Encrypted or compressed content is opaque.** Secrets inside archives, images, or
    encrypted blobs are not detected.

## Operational limits

12. **Read-only by design.** The tool cannot apply fixes. Every remediation is a
    recommendation.
13. **Deception artifacts are generated, not deployed.** Module I produces files for a
    human to review and deploy where authorised.
14. **Diversification is surface-level.** Module J changes formatting, ordering, and
    whitespace. It does not restructure logic, and it is not an obfuscation guarantee.
15. **Reports reflect a point in time.** A repository changes; a report does not.

## Not a substitute

> Automated scanning does not replace a professional security audit. It finds evidence
> and reduces the search space. A qualified reviewer makes the judgement.
