# DocuTrust SCA Policy

## Severity Thresholds
- Critical / High → blocks the build. No merge until fixed or replaced.
- Moderate → allowed to merge only with a documented exception (see below), max 30 days before mandatory fix.
- Low → tracked in backlog, non-blocking.

## Exception Process
Any Moderate-or-above finding that isn't fixed immediately needs:
1. A written justification (why it can't be fixed now — no upstream fix, breaking change, etc.)
2. A named owner responsible for tracking it
3. A re-review date (max 30 days out)
Exceptions are logged in `SCA-EXCEPTIONS.md`, not just verbally agreed.

## Enforcement
`npm audit --audit-level=high` runs in CI on every PR and blocks merge on Critical/High.

## Scorecard Minimum Threshold
- Minimum acceptable OpenSSF Scorecard score for CI to pass: 5.0
- Enforced in .github/workflows/ci.yml (scorecard-policy job)
- Current DocuTrust score: 2.9 — below threshold. Repo does not yet meet the minimum
  maturity bar. Gaps are expected to close via Project 8 (branch protection, signed
  commits) and Project 7 (continuous fuzzing). This reflects a genuine, current gap
  in the pipeline, not a misconfigured check.
