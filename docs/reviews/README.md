# Audits and reviews

macwarden handles credentials that can move funds, so every release is audited before and after it ships. This folder keeps each report as it was written, including the findings that were wrong, partly fixed or carried over. Each report states its scope, the commit it examined and how each finding was proven.

Release audits since 1.0.0 use stable finding IDs (`MW102-nn`, `MW110-nn`). The [CHANGELOG](../../CHANGELOG.md) names the release that fixed each one, and every fix comes with a test that fails before it.

## Release audits

| Date | Report | Release audited | Findings | Status |
| --- | --- | --- | --- | --- |
| 2026-10-09 | [Audit of 1.1.0](2026-10-09-audit-1.1.0.md) | 1.1.0 | 11: 1 high, 4 medium, 6 low (MW110-01 to MW110-11) | All fixed in 1.1.1 |
| 2026-10-08 | [Audit of 1.0.1](2026-10-08-audit-1.0.1.md) | 1.0.1 | 12: 2 high, 7 medium, 3 low (MW102-01 to MW102-12) | All fixed in 1.1.0 |
| 2026-10-08 | [Deep audit, fixes and additions](2026-10-08-deep-audit.md) | 1.0.0 candidate (whole codebase at `5f2c3ee`) | Security, state-correctness and scale findings; mutation testing with 97 injected bugs, of which 24 exposed test gaps; red-team rounds under an attacker-controlled rate and volume model | All fixed in 1.0.0 |

Pre-release development reviews (before 1.0.0) are not included here.

Commit hashes and line numbers in these reports refer to the snapshot each one examined, in the project's development history before this repository was published. File paths have been updated to the current layout, in which the specification, architecture and security model live in [docs/spec.md](../spec.md), [docs/architecture.md](../architecture.md) and [docs/security-model.md](../security-model.md).
