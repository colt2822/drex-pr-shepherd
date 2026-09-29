# Changelog

## 0.1.0 (unreleased, pre-release)

First public snapshot. Alpha quality; not production-hardened.

- Deterministic PR lifecycle state machine (WATCHING through settlement states), with `APPROVED`, `MERGED`, `ACCEPTED_PAYOUT` and `REALIZED_REVENUE` kept as separate facts.
- CI and review event normalization into canonical events; append-only, replay-deduplicated event history.
- Deterministic CI-failure classification; only patch-caused failures and merge conflicts create repair work.
- Bounded repair/revision routing with configurable limits; exhaustion escalates to `HUMAN_ACTION_REQUIRED` with evidence. `drex-shepherd release` lets an operator resume a held PR.
- Same-mission invariant: revisions reuse the original mission, task, PR and branch; no new missions or PRs.
- GitHub polling adapter (REST or `gh` transports) with ETags, adaptive intervals, exponential backoff and rate-limit pause. Read-only in the CLI.
- Webhook event ingestion with HMAC-SHA256 verification (no bundled HTTP server).
- Settlement tracked separately from code acceptance; only platform-probe evidence advances it (watch starts at approval and continues after merge).
- SQLite persistence with restart recovery.
- Prompt-injection boundary: all GitHub content is untrusted, redacted, quoted as evidence, never executed.
- Evidence-grounded template replies (opt-in, dry-run).
- Deterministic offline demo (`drex-shepherd demo`).

Not included: real GitHub writes (experimental embedding API only, not enabled by CLI or environment), HTTP webhook listener, bundled workers or verifiers.
