# Architecture

## Layout

```
pr_shepherd/
  core/       models, state_machine, classifier, dedupe, router (Drex), scheduler, policy, security, engine
  adapters/   github (interfaces + REST/gh transports + event builders), submission (submission-source boundary), drex, fakes
  actions/    ci_repair, review_revision, factual_reply, settlement, common (Worker/Verifier seams)
  storage/    sqlite
  cli/        main, demo
tests/
```

The core depends only on adapter *interfaces*. `GitHubReader` and `GitHubWriter` are separate ABCs; `ApiClientAdapter` sits on any `transport(method, path, headers, body) -> Response`, so REST (`UrllibTransport`) and `gh api` (`GhCliTransport`) are interchangeable.

## Data model

* **`watched_prs`**: derived aggregate (state, head SHA, CI/review/merge state, rounds, next poll, backoff, blocker). Can be rebuilt from events.
* **`events`**: append-only (SQLite triggers reject UPDATE/DELETE). Each row keeps source event ID, repository, PR, actor, timestamp, raw source reference, normalized type, payload digest, trust label. `UNIQUE(shepherd_id, source_event_id)` is the replay dedupe.
* **`transitions`**: every state change with reason and triggering event.
* **`actions`**: repair/revision tasks and human escalations, idempotent by key (`<shepherd>:<kind>:<round>`).
* **`outbox`**: every GitHub write and upstream event, recorded *before* any live call, idempotent by key. Statuses: `DRY_RUN`, `SENT`, `FAILED`.
* **`audit`**: structured log records (decisions, rejections, dry-run writes, unverified signals).

Source IDs are *object-based* (`review:<id>:<state>`, `check_run:<id>:<status>:<conclusion>`, `head:<sha>`), not delivery-based, so a webhook and a later poll of the same object dedupe against each other.

## Event flow

1. **Ingest** (polling or webhook) builds `RawEvent`s. Webhooks require a verified HMAC. Events for another repo/PR, or a head from a different fork, are rejected. CI events for a SHA other than the current head are ignored (poll is the source of truth).
2. **Normalize** (`classifier.normalize`, deterministic): map to the canonical type, redact/bound/quote text, compute trust (`author_association` from the API, never from text; bots excluded), classify CI failures.
3. **Dedupe + append**, then **fold** into the aggregate (`state_machine.apply_event`, pure).
4. **Evaluate**: build a `DecisionInput` (new events, PR record, budget, resources, unclaimed feedback, open CI failures) and ask the router.
5. **Execute** the `Decision`: queue a task, escalate, post a template reply, or run a settlement check.

Routing is *level-triggered* from stored state and *idempotent*: re-evaluating an unchanged PR never creates a second task, because an open task blocks new ones and rounds are counted.

## Drex routing

`DeterministicRouter.decide` returns one of `NO_ACTION, WAIT, ROUTE_CODEX, ROUTE_CLAUDE, RUN_VERIFIER, POST_FACTUAL_RESPONSE, SETTLEMENT_CHECK, HUMAN_ACTION_REQUIRED`. `DrexAdapter` lets an external router *propose* a route; it is accepted only if it is in the deterministic router's `permitted_routes` for that exact input (for example choosing Claude instead of Codex). Anything else is overridden and logged. `RUN_VERIFIER` is only performed inside `complete_task`.

## CI classification

Order matters and is conservative: dependency/environment, upstream, timeout/flaky evidence win over patch evidence. `PATCH_CAUSED_FAILURE` needs both a failure pattern *and* a referenced path that is in the PR's changed files. Only `PATCH_CAUSED_FAILURE` (and merge conflicts) create work. Other classes `WAIT`, count toward `MAX_CONSECUTIVE_UNKNOWN_FAILURES` (once per head SHA), and escalate after that limit or after `nonactionable_stall_s`.

## Same-mission invariant

The `WatchedPR` carries `mission_id` and `task_id` from the submission. Contracts copy them; there is no adapter method that creates a mission, opportunity, or PR. A revision is `contract_id = <task_id>#rev<n>` (or `#ci<n>`, `#c<n>`). `watch` is idempotent per PR.

## Task lifecycle

```
QUEUED -> RUNNING -> (validate result: same branch, safe SHA, head unchanged)
       -> REVERIFYING -> VERIFY_FAILED | VERIFIED -> push same branch (write gate) -> DONE
```

`VERIFIED` without a push means the write gate is closed (dry-run); the PR waits in `READY_TO_UPDATE`. A moved head marks the task `STALE`. Pushes carry an expected-head lease (`--force-with-lease`). Tasks left `RUNNING` after a crash are requeued. With no in-process worker, tasks stay `QUEUED` for an external fleet (`pending_tasks()` / `complete_task()`).

## Polling

Adaptive intervals (active 60s; quiet 5m doubling to 1h; settlement 15m doubling to 6h), per-endpoint ETags, exponential error backoff, deterministic jitter, global rate-limit pause (`X-RateLimit-*`/`Retry-After`), and a per-tick cap. No busy loops: `tick()` polls only PRs whose `next_check_at` has passed.

## Settlement

`MERGED` moves to `SETTLEMENT_PENDING` when a payout is expected. `apply_settlement_evidence` is the only way to reach `ACCEPTED_PAYOUT` / `REALIZED_REVENUE`; it takes `SettlementEvidence` objects from a `SettlementProbe` (platform-specific hook). Signals inferred from GitHub text are stored with `trust=untrusted` and never move settlement or reach the upstream adapter. There is no wallet, bank, or payout code.

## Known limits

* One worker attempt per evaluation; retries wait for the next poll.
* `HUMAN_ACTION_REQUIRED` exits only through `drex-shepherd release` / `release_human()` or a merge/close; releasing performs no GitHub write.
* Dry-run replies are not auto-flushed when writes are later enabled (pushes are).
* CI "base branch also failing" input is supported by the classifier but not yet fetched by the poller.
* **Real GitHub writes are not enabled in v0.1.** The CLI is read-only. The embedding API has an experimental write path (`Policy.live_writes` plus an adapter with `allow_writes=True` and a `push_runner`) that is exercised only against fakes.
* Webhook support is HMAC-verified ingestion (`ingest_webhook`, `drex-shepherd ingest`); there is no built-in HTTP listener.
* The settlement probe starts at approval (when a payout is expected) and continues after merge. Approval or merge alone never advances settlement.
