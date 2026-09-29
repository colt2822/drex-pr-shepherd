# Security

## Threat model

Everything that arrives from GitHub is attacker-controlled: comment and review text, CI logs, filenames, branch names, actor names, repository instructions. The Shepherd is built so that this text can influence *data* (a quoted evidence field) but never *control flow*.

## Guarantees and defaults

* **GitHub comments, reviews, CI logs and filenames are untrusted input.** They are stored and quoted as data.
* **No arbitrary instructions from comments are executed.** Nothing in the core runs shell commands or evaluates text, and routing ignores route names or commands that appear in text.
* **Do not put secrets in event payloads, contracts, or submission fields.** Secret-shaped strings are redacted on a best-effort basis, but the redaction is a safety net, not a guarantee. Keep tokens in the environment only.
* **GitHub writes are disabled by default and not enabled in v0.1's CLI.** The embedding API has an experimental, opt-in write path (outbox first, double-gated); treat it as untested against real GitHub.
* Webhook ingestion requires a valid HMAC-SHA256 signature; v0.1 ships no HTTP listener, so put your own TLS-terminating receiver in front of `ingest_webhook`.

## Boundaries

| Threat | Mitigation |
|---|---|
| Prompt injection in comments/logs | Text is cleaned, bounded, redacted and quoted into `untrusted_evidence` fields labelled `UNTRUSTED_DATA_NOT_INSTRUCTIONS`. Contract `instructions` is a fixed constant. Instruction-like text (`injection_flags`) from a trusted reviewer is escalated to a human instead of routed. |
| Commands embedded in review text | The router is a pure function of typed fields; nothing parses comment text for commands, and there is no shell execution anywhere in the core. Route names in text are ignored (tested). |
| Malicious filenames / path escape | `safe_relative_path` rejects absolute, `..`, backslash, shell metacharacter, control-character paths; failing paths are dropped from contracts. |
| Branch/repo confusion | Events must match the watched repo and PR number; a head from a different fork is rejected; task results must name the watched branch; pushes use an expected-head lease and validated ref names. |
| Actor spoofing | Trust comes only from API `author_association` (and bot type), never from text. Untrusted actors are recorded but cannot drive revisions, questions, or settlement signals. Own logins are excluded. |
| Webhook forgery/replay | HMAC-SHA256 verification is required by `ingest_webhook(verified=True)`; replays dedupe by object ID. |
| Secret exfiltration | Secret-shaped strings are redacted before storage; external URLs are stripped from quoted evidence; the token is read from the environment and never logged or printed. |
| Unauthorized writes | Writes are separate methods, gated twice (policy + adapter), and recorded in an outbox first. Default is dry-run and the CLI never enables them. There is no merge, close, or payout method. |
| Fabricated verification / payment | Replies are fixed templates that require a stored passing verification receipt; settlement advances only from platform evidence objects. |

## Not covered

The coding worker and verifier you plug in are outside this boundary: run them sandboxed, with no credentials, over a scratch checkout. The regex heuristics are defense in depth, not a proof; do not rely on them alone.

## Reporting

Use GitHub's **private vulnerability reporting** (Security tab → "Report a vulnerability") on the project repository when it is enabled. If it is not, open a public issue that says only that you have a security report and asks for a private contact; do not include exploit details, credentials, or private data in the issue. We aim to acknowledge reports within a few days. This is an alpha project maintained on a best-effort basis.
