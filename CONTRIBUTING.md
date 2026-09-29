# Contributing

* Python 3.10+, standard library only at runtime. Keep it that way unless there is a strong reason.
* Run the suite: `python -m unittest` (also works under `pytest`). Tests use fakes; nothing may touch the network or real GitHub writes.
* Keep the core free of adapter specifics, private paths, usernames, repository names and tokens. Integrations with specific systems belong in optional adapters, not the core API. Fixtures use `example-org/example-repo`.
* New event types or states need: a normalizer rule, a state-machine rule, a router rule, and tests.
* Anything that writes to GitHub must go through `Shepherd._write` (outbox first, dry-run by default).
* Treat all GitHub text as untrusted; add a test when you introduce a new place where it is used.
* Security-sensitive changes: see SECURITY.md before opening a PR.
