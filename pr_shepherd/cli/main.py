"""drex-shepherd CLI. Read-only against GitHub: v0.1 has no CLI path that writes."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from typing import Any, Optional, Sequence

from ..adapters.submission import Submission
from ..adapters.github import (
    ApiClientAdapter, GhCliTransport, GitHubError, UrllibTransport, parse_pr_url, verify_webhook_signature,
)
from ..core.engine import Shepherd
from ..core.models import make_shepherd_id
from ..core.policy import Policy
from ..storage.sqlite import Store
from .demo import run_demo


def _build(args: argparse.Namespace, need_reader: bool) -> Shepherd:
    policy = Policy.from_env()
    store = Store(args.db or os.environ.get("PR_SHEPHERD_DB", "./shepherd.db"))
    reader = writer = None
    if need_reader:
        kind = os.environ.get("PR_SHEPHERD_TRANSPORT", "urllib")
        transport = GhCliTransport() if kind == "gh" else UrllibTransport(os.environ.get("PR_SHEPHERD_API_URL", "https://api.github.com"))
        reader = ApiClientAdapter(transport, allow_writes=False)  # v0.1 CLI is read-only
    return Shepherd(store, reader=reader, writer=writer, policy=policy)


def _resolve(store: Store, ref: str, policy: Policy) -> Optional[str]:
    if ref.startswith("shp_"):
        return ref if store.get_pr(ref) else None
    try:
        repo, n = parse_pr_url(ref, policy.allowed_url_hosts)
    except ValueError:
        if "#" in ref:
            repo, _, num = ref.partition("#")
            repo, n = repo, int(num) if num.isdigit() else -1
        else:
            return None
    pr = store.find_pr(repo, n)
    return pr.shepherd_id if pr else None


def _fmt_ts(ts: Optional[float]) -> str:
    return "-" if not ts else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def cmd_watch(a: argparse.Namespace) -> int:
    sh = _build(a, need_reader=a.fetch)
    head_sha, head_branch, base, head_repo = a.head_sha, a.head_branch, a.base_branch, a.head_repository
    if a.fetch:
        repo, n = parse_pr_url(a.pr_url, sh.policy.allowed_url_hosts)
        snap = sh.reader.get_pr(repo, n)  # type: ignore[union-attr]
        head_sha, head_branch, base, head_repo = snap.head_sha, snap.head_ref, snap.base_ref, snap.head_repo
    if not head_sha or not head_branch:
        print("error: provide --head-sha and --head-branch, or use --fetch", file=sys.stderr)
        return 2
    payout = json.loads(a.expected_payout) if a.expected_payout else None
    sub = Submission(a.mission_id, a.task_id, a.receipt, a.artifact_digest, a.pr_url, payout)
    pr = sh.watch(sub, head_sha=head_sha, head_branch=head_branch, base_branch=base, head_repository=head_repo)
    print(f"watching {pr.repository}#{pr.pr_number} as {pr.shepherd_id} (state={pr.state.value})")
    return 0


def cmd_status(a: argparse.Namespace) -> int:
    sh = _build(a, need_reader=False)
    st = sh.status()
    if a.json:
        print(json.dumps(st, indent=2, sort_keys=True))
        return 0
    print("  ".join(f"{k}={v}" for k, v in st.items() if k != "prs"))
    for p in st["prs"]:
        print(f"- {p['repository']}#{p['pr_number']} {p['state']} sha={p['head_sha'][:7]} ci={p['ci_state']} review={p['review_state']} "
              f"rounds(ci/rev)={p['repair_round']}/{p['review_round']} settlement={p['settlement_stage']} "
              f"next={_fmt_ts(p['next_check_at'])} blocker={p['blocker'] or '-'}")
    return 0


def cmd_tick(a: argparse.Namespace) -> int:
    sh = _build(a, need_reader=True)
    rep = sh.tick()
    print(json.dumps({"polled": rep.polled, "errors": rep.errors, "rate_limited_until": rep.rate_limited_until}))
    queued = sh.pending_tasks()
    if queued:
        print(f"{len(queued)} task(s) queued for an external worker (see `drex-shepherd tasks`)")
    return 1 if rep.errors else 0


def cmd_tasks(a: argparse.Namespace) -> int:
    sh = _build(a, need_reader=False)
    for t in sh.pending_tasks():
        print(json.dumps({"key": t["action_key"], "kind": t["kind"], "route": t["route"], "contract": t["payload"]["contract"]}, sort_keys=True))
    return 0


def cmd_events(a: argparse.Namespace) -> int:
    sh = _build(a, need_reader=False)
    sid = _resolve(sh.store, a.pr, sh.policy)
    if not sid:
        print("error: PR is not watched", file=sys.stderr)
        return 2
    for e in sh.store.events(sid):
        if a.json:
            print(json.dumps(e.to_dict(), sort_keys=True))
        else:
            print(f"{e.seq:>4} {_fmt_ts(e.timestamp)} {e.type.value:<26} actor={e.actor or '-':<14} src={e.source_event_id} digest={e.payload_digest[:19]}")
    return 0


def cmd_ingest(a: argparse.Namespace) -> int:
    sh = _build(a, need_reader=False)
    body = open(a.file, "rb").read() if a.file != "-" else sys.stdin.buffer.read()
    secret = os.environ.get("PR_SHEPHERD_WEBHOOK_SECRET", "")
    if not verify_webhook_signature(secret, body, a.signature or ""):
        print("error: webhook signature missing or invalid", file=sys.stderr)
        return 2
    res = sh.ingest_webhook(a.event, json.loads(body), a.delivery or "", verified=True)
    print(json.dumps({sid: {"new": len(r.new_events), "duplicates": r.duplicates, "rejected": r.rejected,
                            "route": r.decision.route.value if r.decision else None} for sid, r in res.items()}))
    return 0


def cmd_demo(a: argparse.Namespace) -> int:
    if a.json:
        print(json.dumps(run_demo(lambda _msg: None), indent=2, sort_keys=True))
    else:
        run_demo()
    return 0


def cmd_release(a: argparse.Namespace) -> int:
    """Operator action: release a HUMAN_ACTION_REQUIRED hold. Performs no GitHub write."""
    sh = _build(a, need_reader=False)
    sid = _resolve(sh.store, a.pr, sh.policy)
    if not sid:
        print("error: PR is not watched", file=sys.stderr)
        return 2
    before = sh.store.get_pr(sid)
    if before.state.value != "HUMAN_ACTION_REQUIRED":
        print(f"error: PR is in {before.state.value}, not HUMAN_ACTION_REQUIRED; nothing released", file=sys.stderr)
        return 2
    after = sh.release_human(sid, a.reason, reset_budgets=a.reset_budgets)
    print(f"released {after.repository}#{after.pr_number}: {before.state.value} -> {after.state.value} (no GitHub write performed)")
    return 0


def cmd_doctor(a: argparse.Namespace) -> int:
    policy = Policy.from_env()
    checks: list[tuple[str, bool, str]] = [
        ("python>=3.10", sys.version_info >= (3, 10), sys.version.split()[0]),
        ("sqlite writable", True, a.db or os.environ.get("PR_SHEPHERD_DB", "./shepherd.db")),
        ("GITHUB_TOKEN set (reads)", bool(os.environ.get("GITHUB_TOKEN")) or os.environ.get("PR_SHEPHERD_TRANSPORT") == "gh", "value never printed"),
        ("gh CLI (optional)", shutil.which("gh") is not None, "only needed for PR_SHEPHERD_TRANSPORT=gh"),
        ("GitHub writes", True, "disabled: v0.1 CLI is read-only / dry-run"),
        ("factual replies", True, "enabled" if policy.allow_factual_replies else "disabled"),
    ]
    try:
        Store(a.db or os.environ.get("PR_SHEPHERD_DB", "./shepherd.db")).close()
    except Exception as e:  # noqa: BLE001
        checks[1] = ("sqlite writable", False, type(e).__name__)
    for name, ok, note in checks:
        print(f"[{'ok' if ok else '!!'}] {name}: {note}")
    return 0 if all(ok for _, ok, _ in checks[:2]) else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="drex-shepherd", description="Watch submitted PRs; route bounded repair; track settlement separately.")
    p.add_argument("--db", help="SQLite path (default: $PR_SHEPHERD_DB or ./shepherd.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("watch", help="start watching a submitted PR")
    w.add_argument("pr_url")
    w.add_argument("--mission-id", required=True)
    w.add_argument("--task-id", required=True)
    w.add_argument("--receipt", default="", help="verification receipt id of the submission")
    w.add_argument("--artifact-digest", default="")
    w.add_argument("--expected-payout", help='JSON, e.g. \'{"amount":"100","currency":"USD"}\'')
    w.add_argument("--fetch", action="store_true", help="read head sha/branch from GitHub (read-only)")
    w.add_argument("--head-sha", default="")
    w.add_argument("--head-branch", default="")
    w.add_argument("--head-repository", default="", help="owner/repo the PR branch lives in (forks)")
    w.add_argument("--base-branch", default="main")
    w.set_defaults(fn=cmd_watch)

    s = sub.add_parser("status", help="show watched PRs")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_status)
    sub.add_parser("tick", help="poll due PRs once").set_defaults(fn=cmd_tick)
    sub.add_parser("tasks", help="list queued repair/revision tasks").set_defaults(fn=cmd_tasks)
    e = sub.add_parser("events", help="immutable event history for a PR (URL, owner/repo#N, or shepherd id)")
    e.add_argument("pr")
    e.add_argument("--json", action="store_true")
    e.set_defaults(fn=cmd_events)
    i = sub.add_parser("ingest", help="ingest a signed webhook payload from a file or stdin (-)")
    i.add_argument("--event", required=True)
    i.add_argument("--file", default="-")
    i.add_argument("--signature", default="")
    i.add_argument("--delivery", default="")
    i.set_defaults(fn=cmd_ingest)
    d = sub.add_parser("demo", help="safe offline demo with fixtures")
    d.add_argument("--json", action="store_true", help="print the final summary as JSON only")
    d.set_defaults(fn=cmd_demo)
    r = sub.add_parser("release", help="operator: release a HUMAN_ACTION_REQUIRED hold (no GitHub write)")
    r.add_argument("pr", help="PR URL, owner/repo#N, or shepherd id")
    r.add_argument("--reason", required=True, help="why the hold is being released (recorded in the audit log)")
    r.add_argument("--reset-budgets", action="store_true", help="also reset revision/repair/unknown-failure counters")
    r.set_defaults(fn=cmd_release)
    sub.add_parser("doctor", help="check configuration").set_defaults(fn=cmd_doctor)

    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except (GitHubError, ValueError) as ex:
        print(f"error: {type(ex).__name__}: {ex}", file=sys.stderr)
        return 2
