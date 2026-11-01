#!/usr/bin/env python3
"""The counterexamples from the 1 November 2026 review, kept as tests.

Every mode here beat the verifier at commit 25cd57f. Each one now has to be
caught by a named check, or this script fails. That is the point: a fix
without a counterexample that can fail again is a fix waiting to regress.

    python3 audit/regressions.py            # all seven, exit 0 only if all caught
    python3 audit/regressions.py f1         # one, with the evidence printed

Each mode copies the repository into a temporary directory and works there,
so nothing here can damage the checkout it is run from.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_REPO = os.path.dirname(HERE)

# mode -> (what it does, when it is applied, checks that must fail, checks that must not fail)
#
# f2a and f2b are the two intervention points around replay, and they test different
# properties. f2a alters the WAL before replay, so the replayed record and the WAL agree
# and the timestamp binding is what fails: B fails, B.wal holds. f2b alters the WAL after
# replay, so the two disagree: B.wal fails. After the P0 patch B fails as well in the
# second case, because the WAL record's signature no longer covers its bytes, which is a
# second and independent reason. Both cases were raised as T08.
MODES = {
    "f1": ("WAL verdict flipped BLOCK to ALLOW and replayed with its stale signature",
           "mid-run", {"B"}, set()),
    "f2a": ("WAL decision_ts changed before replay and re-signed, so the record agrees with it",
            "mid-run", {"B"}, {"B.wal"}),
    "f2b": ("WAL decision_ts changed after replay, store untouched",
            "after-run", {"B.wal"}, set()),
    "f3": ("unsigned verdict for C-3003 appended and reframed",
           "after-run", {"gap:C-3003"}, set()),
    "f5": ("the seven host journals that prove scenarios ran deleted",
           "after-run", {"artifacts-complete"}, set()),
    "f8": ("D-4004 actor and policy rewritten and re-signed with the fixture key",
           "after-run", {"D"}, set()),
    "f13": ("host-B.jsonl cut mid-line, as a crash during an append leaves it",
            "after-run", {"artifacts-parse"}, set()),
    "f14": ("D-4004 decision_ts replaced with a Unix epoch value, re-signed, reframed",
            "after-run", {"D"}, set()),
}

TAMPER_HOOK = '''

def _regression_tamper(rundir):
    """Applied mid-run, at the one moment the mutation is meaningful.

    Both cases here touch the WAL before it is replayed, which is what
    distinguishes them from the after-run modes.
    """
    import sys as _sys
    _sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench"))
    from common import record_payload, sign

    mode = os.environ.get("REGRESSION_MODE", "")
    if mode not in ("f1", "f2a"):
        return
    path = os.path.join(rundir, "wal-B.jsonl")
    with open(path, encoding="utf-8") as fh:
        record = json.loads(fh.read().splitlines()[0])
    if mode == "f1":
        record["verdict"] = "ALLOW"        # the signature is deliberately left stale
    else:
        record["decision_ts"] = 7          # re-signed, so only the timestamp is wrong
        record["signature"] = sign(record_payload(record))
    with open(path, "w", encoding="utf-8", newline="\\n") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\\n")
'''


def patch_driver(repo: str) -> None:
    path = os.path.join(repo, "run.py")
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    anchor = '    print("[store] restarting from its journal")'
    if "_regression_tamper" in source or anchor not in source:
        return
    source = source.replace("def main(argv):", TAMPER_HOOK.strip("\n") + "\n\n\ndef main(argv):", 1)
    source = source.replace(anchor, "    _regression_tamper(rundir)\n" + anchor, 1)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(source)


def run_suite(repo: str, env: dict | None = None) -> str:
    """Run the suite in a fresh copy and return the directory it wrote.

    The directory is found by looking at what appeared under artifacts/, not by
    parsing what run.py printed: the printed path uses the platform separator,
    and a Windows run and a Linux run should not need different parsing.
    """
    before = set(os.listdir(os.path.join(repo, "artifacts"))) \
        if os.path.isdir(os.path.join(repo, "artifacts")) else set()
    proc = subprocess.run([sys.executable, "run.py"], cwd=repo, capture_output=True,
                          text=True, env=env)
    artifacts = os.path.join(repo, "artifacts")
    after = set(os.listdir(artifacts)) if os.path.isdir(artifacts) else set()
    new_dirs = sorted(name for name in after - before if name.startswith("run-"))
    if not new_dirs:
        sys.stderr.write(proc.stdout[-1500:] + proc.stderr[-1500:])
        raise SystemExit("run.py produced no artifact directory")
    return os.path.join(artifacts, new_dirs[-1])


def bench_import(repo: str):
    sys.path.insert(0, os.path.join(repo, "bench"))
    import common  # noqa: PLC0415
    return common


def start_store(repo: str, rundir: str):
    announce = os.path.join(rundir, "port-regression.txt")
    if os.path.exists(announce):
        os.remove(announce)
    proc = subprocess.Popen(
        [sys.executable, os.path.join(repo, "bench", "store.py"),
         "--journal", os.path.join(rundir, "store.jsonl"), "--announce", announce],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    for _ in range(500):
        if os.path.exists(announce):
            with open(announce, encoding="utf-8") as fh:
                text = fh.read().strip()
            if text:
                return proc, int(text)
        if proc.poll() is not None:
            raise SystemExit("store exited: %s" % proc.stderr.read())
        time.sleep(0.02)
    raise SystemExit("store did not announce a port")


def stop_store(proc) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def gap_names(port: int) -> set:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(b'{"cmd": "reconcile"}\n')
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    return {gap["action_id"] for gap in json.loads(buf.decode("utf-8")).get("gaps") or []}


def append_unsigned_verdict(repo: str, rundir: str) -> None:
    common = bench_import(repo)
    path = os.path.join(rundir, "store.jsonl")
    with open(path, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
    forged = {"action_id": "C-3003", "kind": "verdict",
              "store_seq": max(r.get("store_seq", 0) for r in rows) + 1,
              "record": {"action_id": "C-3003", "decided_by": "nobody", "decision_ts": 2,
                         "descriptor_sha": None, "policy_sha": None, "rule": None,
                         "signature": None, "verdict": "ALLOW"}}
    forged["digest"] = common.frame(forged)
    with open(path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(forged, sort_keys=True) + "\n")


def apply_after_run(repo: str, rundir: str, mode: str) -> None:
    common = bench_import(repo)

    if mode == "f2b":
        path = os.path.join(rundir, "wal-B.jsonl")
        with open(path, encoding="utf-8") as fh:
            record = json.loads(fh.read().splitlines()[0])
        record["decision_ts"] = 7
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return

    if mode == "f3":
        append_unsigned_verdict(repo, rundir)
        return

    if mode == "f5":
        for name in ("host-A.jsonl", "host-Ap.jsonl", "host-C.jsonl", "host-Cp.jsonl",
                     "host-Cpp.jsonl", "host-D.jsonl", "host-Dp.jsonl"):
            os.remove(os.path.join(rundir, name))
        return

    if mode == "f13":
        path = os.path.join(rundir, "host-B.jsonl")
        with open(path, "rb") as fh:
            data = fh.read()
        with open(path, "wb") as fh:
            fh.write(data[: len(data) // 2])
        return

    if mode in ("f8", "f14"):
        path = os.path.join(rundir, "store.jsonl")
        with open(path, encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
        for row in rows:
            if row.get("kind") == "verdict" and row.get("action_id") == "D-4004":
                if mode == "f8":
                    row["record"]["decided_by"] = "someone-else"
                    row["record"]["policy_sha"] = "sha256:" + "0" * 64
                else:
                    row["record"]["decision_ts"] = 1767225600
                row["record"]["signature"] = common.sign(common.record_payload(row["record"]))
                row["digest"] = common.frame(row)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        return

    raise SystemExit("no after-run change for %r" % mode)


def run_verify(repo: str, rundir: str) -> None:
    subprocess.run([sys.executable, "verify.py", rundir], cwd=repo,
                   capture_output=True, text=True)


def failed_checks(rundir: str) -> tuple[set, str]:
    path = os.path.join(rundir, "verify-report.json")
    if not os.path.exists(path):
        return set(), "no report written"
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    return {row["id"] for row in report["checks"] if row["result"] == "fails"}, ""


def run_mode(repo: str, mode: str) -> tuple[bool, str]:
    work = tempfile.mkdtemp(prefix="hfb-regression-")
    tree = os.path.join(work, "host-failure-benchmark")
    shutil.copytree(repo, tree, ignore=shutil.ignore_patterns(
        "artifacts", ".git", "__pycache__", "*.pyc"))
    try:
        env = dict(os.environ)
        if MODES[mode][1] == "mid-run":
            patch_driver(tree)
            env["REGRESSION_MODE"] = mode
        rundir = run_suite(tree, env)
        detail = ""
        if MODES[mode][1] == "after-run":
            apply_after_run(tree, rundir, mode)

        if mode == "f3":
            # The assertion is not a failing check: a forged verdict must not erase a gap.
            proc, port = start_store(tree, rundir)
            try:
                gaps = gap_names(port)
            finally:
                stop_store(proc)
            kept = "C-3003" in gaps
            return kept, "C-3003 named as a gap: %s" % ("yes" if kept else "no")

        run_verify(tree, rundir)
        wanted, forbidden = MODES[mode][2], MODES[mode][3]
        failed, note = failed_checks(rundir)
        caught = wanted <= failed and not (forbidden & failed)
        detail = note or ("failed: %s" % (", ".join(sorted(failed)) or "nothing"))
        if forbidden & failed:
            detail += " (expected %s to hold)" % ", ".join(sorted(forbidden & failed))
        return caught, detail
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Counterexamples from the 1 Nov 2026 review.")
    parser.add_argument("mode", nargs="?", default="all",
                        help="one of %s, or all" % ", ".join(sorted(MODES)))
    parser.add_argument("--repo", default=DEFAULT_REPO,
                        help="checkout to test (default: the one this file sits in)")
    args = parser.parse_args(argv)

    if args.mode != "all" and args.mode not in MODES:
        raise SystemExit("unknown mode %r" % args.mode)

    repo = os.path.abspath(args.repo)
    for required in ("run.py", "verify.py", os.path.join("bench", "store.py")):
        if not os.path.exists(os.path.join(repo, required)):
            raise SystemExit("%s is not a benchmark checkout: no %s" % (repo, required))

    modes = sorted(MODES) if args.mode == "all" else [args.mode]
    missed = []
    for mode in modes:
        caught, detail = run_mode(repo, mode)
        print("%-4s %-7s %s" % (mode, "caught" if caught else "MISSED", MODES[mode][0]))
        print("%-4s         %s" % ("", detail))
        if not caught:
            missed.append(mode)

    print("")
    if missed:
        print("NOT CAUGHT: %s" % ", ".join(missed))
        print("A counterexample the verifier still accepts is a claim it does not support.")
        return 1
    print("Every counterexample from the review is caught by the check that claims to catch it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
