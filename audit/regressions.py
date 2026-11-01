#!/usr/bin/env python3
"""The counterexamples from the two reviews of 1 November 2026, kept as tests.

Every mode here beat the verifier at commit 25cd57f. Each one now has to be
caught by a named check, or this script fails. That is the point: a fix
without a counterexample that can fail again is a fix waiting to regress.

    python3 audit/regressions.py            # all nineteen, exit 0 only if all caught
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
import hashlib

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
    # The P1 counterexamples. Two of them are mutations of the evidence and two are mutations
    # of the code, because F7 and F9 are defects in what the artifacts contain while F10 and
    # F11 are defects in the order the processes act in. Mutating the artifact cannot show a
    # bug that lives in the code, and pretending otherwise would test the mutation instead.
    "f7": ("the bytes a repair removed deleted, so recovery destroys what it recovered",
           "after-run", {"repair-quarantine"}, set()),
    "f9": ("the conflict record removed, leaving the first verdict to be read as the answer",
           "after-run", {"conflict"}, set()),
    "f10": ("the host accepting any well-formed reply, as it did before the patch",
            "before-run", {"reply-checked"}, set()),
    "f11": ("the store indexing memory before the journal, as it did before the patch",
            "before-run", {"journal-first"}, set()),
    # The P2 counterexamples, from the differential review of the same day. F-01 is two defects
    # in one area, so it gets two modes: a row that asserts its own state, and a record signed
    # for one action filed under another. Neither is a mutation of the verifier. Both are
    # answered by the store's own replay, so the assertion is what a restarted store reports,
    # exactly as the reviewer asked it.
    "f16": ("a journal row that asserts state=verified over an unsigned record, then a restart",
            "after-run", set(), set()),
    "f17": ("a record signed for D-4004 filed under C-3003, then a restart",
            "after-run", set(), set()),
    # F-02. The conflict record is gone and the two signed verdicts remain: whichever one a
    # reader loads first must not become the answer.
    "f18": ("two differently signed D-4004 verdicts with the conflict record removed",
            "after-run", {"D"}, set()),
    # F-03. The pre-P2 host reads ok:true as consent, so D' ships an effect the store said it
    # could not resolve.
    "f19": ("the host accepting a reply that was neither stored nor resolved, as it did before P2",
            "before-run", {"D'.effect"}, set()),
    # F-05, in both directions: the benign restart must verify, and the pre-P2 binding must not.
    "f20": ("a routine restart after a valid run, against the binding P2 replaced",
            "custom", set(), set()),
    # F-04. A journal that raises on write, in process, where an injected EIO can reach it.
    "f21": ("a journal whose open() and fsync() raise EIO during a verdict append",
            "custom", set(), set()),
    # F-09. The two input-handling cases the reviewer found in the runner, not in the run.
    "f22": ("one directory compared with itself, and a challenge that edits the evidence",
            "custom", set(), set()),
}


def apply_before_run(tree: str, mode: str) -> None:
    """Undo a P1 fix in the copy, so the check that claims to catch it has to catch it.

    These two are orderings inside a process. There is no artifact to damage: the defect is
    that the process acts in the wrong order, so the only counterexample is the wrong order.
    """
    if mode == "f11":
        path = os.path.join(tree, "bench", "store.py")
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        before = """    def record(self, rec):
        \"\"\"Journal first, memory second. The order is the claim: nothing is known here that
        a restart could not also know.\"\"\"
        stored = self.journal.append(rec)
        self.index(stored)
        return stored"""
        after = """    def record(self, rec):
        # The pre-patch order: memory first, journal second.
        self.index(rec)
        return self.journal.append(rec)"""
        if before not in source:
            raise SystemExit("f11: could not find the journal-then-memory ordering")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(source.replace(before, after, 1))
        return

    if mode == "f10":
        path = os.path.join(tree, "bench", "host.py")
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        before = "            if action_id is not None and resp.get(\"action_id\") != action_id:"
        after = "            if False and action_id is not None and resp.get(\"action_id\") != action_id:"
        if before not in source:
            raise SystemExit("f10: could not find the reply check")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(source.replace(before, after, 1))
        return

    if mode == "f19":
        path = os.path.join(tree, "bench", "host.py")
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        before = '            if req.get("cmd") == "verdict":'
        after = '            if False and req.get("cmd") == "verdict":'
        if before not in source:
            raise SystemExit("f19: could not find the acknowledgement requirement")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(source.replace(before, after, 1))
        return

    if mode == "f20":
        path = os.path.join(tree, "verify.py")
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        before = ("    arrived_after_recovery = bool(recovery_boot) and len(boots) > 1 "
                  "and not predates_recovery")
        after = ("    arrived_after_recovery = bool(\n"
                 "        stored_b and boots and stored_b[\"store_seq\"] > max(b[\"store_seq\"] "
                 "for b in boots)\n"
                 "    ) if len(boots) > 1 else False")
        if before not in source:
            raise SystemExit("f20: could not find the recovery-epoch binding")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(source.replace(before, after, 1))
        return

    raise SystemExit("no before-run change for %r" % mode)

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


EXPECTED_ARTIFACTS = ("store.jsonl", "host-A.jsonl", "host-Ap.jsonl", "host-B.jsonl",
                      "host-C.jsonl", "host-Cp.jsonl", "host-Cpp.jsonl", "host-D.jsonl",
                      "host-Dp.jsonl", "wal-B.jsonl", "reconciled.json", "manifest.json",
                      "probe-durability/journal.jsonl", "probe-durability/result.json",
                      "probe-repair/journal.jsonl",
                      "probe-repair/journal.jsonl.quarantine-1.bin",
                      "probe-reply/host-E.jsonl")


def run_suite(repo: str, env: dict | None = None, attempts: int = 3) -> str:
    """Run the suite in a fresh copy and return the directory it wrote.

    The directory is found by looking at what appeared under artifacts/, not by
    parsing what run.py printed: the printed path uses the platform separator,
    and a Windows run and a Linux run should not need different parsing.

    A run that fails partway still leaves its directory behind, so the presence
    of a directory is not evidence that the scenario ran. Each attempt is
    checked for the artifacts a complete run writes, and retried: on Windows,
    the store sometimes needs longer than its ten second budget to announce on
    a freshly copied tree, and one retry is cheaper than a flaky suite.
    """
    artifacts = os.path.join(repo, "artifacts")
    last = ""
    for attempt in range(1, attempts + 1):
        before = set(os.listdir(artifacts)) if os.path.isdir(artifacts) else set()
        proc = subprocess.run([sys.executable, "run.py"], cwd=repo, capture_output=True,
                              text=True, env=env)
        after = set(os.listdir(artifacts)) if os.path.isdir(artifacts) else set()
        new_dirs = sorted(name for name in after - before if name.startswith("run-"))
        if not new_dirs:
            last = "run.py produced no artifact directory (exit %d)" % proc.returncode
            continue
        rundir = os.path.join(artifacts, new_dirs[-1])
        missing = [name for name in EXPECTED_ARTIFACTS
                   if not os.path.exists(os.path.join(rundir, name))]
        if not missing and proc.returncode == 0:
            return rundir
        last = ("run.py exited %d and left %s missing from %s"
                % (proc.returncode, ", ".join(missing) or "nothing", os.path.basename(rundir)))
        time.sleep(1)
    sys.stderr.write(proc.stdout[-1500:] + proc.stderr[-1500:])
    raise SystemExit("the suite did not complete for this mode: %s" % last)


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

    if mode == "f7":
        # Repair kept the bytes; delete them, and the check that says it does must fail.
        for name in os.listdir(os.path.join(rundir, "probe-repair")):
            if ".quarantine-" in name:
                os.remove(os.path.join(rundir, "probe-repair", name))
        return

    if mode == "f9":
        # Remove the conflict record, as a store that resolved duplicates silently would not
        # have written one. The two verdicts stay, so the ambiguity is still in the journal.
        path = os.path.join(rundir, "store.jsonl")
        with open(path, encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
        kept = [row for row in rows if row.get("kind") != "conflict"]
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for row in kept:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
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

    if mode in ("f16", "f17"):
        path = os.path.join(rundir, "store.jsonl")
        with open(path, encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
        seq = max(row.get("store_seq", 0) for row in rows) + 1
        if mode == "f16":
            # An unsigned record whose journal line says it is verified. Nothing signed it and
            # nothing should believe it, but the line is framed correctly, so only the state
            # rule stands between this row and a closed gap.
            row = {"kind": "verdict", "action_id": "C-3003", "state": "verified",
                   "record": {"action_id": "C-3003", "verdict": "ALLOW", "signature": None},
                   "store_seq": seq}
        else:
            # A real, correctly signed record, signed for another action. The signature is not
            # the question; the binding is, and no key is needed to mount the substitution.
            donor = [r for r in rows
                     if r.get("kind") == "verdict" and r.get("action_id") == "D-4004"][0]
            row = {"kind": "verdict", "action_id": "C-3003", "state": "verified",
                   "record": dict(donor["record"]), "store_seq": seq}
        row["digest"] = common.frame(row)
        with open(path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
        return

    if mode == "f18":
        path = os.path.join(rundir, "store.jsonl")
        with open(path, encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
        donor = [r for r in rows
                 if r.get("kind") == "verdict" and r.get("action_id") == "D-4004"][0]
        second = {"kind": "verdict", "action_id": "D-4004",
                  "record": dict(donor["record"], decision_ts=99),
                  "store_seq": max(r.get("store_seq", 0) for r in rows) + 1}
        second["record"]["signature"] = common.sign(common.record_payload(second["record"]))
        second["state"] = "verified"
        second["digest"] = common.frame(second)
        kept = [r for r in rows if r.get("kind") != "conflict"]
        kept.append(second)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for row in kept:
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


# -- the P2 modes that do not fit a single damage-then-verify shape ---------------------------
def fresh_copy(repo: str, name: str) -> str:
    work = tempfile.mkdtemp(prefix="hfb-%s-" % name)
    tree = os.path.join(work, "host-failure-benchmark")
    shutil.copytree(repo, tree, ignore=shutil.ignore_patterns(
        "artifacts", ".git", "__pycache__", "*.pyc"))
    return tree


def append_boot(tree: str, rundir: str) -> None:
    """One more boot record, which is what an ordinary restart after the run leaves behind.

    A store that is started on a finished journal replays it and writes one boot line. This
    writes the same line without starting the store, so the run's own evidence is untouched
    apart from the record a routine restart would have added.
    """
    common = bench_import(tree)
    path = os.path.join(rundir, "store.jsonl")
    with open(path, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
    boot = {"kind": "boot", "replayed_records": len(rows),
            "store_seq": max(row.get("store_seq", 0) for row in rows) + 1}
    boot["digest"] = common.frame(boot)
    with open(path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(boot, sort_keys=True) + "\n")


def custom_f20(repo: str) -> tuple[bool, str]:
    """F-05 in both directions, because a check that fires on a routine restart is not a check.

    First the benign case: the tree as it stands, a valid run, one more boot record, and the
    run still verifies. Then the counterexample: the pre-P2 binding, the same boot record, and
    B fails. One half alone would let either a check that never fires or a check that always
    fires pass as a fix.
    """
    benign_tree = fresh_copy(repo, "f20-benign")
    rundir = run_suite(benign_tree)
    append_boot(benign_tree, rundir)
    run_verify(benign_tree, rundir)
    failed, note = failed_checks(rundir)
    benign = not failed

    old_tree = fresh_copy(repo, "f20-old")
    apply_before_run(old_tree, "f20")
    old_run = run_suite(old_tree)
    append_boot(old_tree, old_run)
    run_verify(old_tree, old_run)
    old_failed, _ = failed_checks(old_run)
    caught = "B" in old_failed

    detail = ("routine restart then verify: failed %s; the pre-P2 binding on the same restart: "
              "failed %s" % (", ".join(sorted(failed)) or "nothing",
                             ", ".join(sorted(old_failed)) or "nothing"))
    return benign and caught, detail


STORE_IO_CASE = r"""
import json, os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "bench"))
import store as S

out = {}
journal = os.path.join(sys.argv[2], "store.jsonl")
real_open, real_fsync = open, os.fsync

s = S.Store(S.Journal(journal))
s.handle({"cmd": "issue", "action_id": "M-1"})
record = {"action_id": "M-1", "verdict": "ALLOW", "signature": None}

def eio(*a, **k):
    raise OSError(5, "Input/output error")

# 1. open() raises while the verdict is being appended
S.open = eio
def attempt():
    try:
        return {"reply": s.handle({"cmd": "verdict", "record": record}), "raised": False}
    except Exception as exc:
        return {"reply": None, "raised": True, "error": repr(exc)}
out["open_eio"] = attempt()
S.open = real_open
out["open_eio"]["live_knows"] = s.handle({"cmd": "lookup", "action_id": "M-1"})["verdict"] is not None
s2 = S.Store(S.Journal(journal))
out["open_eio"]["restart_knows"] = s2.handle({"cmd": "lookup", "action_id": "M-1"})["verdict"] is not None

# 2. fsync raises after the bytes were written
s3 = S.Store(S.Journal(journal))
def bad_fsync(fd):
    raise OSError(5, "Input/output error")
S.os.fsync = bad_fsync
def attempt2():
    try:
        return {"reply": s3.handle({"cmd": "verdict", "record": record}), "raised": False}
    except Exception as exc:
        return {"reply": None, "raised": True, "error": repr(exc)}
out["fsync_eio"] = attempt2()
S.os.fsync = real_fsync
out["fsync_eio"]["live_knows"] = s3.handle({"cmd": "lookup", "action_id": "M-1"})["verdict"] is not None
s4 = S.Store(S.Journal(journal))
out["fsync_eio"]["restart_knows"] = s4.handle({"cmd": "lookup", "action_id": "M-1"})["verdict"] is not None
rows = [json.loads(line) for line in real_open(journal, encoding="utf-8") if line.strip()]
seqs = [row["store_seq"] for row in rows]
out["fsync_eio"]["unique_seq"] = len(seqs) == len(set(seqs))

# 3. a partial line left by something else, then an acknowledged record, then a restart
s5 = S.Store(S.Journal(journal))
with real_open(journal, "ab") as fh:
    fh.write(b'{"kind": "issued", "action_id": "T-2", "dig')
ack = s5.handle({"cmd": "issue", "action_id": "T-3"})
s6 = S.Store(S.Journal(journal))
out["torn_tail"] = {"ack": ack, "survived": "T-3" in s6.handle({"cmd": "state"})["issued"]}

print(json.dumps(out))
"""


def custom_f21(repo: str) -> tuple[bool, str]:
    """F-04, in process, because a failed write cannot be arranged by editing evidence.

    These are the reviewer's V19, V20 and V21 in one mode: an EIO on open, an EIO on fsync after
    the bytes reached the page cache, and a partial line left by something else. Each one asks
    the same question: did the store answer, and do memory and the next restart agree.
    """
    tree = fresh_copy(repo, "f21")
    work = tempfile.mkdtemp(prefix="hfb-f21-journal-")
    script = os.path.join(work, "store_io_case.py")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write(STORE_IO_CASE)
    proc = subprocess.run([sys.executable, script, tree, work], capture_output=True, text=True,
                          timeout=120)
    if proc.returncode != 0:
        return False, "the case did not run: %s" % (proc.stderr or proc.stdout)[-300:]
    out = json.loads(proc.stdout.strip().splitlines()[-1])

    def answered(case):
        reply = case.get("reply") or {}
        return (not case["raised"]) and reply.get("ok") is False and reply.get("durable") is False

    open_ok = answered(out["open_eio"]) and not out["open_eio"]["live_knows"]         and not out["open_eio"]["restart_knows"]
    fsync_case = out["fsync_eio"]
    fsync_ok = answered(fsync_case) and fsync_case["live_knows"] == fsync_case["restart_knows"]         and fsync_case["unique_seq"]
    torn_ok = out["torn_tail"]["survived"] and out["torn_tail"]["ack"].get("ok") is True
    detail = ("open EIO answered %s, fsync EIO answered %s and left memory and disk in step %s, "
              "record after a torn tail survived %s"
              % (open_ok, fsync_ok, fsync_case["live_knows"] == fsync_case["restart_knows"],
                 torn_ok))
    return open_ok and fsync_ok and torn_ok, detail


def fingerprint(rundir: str) -> dict:
    out = {}
    for root, _dirs, files in os.walk(rundir):
        for name in files:
            path = os.path.join(root, name)
            with open(path, "rb") as fh:
                out[os.path.relpath(path, rundir)] = hashlib.sha256(fh.read()).hexdigest()
    return out


def custom_f22(repo: str) -> tuple[bool, str]:
    """F-09, where the subject is the tool rather than the run.

    One directory is not two runs, and a challenge run may not edit the evidence it was pointed
    at. Both were files that looked like results and were not.
    """
    tree = fresh_copy(repo, "f22")
    rundir = run_suite(tree)
    subprocess.run([sys.executable, "verify.py", rundir, rundir], cwd=tree,
                   capture_output=True, text=True)
    with open(os.path.join(rundir, "verify-report.json"), encoding="utf-8") as fh:
        report = json.load(fh)
    determinism = next(row for row in report["checks"] if row["id"] == "determinism")
    refused = (determinism["result"] == "fails"
               and determinism["evidence"].get("same_directory") is not None)

    before = fingerprint(rundir)
    proc = subprocess.run([sys.executable, "challenge.py", rundir], cwd=tree,
                          capture_output=True, text=True, timeout=300)
    after = fingerprint(rundir)
    untouched = before == after
    detail = ("same directory refused: %s; challenge exit %d left the evidence %s"
              % (refused, proc.returncode,
                 "unchanged" if untouched else "changed: %s" % ", ".join(
                     sorted(set(before) ^ set(after)))))
    return refused and untouched and proc.returncode == 0, detail


CUSTOM = {"f20": custom_f20, "f21": custom_f21, "f22": custom_f22}


def run_mode(repo: str, mode: str) -> tuple[bool, str]:
    if MODES[mode][1] == "custom":
        return CUSTOM[mode](repo)
    work = tempfile.mkdtemp(prefix="hfb-regression-")
    tree = os.path.join(work, "host-failure-benchmark")
    shutil.copytree(repo, tree, ignore=shutil.ignore_patterns(
        "artifacts", ".git", "__pycache__", "*.pyc"))
    try:
        env = dict(os.environ)
        if MODES[mode][1] == "mid-run":
            patch_driver(tree)
            env["REGRESSION_MODE"] = mode
        elif MODES[mode][1] == "before-run":
            apply_before_run(tree, mode)
        rundir = run_suite(tree, env)
        detail = ""
        if MODES[mode][1] == "after-run":
            apply_after_run(tree, rundir, mode)

        if mode in ("f3", "f16", "f17"):
            # The assertion is not a failing check: a forged verdict must not erase a gap.
            proc, port = start_store(tree, rundir)
            try:
                gaps = gap_names(port)
            finally:
                stop_store(proc)
            kept = "C-3003" in gaps
            return kept, "C-3003 still named as a gap after a restart on that journal: %s" % (
                "yes" if kept else "no, the row closed the gap")

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
