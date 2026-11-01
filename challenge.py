#!/usr/bin/env python3
"""Break the artifacts on purpose and confirm verification notices.

A checker that cannot fail is a decoration. This script takes a finished run, damages the record
in ten specific ways, and requires that the damage be caught by the check that claims to catch
it. If a mutation slips through, the check it targets is not measuring what it says it measures.

It also does two things that are not mutations, because verification can fail in the other
direction: it points the verifier at a directory that is not a run, and it compares a run against
a copy that is missing artifacts. A verifier that raises on the first, or calls the second
identical, has reported on nothing.

    python challenge.py artifacts/run-20261101T120000Z

Exit code is 0 only if every mutation was caught by its expected check.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "bench"))

from common import frame, record_payload, sign  # noqa: E402

VERIFY = os.path.join(HERE, "verify.py")


def load_store(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def save_store(path, records):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")


def copy_run(rundir, work):
    """Copy the whole run, probe directories included.

    Copying only the top level of files left every mutation looking like a run with missing
    probes, which made some checks fail for a reason that had nothing to do with the damage.
    """
    for root, dirs, files in os.walk(rundir):
        rel = os.path.relpath(root, rundir)
        target = work if rel == "." else os.path.join(work, rel)
        os.makedirs(target, exist_ok=True)
        for name in files:
            shutil.copy2(os.path.join(root, name), os.path.join(target, name))


def renumber(records):
    """Resequence and reframe.

    Editing a journal without recomputing its frames would make every mutation fail the frame
    check, and a mutation that is caught for the wrong reason has not tested the check it names.
    The one mutation that is supposed to leave a stale frame breaks it afterwards, on the file.
    """
    for index, rec in enumerate(records, start=1):
        rec["store_seq"] = index
        rec["digest"] = frame(rec)
    return records


# -- the mutations ---------------------------------------------------------------------------
# Each takes the list of store records and returns the damaged list, plus a sentence a reader
# can check against the run.

def stamp_at_replay(records):
    """The timestamp the record carries is the moment it arrived, not the moment it was decided."""
    for rec in records:
        if rec.get("kind") == "verdict" and rec.get("action_id") == "B-2001":
            rec["record"]["decision_ts"] = 99
    return records, "B-2001 now claims a decision time it never had"


def drop_expectation(records):
    """Nothing promised to look for A-1042, so its absence stops being nameable."""
    return ([r for r in records
             if not (r.get("kind") == "expectation" and r.get("action_id") == "A-1042")],
            "the expectation for A-1042 is gone")


def name_the_silence(records):
    """The store is given a name for the action it was never told about."""
    records.append({"kind": "issued", "action_id": "C-3005"})
    return records, "C-3005 was never issued, but the store now holds it"


def rewrite_content(records):
    """The preserved commitment no longer matches the action it commits to."""
    for rec in records:
        if rec.get("kind") == "commitment" and rec.get("action_id") == "C-3003":
            rec["descriptor_sha"] = "sha256:" + "0" * 64
    return records, "the commitment for C-3003 was swapped for a wrong digest"


def bless_the_unbound(records):
    """The unsigned record is handed a valid binding it never had when it arrived."""
    for rec in records:
        if rec.get("kind") == "verdict" and rec.get("action_id") == "D-4005":
            rec["record"]["signature"] = sign(record_payload(rec["record"]))
    return records, "D-4005 was signed after the fact"


def dirty_the_signature(records):
    """One byte changes in a signature that used to verify."""
    for rec in records:
        if rec.get("kind") == "verdict" and rec.get("action_id") == "D-4004":
            sig = rec["record"]["signature"]
            rec["record"]["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    return records, "one byte of D-4004's binding was altered"


def crlf_the_journal(records):
    """The journal is rewritten the way a Windows text mode would rewrite it."""
    return records, "the store journal now carries CRLF, as Windows text mode writes it"


def torn_tail(records):
    """A crash in the middle of a write: the last record stops halfway through."""
    return records, "the last record in the journal was cut in half"


def cut_tail(path):
    with open(path, "rb") as fh:
        data = fh.read()
    with open(path, "wb") as fh:
        fh.write(data[: len(data) - 40])


def drop_conflict(records):
    """The store keeps both verdicts and drops the record saying they disagree."""
    return ([r for r in records if r.get("kind") != "conflict"],
            "the conflict record between the two verdicts for C-9009 is gone")


def break_a_frame(records):
    """A record is edited and its frame is left as it was, as a careless editor would leave it.

    The edit happens in `stale_frame`, after the journal has been reframed, so the only thing
    damaged is the frame itself.
    """
    return records, "an expectation was edited and its frame was not recomputed"


def stale_frame(path):
    rows = load_store(path)
    for row in rows:
        if row.get("kind") == "expectation":
            row["policy_sha"] = "sha256:" + "f" * 64
            break
    save_store(path, rows)


def to_crlf(path):
    with open(path, "rb") as fh:
        data = fh.read()
    with open(path, "wb") as fh:
        fh.write(data.replace(b"\n", b"\r\n"))


MUTATIONS = [
    ("stamp-at-replay", stamp_at_replay, {"B"}),
    ("drop-expectation", drop_expectation, {"A"}),
    ("name-the-silence", name_the_silence, {"C''"}),
    ("rewrite-content", rewrite_content, {"C"}),
    ("bless-the-unbound", bless_the_unbound, {"D'"}),
    ("dirty-the-signature", dirty_the_signature, {"D"}),
    ("crlf-the-journal", (crlf_the_journal, to_crlf), {"line-endings"}),
    ("torn-tail", (torn_tail, cut_tail), {"artifacts-readable"}),
    ("break-a-frame", (break_a_frame, stale_frame), {"store-records-framed"}),
    ("drop-conflict", drop_conflict, {"conflict"}),
]


def copy_of(rundir):
    work = tempfile.mkdtemp(prefix="challenge-copy-")
    copy_run(rundir, work)
    return work


def baseline(rundir):
    """Verify a copy. The directory you point this script at is evidence, and evidence is not
    where a report about it belongs: a failed report left in the run directory is a file that
    looks like a verdict on a run nobody judged."""
    work = copy_of(rundir)
    try:
        proc = subprocess.run([sys.executable, VERIFY, work], capture_output=True, text=True)
        if proc.returncode != 0:
            raise SystemExit("the run you pointed me at does not verify already:\n" + proc.stdout)
        with open(os.path.join(work, "verify-report.json"), encoding="utf-8") as fh:
            return {row["id"] for row in json.load(fh)["checks"] if row["result"] == "holds"}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run_mutation(rundir, name, mutate):
    work = tempfile.mkdtemp(prefix="challenge-%s-" % name)
    copy_run(rundir, work)
    store_path = os.path.join(work, "store.jsonl")
    post = None
    if isinstance(mutate, tuple):
        mutate, post = mutate
    records, note = mutate(load_store(store_path))
    save_store(store_path, renumber(records))
    if post:
        post(store_path)

    proc = subprocess.run([sys.executable, VERIFY, work], capture_output=True, text=True)
    report_path = os.path.join(work, "verify-report.json")
    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)
    failed = {row["id"] for row in report["checks"] if row["result"] == "fails"}
    shutil.rmtree(work, ignore_errors=True)
    return note, failed, proc.returncode


def input_checks(rundir):
    """The two ways of asking the verifier about something that is not a run.

    Both were defects found on 1 November by mistyping a path. Neither is a claim about the
    benchmark; both are claims the documentation makes about the verifier, which is why they
    are tested here rather than in the regression suite.
    """
    results = []

    # A fixed path is not a missing path. The earlier version named one constant, so a directory
    # with that name in the temp directory turned "a directory that is not there" into a
    # directory that was, and the check stopped testing what it says it tests.
    missing = os.path.join(tempfile.mkdtemp(prefix="hfb-absent-"), "not-a-run")
    proc = subprocess.run([sys.executable, VERIFY, missing], capture_output=True, text=True)
    said = (proc.stdout or proc.stderr).strip().splitlines()
    results.append((
        "verifier on a directory that is not there",
        proc.returncode == 2 and "no run directory" in proc.stdout
        and "Traceback" not in proc.stderr and "Traceback" not in proc.stdout,
        "exit %d, %s" % (proc.returncode, said[-1] if said else "no output"),
    ))

    first, second = copy_of(rundir), copy_of(rundir)
    for name in ("host-D.jsonl", "probe-reply/host-E.jsonl"):
        path = os.path.join(second, name)
        if os.path.exists(path):
            os.remove(path)
    subprocess.run([sys.executable, VERIFY, first, second], capture_output=True, text=True)
    with open(os.path.join(first, "verify-report.json"), encoding="utf-8") as fh:
        rows = {row["id"]: row["result"] for row in json.load(fh)["checks"]}
    results.append((
        "determinism against a run with artifacts missing",
        rows.get("determinism") == "fails",
        "determinism %s" % rows.get("determinism"),
    ))
    shutil.rmtree(first, ignore_errors=True)
    shutil.rmtree(second, ignore_errors=True)
    return results


def fingerprint(rundir):
    """Every file under the run directory, by relative path and content digest."""
    out = {}
    for root, _dirs, files in os.walk(rundir):
        for name in files:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, rundir)
            with open(path, "rb") as fh:
                out[rel] = hashlib.sha256(fh.read()).hexdigest()
    return out


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    rundir = argv[1]
    before = fingerprint(rundir)
    holds_before = baseline(rundir)
    print("baseline: %d checks hold" % len(holds_before))
    print("")

    missed = []
    for name, mutate, expected in MUTATIONS:
        note, failed, code = run_mutation(rundir, name, mutate)
        caught_by = expected & failed
        ok = bool(caught_by)
        print("%-20s %-7s %s" % (name, "caught" if ok else "MISSED", note))
        print("%-20s         failed: %s" % ("", ", ".join(sorted(failed)) or "nothing"))
        if not ok:
            missed.append((name, sorted(failed), code))

    print("")
    input_missed = []
    for name, held, detail in input_checks(rundir):
        print("%-54s %-7s %s" % (name, "held" if held else "MISSED", detail))
        if not held:
            input_missed.append(name)

    after = fingerprint(rundir)
    touched = sorted(set(before) ^ set(after)) + sorted(
        name for name in set(before) & set(after) if before[name] != after[name])
    print("%-54s %-7s %s" % ("the run you pointed me at is unchanged",
                             "held" if not touched else "MISSED",
                             ", ".join(touched) or "no file added, removed or rewritten"))
    if touched:
        input_missed.append("evidence directory left changed: %s" % ", ".join(touched))

    print("")
    if missed:
        for name, failed, code in missed:
            print("UNDETECTED: %s (verify exit %s, failed: %s)"
                  % (name, code, ", ".join(failed) or "nothing"))
        print("A mutation that verification does not catch is a claim it does not support.")
        return 1
    if input_missed:
        print("NOT REFUSED: %s" % ", ".join(input_missed))
        print("Something that is not a run was not refused as something that is not a run.")
        return 1
    print("Every mutation was caught by the check that claims to catch it.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
