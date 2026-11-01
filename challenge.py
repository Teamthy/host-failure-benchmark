#!/usr/bin/env python3
"""Break the artifacts on purpose and confirm verification notices.

A checker that cannot fail is a decoration. This script takes a finished run, damages the record
in seven specific ways, and requires that the damage be caught by the check that claims to catch
it. If a mutation slips through, the check it targets is not measuring what it says it measures.

    python challenge.py artifacts/run-20261101T120000Z

Exit code is 0 only if every mutation was caught by its expected check.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "bench"))

from common import record_payload, sign  # noqa: E402

VERIFY = os.path.join(HERE, "verify.py")


def load_store(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def save_store(path, records):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")


def renumber(records):
    for index, rec in enumerate(records, start=1):
        rec["store_seq"] = index
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
]


def baseline(rundir):
    proc = subprocess.run([sys.executable, VERIFY, rundir], capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit("the run you pointed me at does not verify already:\n" + proc.stdout)
    with open(os.path.join(rundir, "verify-report.json"), encoding="utf-8") as fh:
        return {row["id"] for row in json.load(fh)["checks"] if row["result"] == "holds"}


def run_mutation(rundir, name, mutate):
    work = tempfile.mkdtemp(prefix="challenge-%s-" % name)
    for entry in os.listdir(rundir):
        src = os.path.join(rundir, entry)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(work, entry))
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


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    rundir = argv[1]
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
    if missed:
        for name, failed, code in missed:
            print("UNDETECTED: %s (verify exit %s, failed: %s)"
                  % (name, code, ", ".join(failed) or "nothing"))
        print("A mutation that verification does not catch is a claim it does not support.")
        return 1
    print("Every mutation was caught by the check that claims to catch it.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
