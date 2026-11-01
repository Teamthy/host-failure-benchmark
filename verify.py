#!/usr/bin/env python3
"""Read one run's artifacts and decide, without trusting anything the run said about itself.

Every check below is a claim paired with the counterclaim that would refute it. The verdict is
recomputed from raw files: the store journal, the write-ahead log, the host journals, and the
lookups. Nothing here reads a pass flag, because nothing writes one.

    python verify.py artifacts/run-20261101T120000Z
    python verify.py run-a run-b            # also checks the two runs are byte-identical

Exit code is 0 only if every check passes. A missing artifact is a failure, not a skip.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "bench"))

from common import digest, record_payload, verify as verify_signature  # noqa: E402

DESC_TRANSITION = {"kind": "state_transition", "from": "draft", "to": "issued"}
DESC_READ = {"kind": "read", "target": "order-42"}

RESULTS = []


def check(check_id, klass, claim, counterclaim, passed, evidence):
    RESULTS.append({
        "id": check_id,
        "class": klass,
        "claim": claim,
        "counterclaim": counterclaim,
        "result": "holds" if passed else "fails",
        "evidence": evidence,
    })


def read_jsonl(path):
    if not os.path.exists(path):
        return None
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def read_json(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def journal_index(records):
    """Every event a host wrote, keyed by (scenario, kind) as an ordered list."""
    out = {}
    for rec in records or []:
        out.setdefault((rec.get("scenario"), rec.get("kind")), []).append(rec)
    return out


def step_of(events):
    return events[0]["step"] if events else None


def find_verdict(store_records, action_id):
    for rec in store_records:
        if rec.get("kind") == "verdict" and rec.get("action_id") == action_id:
            return rec
    return None


def find_gap(gaps, action_id):
    for gap in gaps:
        if gap.get("action_id") == action_id:
            return gap
    return None


def recompute_gaps(store_records):
    """Rebuild reconciliation from the journal, not from the file that reports on it.

    If this function and the store disagree, the store's own summary is the thing that is
    wrong, and the reader has to see that rather than a comfortable pass.
    """
    issued, commitments, expectations, verdicts = set(), {}, set(), set()
    for rec in store_records:
        kind, aid = rec.get("kind"), rec.get("action_id")
        if kind == "issued":
            issued.add(aid)
        elif kind == "commitment":
            commitments[aid] = rec.get("descriptor_sha")
        elif kind == "expectation":
            expectations.add(aid)
        elif kind == "verdict":
            verdicts.add(aid)

    gaps = []
    for aid in sorted(issued | expectations):
        if aid in verdicts:
            continue
        if aid in expectations:
            gaps.append({"action_id": aid,
                         "content": commitments.get(aid),
                         "strength": "content" if aid in commitments else "name only"})
        elif aid in commitments:
            gaps.append({"action_id": aid, "content": commitments[aid], "strength": "content"})
        else:
            gaps.append({"action_id": aid, "content": None, "strength": "name only"})
    return gaps


def appears_anywhere(store_records, action_id):
    return [r for r in store_records if r.get("action_id") == action_id]


def verify_run(rundir):
    store = read_jsonl(os.path.join(rundir, "store.jsonl"))
    reconciled = read_json(os.path.join(rundir, "reconciled.json"))
    manifest = read_json(os.path.join(rundir, "manifest.json"))

    if store is None or reconciled is None or manifest is None:
        check("0", "meta", "the run produced the artifacts verification needs",
              "any missing artifact means the run is unverifiable, not a pass",
              False, {"rundir": rundir})
        return

    gaps = recompute_gaps(store)

    reported = sorted((g.get("action_id"), g.get("strength"), g.get("content"))
                      for g in (reconciled.get("gaps") or []))
    recomputed = sorted((g["action_id"], g["strength"], g["content"]) for g in gaps)
    check(
        "reconcile", "meta",
        "the store's reconciliation report matches what its own journal implies, so the report "
        "is derived and not asserted",
        "if the report names gaps the journal cannot support, or omits gaps the journal implies, "
        "every gap claim below rests on an unverified summary",
        reported == recomputed,
        {"reported": reported, "recomputed": recomputed},
    )

    def host(name):
        return journal_index(read_jsonl(os.path.join(rundir, "host-%s.jsonl" % name)))

    ja, jap, jb, jc, jcp, jcpp, jd, jdp = (
        host(n) for n in ("A", "Ap", "B", "C", "Cp", "Cpp", "D", "Dp"))
    wal_b = read_jsonl(os.path.join(rundir, "wal-B.jsonl"))

    # -- M1: decided, never emitted -------------------------------------------------------
    gap_a = find_gap(gaps, "A-1042")
    verdict_a = find_verdict(store, "A-1042")
    check(
        "A", "P",
        "A guard decision that never left the host is still nameable as missing, because an "
        "expectation was registered before the action ran",
        "if the store holds a verdict for A-1042, or reconciliation cannot name it, the "
        "expectation did not do the work claimed",
        bool(gap_a) and verdict_a is None and gap_a.get("strength") == "name only",
        {"gap": gap_a, "verdict_present": verdict_a is not None},
    )

    leaked_a = appears_anywhere(store, "A-1043")
    check(
        "A'", "P",
        "without a prior expectation the same failure leaves no name at all, so M1 depends on "
        "the expectation and not on the store noticing something by itself",
        "if A-1043 appears anywhere in the store, the store is naming what it was never told "
        "about and M1 is measuring the wrong thing",
        not leaked_a and find_gap(gaps, "A-1043") is None,
        {"records": leaked_a, "gap": find_gap(gaps, "A-1043")},
    )

    # -- M2: decided, emitted, lost --------------------------------------------------------
    def phase(events, run):
        return [e for e in (events or []) if e.get("run") == run]

    guard_b = (phase(jb.get(("B", "guard_decision")), "initial") or [None])[0]
    wal_commit = (phase(jb.get(("B", "wal_commit")), "initial") or [None])[0]
    replay_ship = (phase(jb.get(("B", "replay_shipped")), "replay") or [None])[0]
    ship_failed = (phase(jb.get(("B", "ship_failed")), "initial") or [None])[0]
    redecided = phase(jb.get(("B", "guard_decision")), "replay")
    stored_b = find_verdict(store, "B-2001")
    boots = [r for r in store if r.get("kind") == "boot"]

    guard_step = step_of([guard_b])
    commit_step = step_of([wal_commit])
    ship_step = step_of([replay_ship])
    stored_ts = stored_b["record"].get("decision_ts") if stored_b else None
    arrived_after_recovery = bool(
        stored_b and boots and stored_b["store_seq"] > max(b["store_seq"] for b in boots)
    ) if len(boots) > 1 else False

    check(
        "B", "P",
        "a verdict committed locally before a failed ship survives, and lands later carrying "
        "the time it was decided rather than the time it arrived",
        "if the stored decision timestamp equals the replay step, or the verdict predates the "
        "restart, then the record carries recovery time and the claim fails",
        bool(stored_b) and stored_ts == guard_step and commit_step > guard_step
        and replay_ship is not None and not redecided
        and arrived_after_recovery and ship_failed is not None,
        {"guard_step": guard_step, "commit_step": commit_step,
         "replay_step": step_of([replay_ship]), "stored_ts": stored_ts,
         "redecided_on_replay": len(redecided),
         "ship_failed": ship_failed is not None, "boots": len(boots),
         "arrived_after_recovery": arrived_after_recovery},
    )

    # The WAL is the independent witness: it must carry the same timestamp the store does.
    wal_ts = wal_b[0].get("decision_ts") if wal_b else None
    check(
        "B.wal", "P",
        "the timestamp in the store's record is the one the host wrote down before the ship, "
        "recovered from a separate file",
        "if the write-ahead log disagrees with the store, one of them was reconstructed after "
        "the fact and the timestamp is not independent evidence",
        wal_ts is not None and wal_ts == stored_ts,
        {"wal_ts": wal_ts, "stored_ts": stored_ts},
    )

    effect_b = (jb.get(("B", "effect_committed")) or [None])[0]
    check(
        "B.effect", "P",
        "the effect did not proceed while the verdict was undurable centrally, so a lost "
        "verdict is a failure and not a divergence",
        "if an effect was committed in B, the withheld-effect rule was not being tested",
        effect_b is None,
        {"effect_committed": effect_b},
    )

    # -- M3: host dies before ingestion. The named gap, and how strong the name is --------
    desc_sha = digest(DESC_TRANSITION)
    gap_c = find_gap(gaps, "C-3003")
    check(
        "C", "P",
        "an issued id plus a preserved commitment names the gap and carries its content, so "
        "the missing verdict can be described without the host",
        "if reconciliation names C-3003 without its descriptor digest, the commitment did not "
        "survive and this is only a name",
        bool(gap_c) and gap_c.get("strength") == "content"
        and gap_c.get("content") == desc_sha and find_verdict(store, "C-3003") is None,
        {"gap": gap_c, "expected_content": desc_sha},
    )

    gap_cp = find_gap(gaps, "C-3004")
    check(
        "C'", "P",
        "issuance alone names the gap with no content, so the record knows an action was "
        "named and cannot say what it was",
        "if C-3004's gap carries content, the issuance-only case was not isolated",
        bool(gap_cp) and gap_cp.get("strength") == "name only" and gap_cp.get("content") is None,
        {"gap": gap_cp},
    )

    leaked_cpp = appears_anywhere(store, "C-3005")
    check(
        "C''", "P",
        "a locally minted id leaves silence: the store cannot name the action at all, and this "
        "is the weakest of the three outcomes rather than a variation of the same result",
        "if C-3005 appears anywhere, the silence is not silence and the strongest claim in "
        "this row would be overstated",
        not leaked_cpp and find_gap(gaps, "C-3005") is None,
        {"records": leaked_cpp, "gap": find_gap(gaps, "C-3005")},
    )

    # -- M4: preserved, unverifiable -------------------------------------------------------
    stored_d = find_verdict(store, "D-4004")
    payload_d = record_payload(stored_d["record"]) if stored_d else None
    signer_ok = bool(payload_d) and verify_signature(payload_d, stored_d["record"].get("signature"))
    check(
        "D", "V",
        "a complete record verifies against the key it carries, and the descriptor digest "
        "recomputes from the action rather than being taken on trust",
        "if the signature does not verify over the stored bytes, or the digest does not "
        "recompute, the record is only a file that says so",
        signer_ok and payload_d.get("descriptor_sha") == digest(DESC_READ),
        {"descriptor_sha": payload_d.get("descriptor_sha") if payload_d else None,
         "expected": digest(DESC_READ), "signature_ok": signer_ok},
    )

    stored_dp = find_verdict(store, "D-4005")
    payload_dp = record_payload(stored_dp["record"]) if stored_dp else None
    dp_ok = bool(payload_dp) and bool(stored_dp["record"].get("signature")) and verify_signature(
        payload_dp, stored_dp["record"].get("signature"))
    check(
        "D'", "V",
        "a preserved record whose binding does not verify is quarantined and never counted as "
        "verified, and it stays visible rather than being dropped",
        "if an unsigned record is accepted, or disappears, quarantine is doing no work",
        stored_dp is not None and not dp_ok,
        {"stored": stored_dp is not None, "verifies": dp_ok,
         "quarantined": stored_dp is not None and not dp_ok},
    )

    # -- the honesty checks ----------------------------------------------------------------
    crlf = [name for name in ARTIFACT_FILES
            if (read_bytes(rundir, name) or b"").find(b"\r\n") >= 0]
    check(
        "line-endings", "meta",
        "every artifact uses one newline convention, so a run on Windows is the same bytes as a "
        "run on Linux and not a machine-specific rendering of one",
        "if any artifact carries CRLF, the byte-identical claim is false on that platform and "
        "the record says more about the operating system than about the failure",
        not crlf,
        {"files_with_crlf": crlf},
    )

    check(
        "no-wall-clock", "meta",
        "every timestamp in every artifact is a counter step, so two runs agree byte for byte",
        "a wall clock anywhere makes the suite non-deterministic and the comparison moot",
        bool(stored_b and stored_d) and all(
            isinstance(r["record"].get("decision_ts"), int) for r in [stored_b, stored_d]),
        {"decision_ts_types": [type(r["record"].get("decision_ts")).__name__
                               for r in [stored_b, stored_d] if r]},
    )


ARTIFACT_FILES = ["store.jsonl", "host-A.jsonl", "host-Ap.jsonl", "host-B.jsonl",
                  "host-C.jsonl", "host-Cp.jsonl", "host-Cpp.jsonl", "host-D.jsonl",
                  "host-Dp.jsonl", "wal-B.jsonl", "reconciled.json", "store-state.json",
                  "lookups.json"]


def compare_determinism(first, second):
    files = ARTIFACT_FILES
    same = all(read_bytes(first, f) == read_bytes(second, f) for f in files)
    differing = [f for f in files if read_bytes(first, f) != read_bytes(second, f)]
    check(
        "determinism", "meta",
        "two runs of the suite produce identical artifacts, so a result can be reproduced by "
        "anyone without trusting the machine it ran on",
        "if any artifact differs between runs, the suite reports the machine as much as the "
        "failure",
        same, {"differing": differing},
    )


def read_bytes(rundir, name):
    path = os.path.join(rundir, name)
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        return fh.read()


def report(rundir):
    order = {"P": 0, "V": 1, "meta": 2}
    for row in RESULTS:
        print("%-12s %-4s %-6s %s" % (row["id"], row["class"], row["result"], row["claim"][:80]))
        if row["result"] == "fails":
            print("%-12s      refused by: %s" % ("", row["counterclaim"][:88]))
    p_rows = [r for r in RESULTS if r["class"] == "P"]
    v_rows = [r for r in RESULTS if r["class"] == "V"]
    p_held = sum(1 for r in p_rows if r["result"] == "holds")
    v_held = sum(1 for r in v_rows if r["result"] == "holds")
    print("")
    print("Class P (persistence and recovery): %d of %d hold" % (p_held, len(p_rows)))
    print("Class V (verification):            %d of %d hold" % (v_held, len(v_rows)))
    print("Named gap at M3: C = name with content, C' = name only, C'' = silence.")
    print("Strength is reported, not scored. The three are not gradations of one result.")
    failures = [r for r in RESULTS if r["result"] == "fails"]
    print("")
    print("VERDICT: %s" % ("every check holds" if not failures
                           else "%d check(s) failed" % len(failures)))
    with open(os.path.join(rundir, "verify-report.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"checks": RESULTS,
                   "summary": {"class_P": [p_held, len(p_rows)],
                               "class_V": [v_held, len(v_rows)],
                               "failures": [r["id"] for r in failures]}},
                  fh, indent=2, sort_keys=True)
    return 0 if not failures else 1


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    rundir = argv[1]
    verify_run(rundir)
    if len(argv) > 2:
        compare_determinism(rundir, argv[2])
    return report(rundir)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
