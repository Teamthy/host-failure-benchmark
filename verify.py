#!/usr/bin/env python3
"""Read one run's artifacts and decide, without trusting anything the run said about itself.

Every check below is a claim paired with the counterclaim that would refute it. The verdict is
recomputed from raw files: the store journal, the write-ahead log, the host journals, and the
lookups. Nothing here reads a pass flag, because nothing writes one.

    python verify.py artifacts/run-20261101T120000Z
    python verify.py run-a run-b            # also checks the two runs are byte-identical

Exit code is 0 only if every check passes. A missing artifact is a failure, not a skip.
"""

import hashlib
import hmac
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "bench"))

from common import (DECIDED_BY, POLICY_SHA, bound_state, digest, frame,  # noqa: E402
                    record_payload,
                    verify as verify_signature)

DESC_TRANSITION = {"kind": "state_transition", "from": "draft", "to": "issued"}
DESC_READ = {"kind": "read", "target": "order-42"}

RESULTS = []


def hmac_compare(a, b):
    return hmac.compare_digest(a, b)


def check(check_id, klass, claim, counterclaim, passed, evidence):
    RESULTS.append({
        "id": check_id,
        "class": klass,
        "claim": claim,
        "counterclaim": counterclaim,
        "result": "holds" if passed else "fails",
        "evidence": evidence,
    })


class Unreadable(Exception):
    """An artifact that cannot be parsed. Reported as a failed check, never as a traceback."""

    def __init__(self, path, line_no, detail):
        super().__init__(detail)
        self.path = path
        self.line_no = line_no
        self.detail = detail


def read_jsonl(path):
    if not os.path.exists(path):
        return None
    out = []
    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError as exc:
                raise Unreadable(path, line_no, str(exc))
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
    # None is filtered rather than dereferenced: a missing event used to raise here, and a
    # verifier that raises reports nothing about the run it was asked about.
    present = [e for e in (events or []) if e]
    return present[0]["step"] if present else None


def verdict_state(row):
    """verified, unverified or unbound, recomputed from the record and never read off a field.

    The journal can say whatever it likes about a record's state. This is the check, so it
    recomputes from the bytes that are actually there, and it uses the same definition the
    store uses: a record signed for another action does not resolve the action it is filed
    under.
    """
    row = row or {}
    return bound_state(row.get("record"), row.get("action_id"))


def find_verdict(store_records, action_id, state=None):
    for rec in store_records:
        if rec.get("kind") == "verdict" and rec.get("action_id") == action_id:
            if state is None or verdict_state(rec) == state:
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
    issued, commitments, expectations = set(), {}, set()
    verdict_rows = {}
    for rec in store_records:
        kind, aid = rec.get("kind"), rec.get("action_id")
        if kind == "issued":
            issued.add(aid)
        elif kind == "commitment":
            commitments[aid] = rec.get("descriptor_sha")
        elif kind == "expectation":
            expectations.add(aid)
        elif kind == "verdict":
            verdict_rows.setdefault(aid, []).append(rec)

    # A record that exists is not a decision that is known. Only a verdict whose binding
    # verifies closes a gap, and two verdicts that disagree close nothing: whichever one a
    # reader happened to load first must not become the answer.
    verdicts = set()
    for aid, rows in verdict_rows.items():
        first = rows[0]
        if any(row.get("record") != first.get("record") for row in rows[1:]):
            continue
        if verdict_state(first) == "verified" and first.get("action_id") == aid:
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
    """Never raises. A verifier that falls over has not failed the run, it has failed."""
    try:
        _verify_run(rundir)
    except Unreadable as exc:
        if not _already_reported("artifacts-readable"):
            check(
                "artifacts-readable", "meta",
                "an artifact that cannot be parsed is reported as a damaged run, not as a crash "
                "in the tool that was supposed to judge it",
                "if verification itself falls over, a torn file is indistinguishable from a "
                "broken checker",
                False,
                {"file": os.path.basename(exc.path), "line": exc.line_no,
                 "detail": exc.detail},
            )
    except Exception as exc:  # noqa: BLE001 - the point is that nothing escapes
        check(
            "verifier", "meta",
            "the verifier always reaches a verdict about the run, even when the run is damaged "
            "in a way it did not anticipate",
            "an unhandled exception leaves no report, so a broken artifact and a broken checker "
            "look the same to whoever reads the result",
            False,
            {"error": "%s: %s" % (type(exc).__name__, exc)},
        )


def _already_reported(check_id):
    return any(row["id"] == check_id for row in RESULTS)


def _verify_run(rundir):
    try:
        store = read_jsonl(os.path.join(rundir, "store.jsonl"))
    except Unreadable as exc:
        check(
            "artifacts-readable", "meta",
            "every artifact parses, so an unreadable record is reported as a damaged run rather "
            "than as a crash in the tool that was supposed to judge it",
            "if verification itself falls over, the run has no verdict at all and a torn journal "
            "is indistinguishable from a broken checker",
            False,
            {"file": os.path.basename(exc.path), "line": exc.line_no, "detail": exc.detail},
        )
        return
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

    unreadable = []

    def host(name):
        path = os.path.join(rundir, "host-%s.jsonl" % name)
        try:
            return journal_index(read_jsonl(path))
        except Unreadable as exc:
            unreadable.append({"file": os.path.basename(path), "line": exc.line_no,
                               "detail": exc.detail})
            return {}

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
        bool(gap_a) and find_verdict(store, "A-1042", state="verified") is None
        and gap_a.get("strength") == "name only",
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
    # The epoch the verdict landed in is the one opened by the boot record in front of it, not
    # the last boot in the file. A store that restarts again after the run is a routine restart
    # and says nothing about when the verdict arrived; binding B to "after the latest boot"
    # turned that into a false accusation that the verdict predated recovery.
    boots_before_b = ([b for b in boots if (b.get("store_seq") or 0) < (stored_b.get("store_seq") or 0)]
                      if stored_b else [])
    recovery_boot = max(boots_before_b, key=lambda b: b.get("store_seq") or 0) if boots_before_b else None
    predates_recovery = bool(recovery_boot) and any(
        r.get("kind") == "verdict" and r.get("action_id") == "B-2001"
        and (r.get("store_seq") or 0) < (recovery_boot.get("store_seq") or 0) for r in store)
    arrived_after_recovery = bool(recovery_boot) and len(boots) > 1 and not predates_recovery

    wal_record = wal_b[0] if wal_b else None
    # The independent witness, read before the check that needs it rather than after.
    wal_ts = wal_record.get("decision_ts") if wal_record else None
    wal_sig_ok = bool(wal_record) and isinstance(wal_record.get("signature"), str) and \
        verify_signature(record_payload(wal_record), wal_record.get("signature"))
    stored_b_state = verdict_state(stored_b)
    check(
        "B", "P",
        "a verdict committed locally before a failed ship survives, and lands later carrying "
        "the time it was decided rather than the time it arrived",
        "if the stored decision timestamp equals the replay step, or the verdict predates the "
        "restart, then the record carries recovery time and the claim fails",
        bool(stored_b) and stored_ts == guard_step and stored_ts == wal_ts and commit_step > guard_step
        and replay_ship is not None and not redecided
        and arrived_after_recovery and ship_failed is not None
        and stored_b_state == "verified" and wal_sig_ok,
        {"guard_step": guard_step, "commit_step": commit_step,
         "replay_step": step_of([replay_ship]), "stored_ts": stored_ts,
         "redecided_on_replay": len(redecided),
         "ship_failed": ship_failed is not None, "boots": len(boots),
         "recovery_boot_seq": (recovery_boot or {}).get("store_seq"),
         "verdict_predates_recovery": predates_recovery,
         "arrived_after_recovery": arrived_after_recovery,
         "stored_verdict_state": stored_b_state, "wal_signature_ok": wal_sig_ok},
    )

    # The decision that survived has to be the decision that was made. The host's own journal is
    # the only artifact that records the guard's answer at the time, and nothing here compared
    # the two: a record that was rewritten before it was shipped carried a timestamp nobody
    # questioned because every other field agreed with itself.
    check(
        "B.decision", "P",
        "the verdict that survived recovery is the decision the host recorded when it made it, "
        "so the record that landed is that decision and not a later rewrite of it",
        "if the stored verdict or its rule differs from the guard decision in the host journal, "
        "the record that survived is not the decision that was made",
        bool(stored_b) and bool(guard_b)
        and (stored_b.get("record") or {}).get("verdict") == guard_b.get("verdict")
        and (stored_b.get("record") or {}).get("rule") == guard_b.get("rule"),
        {"stored_verdict": (stored_b.get("record") or {}).get("verdict") if stored_b else None,
         "guard_verdict": (guard_b or {}).get("verdict"),
         "stored_rule": (stored_b.get("record") or {}).get("rule") if stored_b else None,
         "guard_rule": (guard_b or {}).get("rule")},
    )

    # The WAL is the independent witness: it must carry the same timestamp the store does.
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
        and gap_c.get("content") == desc_sha
        and find_verdict(store, "C-3003", state="verified") is None,
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
    decided_ok = bool(payload_d) and payload_d.get("decided_by") == DECIDED_BY
    policy_ok = bool(payload_d) and payload_d.get("policy_sha") == POLICY_SHA
    guard_d_step = step_of(jd.get(("D", "guard_decision")))
    ts_bound_ok = bool(payload_d) and payload_d.get("decision_ts") == guard_d_step
    check(
        "D", "V",
        "a complete record verifies against the key it carries, and the descriptor digest "
        "recomputes from the action rather than being taken on trust",
        "if the signature does not verify over the stored bytes, or the digest does not "
        "recompute, the record is only a file that says so; if the same journal lists D-4004 "
        "as an unresolved gap, then this check and the reconciliation disagree and one of them "
        "is wrong, so neither may be reported as a pass",
        signer_ok and payload_d.get("descriptor_sha") == digest(DESC_READ)
        and decided_ok and policy_ok and ts_bound_ok
        and find_gap(gaps, "D-4004") is None,
        {"descriptor_sha": payload_d.get("descriptor_sha") if payload_d else None,
         "conflicts_with_reconciliation": find_gap(gaps, "D-4004"),
         "expected": digest(DESC_READ), "signature_ok": signer_ok,
         "decided_by": payload_d.get("decided_by") if payload_d else None,
         "decided_by_ok": decided_ok,
         "policy_sha_ok": policy_ok,
         "decision_ts": payload_d.get("decision_ts") if payload_d else None,
         "guard_step": guard_d_step, "timestamp_bound_to_step": ts_bound_ok},
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

    effect_dp = (jdp.get(("D'", "effect_committed")) or [None])[0]
    check(
        "D'.effect", "V",
        "the effect did not proceed on a record the store could not resolve, so quarantine "
        "stops the action and not only the label on the record",
        "if an effect was committed for D-4005, the store said the binding did not verify and "
        "the host acted anyway, which is the same defect as accepting the record",
        effect_dp is None,
        {"effect_committed": effect_dp},
    )

    # -- F11: the journal refuses a write, so nothing may be known ------------------------
    durability = read_json(os.path.join(rundir, "probe-durability", "result.json"))
    probe_store = read_jsonl(os.path.join(rundir, "probe-durability", "journal.jsonl"))
    probe_id = (durability or {}).get("action_id")
    probe_verdict_rows = [r for r in (probe_store or [])
                          if r.get("kind") == "verdict" and r.get("action_id") == probe_id]
    verdict_reply = (durability or {}).get("verdict") or {}
    live_lookup = (durability or {}).get("lookup_same_process") or {}
    restart_lookup = (durability or {}).get("lookup_after_restart") or {}
    check(
        "journal-first", "P",
        "a store that cannot journal a verdict does not report it as known, in memory or "
        "after a restart, so an acknowledged decision is always one a recovery could also find",
        "if the store answers from memory while the journal is behind, it has reported a "
        "decision it could not keep and every count taken from it during that window is wrong",
        bool(durability) and verdict_reply.get("ok") is False
        and live_lookup.get("verdict") is None
        and restart_lookup.get("verdict") is None
        and not probe_verdict_rows,
        {"verdict_reply": verdict_reply.get("ok"),
         "durable_flag": verdict_reply.get("durable"),
         "error": verdict_reply.get("error"),
         "verdict_in_memory": live_lookup.get("verdict") is not None,
         "verdict_after_restart": restart_lookup.get("verdict") is not None,
         "verdict_records_in_probe_journal": len(probe_verdict_rows)},
    )

    # -- F7: repair keeps the bytes it discards -------------------------------------------
    repair_journal = read_jsonl(os.path.join(rundir, "probe-repair", "journal.jsonl")) or []
    repairs = [r for r in repair_journal if r.get("kind") == "repair"]
    repair = repairs[0] if len(repairs) == 1 else None
    quarantine_path = os.path.join(rundir, "probe-repair", (repair or {}).get("quarantine") or "")
    quarantine_bytes = None
    quarantine_sha = None
    if repair and os.path.exists(quarantine_path):
        with open(quarantine_path, "rb") as fh:
            tail = fh.read()
        quarantine_bytes = len(tail)
        quarantine_sha = hashlib.sha256(tail).hexdigest()
    check(
        "repair-quarantine", "P",
        "a repair that shortens a journal keeps the bytes it removed, so what was in flight "
        "when the write stopped survives the truncation",
        "if repair drops the tail, the only record of the interrupted write is destroyed by "
        "the recovery, and a crash and a silent deletion become the same event afterwards",
        bool(repair) and (repair.get("discarded_bytes") or 0) > 0
        and quarantine_bytes == repair.get("quarantine_bytes") == repair.get("discarded_bytes")
        and quarantine_sha == repair.get("quarantine_sha256"),
        {"repair_records": len(repairs),
         "discarded_bytes": (repair or {}).get("discarded_bytes"),
         "quarantine": (repair or {}).get("quarantine"),
         "quarantine_exists": os.path.exists(quarantine_path),
         "quarantine_bytes": quarantine_bytes,
         "digest_matches": quarantine_sha == (repair or {}).get("quarantine_sha256")},
    )

    # -- F9: two verdicts for one action ---------------------------------------------------
    conflict_id = "C-9009"
    conflict_verdicts = [r for r in store
                         if r.get("kind") == "verdict" and r.get("action_id") == conflict_id]
    conflict_records = [r for r in store
                        if r.get("kind") == "conflict" and r.get("action_id") == conflict_id]
    conflicted_state = (read_json(os.path.join(rundir, "store-state.json")) or {})
    named_conflict = conflict_records[0] if len(conflict_records) == 1 else None
    check(
        "conflict", "P",
        "two verdicts that disagree are recorded as a conflict with both sequence numbers, and "
        "the action stays unresolved instead of resolving to whichever record was read first",
        "if a duplicate verdict silently becomes the answer, the record that loses is invisible "
        "and the result depends on file order rather than on evidence",
        len(conflict_verdicts) == 2 and named_conflict is not None
        and {named_conflict.get("first_seq"), named_conflict.get("second_seq")}
        == {r.get("store_seq") for r in conflict_verdicts}
        and conflict_id in (conflicted_state.get("conflicted_verdicts") or [])
        and find_gap(gaps, conflict_id) is not None,
        {"verdict_records": [r.get("store_seq") for r in conflict_verdicts],
         "conflict_record": named_conflict.get("store_seq") if named_conflict else None,
         "named_in_state": conflict_id in (conflicted_state.get("conflicted_verdicts") or []),
         "still_a_gap": find_gap(gaps, conflict_id) is not None},
    )

    # -- F10: a reply is not consent -------------------------------------------------------
    reply_events = []
    try:
        reply_events = read_jsonl(os.path.join(rundir, "probe-reply", "host-E.jsonl")) or []
    except Unreadable:
        reply_events = []
    rejected = [e for e in reply_events if e.get("kind") == "reply_rejected"]
    committed = [e for e in reply_events if e.get("kind") == "effect_committed"]
    wrong_id_named = any("S-" in problem for e in rejected
                         for problem in (e.get("problems") or []))
    check(
        "reply-checked", "P",
        "the host logs an effect only when the store's reply names the action that was asked "
        "about, so a well-formed answer to a different question is refused",
        "if any well-formed reply counts as consent, a store that answers about the wrong "
        "action id can authorise an effect the host was never granted",
        bool(rejected) and not committed and wrong_id_named
        and any(e.get("command") == "verdict" for e in rejected),
        {"reply_rejected": len(rejected), "effect_committed": len(committed),
         "mismatch_named": wrong_id_named,
         "problems": [p for e in rejected for p in (e.get("problems") or [])]},
    )

    # -- completeness: every named artifact, and proof that each scenario ran ---------------
    # A missing journal used to be read as "that scenario had nothing to say". It is not:
    # the artifacts are the evidence, and an absent artifact is an absent result.
    if unreadable:
        check(
            "artifacts-parse", "meta",
            "every artifact parses, so a damaged file is reported instead of being read as an "
            "empty one",
            "if an unreadable journal is treated as a scenario with no events, damage and "
            "silence look the same to a reader",
            False,
            {"unreadable": unreadable},
        )

    missing_files = [name for name in ARTIFACT_FILES
                     if not os.path.exists(os.path.join(rundir, name))]
    manifest_ok = isinstance(manifest, dict) and manifest.get("manifest_version") == 2
    required = set((manifest or {}).get("required") or []) if isinstance(manifest, dict) else set()
    listed_missing = [name for name in sorted(required) if not os.path.exists(os.path.join(rundir, name))]
    check(
        "artifacts-complete", "meta",
        "every artifact the run is supposed to produce is present, and the manifest says which "
        "ones those are",
        "if a missing artifact passes, an absence of evidence has been read as evidence of the "
        "expected absence",
        not missing_files and manifest_ok and not listed_missing and required >= set(ARTIFACT_FILES),
        {"missing": missing_files, "manifest_version": (manifest or {}).get("manifest_version")
         if isinstance(manifest, dict) else None,
         "required_not_present": listed_missing,
         "required_declared": sorted(required)},
    )

    chain_problems = {}
    for filename, kinds in SCENARIO_EVENTS.items():
        try:
            events = read_jsonl(os.path.join(rundir, filename)) or []
        except Unreadable as exc:
            chain_problems[filename] = ["unreadable: %s" % exc.detail]
            continue
        present = [e.get("kind") for e in events]
        absent = [kind for kind in kinds if kind not in present]
        if absent:
            chain_problems[filename] = absent
    check(
        "scenarios-ran", "meta",
        "each scenario left the events that show it ran to the point it is named for, rather "
        "than leaving a file that could equally be a scenario that did nothing",
        "if the events are not there, the row is being reported from a summary instead of from "
        "the thing the summary describes",
        not chain_problems,
        {"missing_events": chain_problems},
    )

    # -- framing ---------------------------------------------------------------------------
    framed = [rec for rec in store if "digest" in rec]
    unframed = len(store) - len(framed)
    broken = [rec.get("store_seq") for rec in framed
              if not hmac_compare(rec["digest"], frame(rec))]
    check(
        "store-records-framed", "meta",
        "each record in the store journal carries a digest of itself, so a write that stopped "
        "halfway is detectable instead of being read as a shorter history",
        "if any record fails its own frame, the journal was damaged or edited and every gap "
        "claim built on it is suspect",
        unframed == 0 and not broken,
        {"records": len(store), "unframed": unframed, "broken": broken},
    )

    # -- the honesty checks ----------------------------------------------------------------
    crlf = [name for name in ARTIFACT_FILES
            if not name.endswith(".bin")
            and (read_bytes(rundir, name) or b"").find(b"\r\n") >= 0]
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


# The events each scenario has to leave behind for its row to mean anything. Kinds only:
# the values are checked by the row itself.
SCENARIO_EVENTS = {
    "host-A.jsonl": ("expectation_registered", "proposal", "guard_decision",
                     "verdict_suppressed"),
    "host-Ap.jsonl": ("proposal", "guard_decision", "verdict_suppressed"),
    "host-B.jsonl": ("proposal", "guard_decision", "wal_commit", "ship_failed",
                     "effect_withheld", "replay_read", "replay_shipped"),
    "host-C.jsonl": ("id_issued", "commitment_preserved", "proposal", "guard_decision",
                     "host_dying"),
    "host-Cp.jsonl": ("id_issued", "proposal", "guard_decision", "host_dying"),
    "host-Cpp.jsonl": ("local_id_minted", "proposal", "guard_decision", "host_dying"),
    "host-D.jsonl": ("proposal", "guard_decision", "ship_ok", "effect_committed"),
    "host-Dp.jsonl": ("proposal", "guard_decision", "signature_stripped", "reply_rejected",
                      "effect_withheld"),
    "probe-reply/host-E.jsonl": ("proposal", "guard_decision", "reply_rejected",
                                 "effect_withheld"),
}

PROBE_FILES = ["probe-durability/journal.jsonl", "probe-durability/result.json",
               "probe-repair/journal.jsonl", "probe-repair/journal.jsonl.quarantine-1.bin",
               "probe-reply/host-E.jsonl"]

ARTIFACT_FILES = ["store.jsonl", "host-A.jsonl", "host-Ap.jsonl", "host-B.jsonl",
                  "host-C.jsonl", "host-Cp.jsonl", "host-Cpp.jsonl", "host-D.jsonl",
                  "host-Dp.jsonl", "wal-B.jsonl", "reconciled.json", "store-state.json",
                  "lookups.json"] + PROBE_FILES


def compare_determinism(first, second):
    """Two directories, both readable, all artifacts present, then equal bytes.

    Two directories that do not exist are equal in the only sense a file comparison can see,
    which is no sense at all: absent compared to absent is a match. This check used to report
    that as determinism holding, which is the same defect class as a missing artifact passing
    a completeness check.
    """
    absent_dirs = [path for path in (first, second) if not os.path.isdir(path)]
    # One directory is not two runs. Comparing a run with itself reads every file twice, agrees
    # with itself, and reports a determinism pass that was never tested.
    same_directory = (os.path.realpath(first) == os.path.realpath(second)
                      if not absent_dirs else False)
    missing = sorted({f for f in ARTIFACT_FILES for path in (first, second)
                      if read_bytes(path, f) is None})
    differing = [] if same_directory else [
        f for f in ARTIFACT_FILES if read_bytes(first, f) != read_bytes(second, f)]
    check(
        "determinism", "meta",
        "two runs of the suite produce identical artifacts, so a result can be reproduced by "
        "anyone without trusting the machine it ran on",
        "if any artifact differs between runs, the suite reports the machine as much as the "
        "failure; if either directory or any artifact is missing, nothing was compared; if the "
        "same directory was named twice, one directory was compared with itself",
        not absent_dirs and not same_directory and not missing and not differing,
        {"differing": differing, "missing_directories": absent_dirs,
         "same_directory": first if same_directory else None,
         "missing_artifacts": missing},
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
    print("Decision time: source-asserted. Carried through replay in M2, never independently "
          "attested by anything in this suite.")
    failures = [r for r in RESULTS if r["result"] == "fails"]
    print("")
    print("VERDICT: %s" % ("every check holds" if not failures
                           else "%d check(s) failed" % len(failures)))
    report_path = os.path.join(rundir, "verify-report.json")
    try:
        report_file = open(report_path, "w", encoding="utf-8", newline="\n")
    except OSError as exc:
        # The verdict above is already on stdout. A directory that cannot hold the report is
        # not a reason to raise: the reader gets the result and an explanation of what is not
        # in the directory.
        print("")
        print("verify-report.json was not written (%s)." % exc)
        stale = os.path.exists(os.path.join(rundir, "verify-report.json"))
        if stale:
            # A report that could not be replaced is still sitting where a reader will look for
            # this run's result. Leaving it unmentioned would be the worst of the two options.
            print("An older verify-report.json is still in that directory and describes an "
                  "earlier run. Do not read it as this run's result.")
        print("The verdict above stands; the report file is missing, not the judgement.")
        return 0 if not failures else 1
    with report_file as fh:
        json.dump({"checks": RESULTS,
                   "summary": {"class_P": [p_held, len(p_rows)],
                               "class_V": [v_held, len(v_rows)],
                               "failures": [r["id"] for r in failures],
                               "artifact_state": (
                                   "unreadable" if any(r["id"] in ("artifacts-readable",
                                                                   "artifacts-parse")
                                                       and r["result"] == "fails"
                                                       for r in RESULTS)
                                   else "readable"),
                               "timestamp": "source-asserted, preserved through replay, "
                                            "not independently verified"}},
                  fh, indent=2, sort_keys=True)
    return 0 if not failures else 1


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    rundir = argv[1]
    if not os.path.isdir(rundir):
        print("no run directory at %s" % rundir)
        print("Nothing was verified. This is not a pass, and it is not a failure of a run.")
        return 2
    verify_run(rundir)
    if len(argv) > 2:
        compare_determinism(rundir, argv[2])
    return report(rundir)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
