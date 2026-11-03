"""Independent regression-audit tests for the revised host-failure-benchmark.

Each test states the documented expectation and records what the code does. `holds` is True when
the implementation behaves as documented, False when a defect is reproduced.

    HFB_REPO=/path/to/hfb python3 v2tests.py            # all
    HFB_REPO=/path/to/hfb python3 v2tests.py V05 V13    # selected
"""
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v2lib import (J, PY, REPO, Store, append_row, check_of, common, copy_repo, copy_run,  # noqa
                   failed, fresh_run, hooked_repo, last_line, load, reframe, regenerate_reconciled,
                   resign, run_host, save, verdict_line, verify)

TESTS, RESULTS = [], []
BASE = None


def test(tid, title, group):
    def deco(fn):
        TESTS.append((tid, title, group, fn))
        return fn
    return deco


def base():
    return copy_run(BASE)


def res(expected, observed, holds, **kw):
    d = dict(expected=expected, observed=observed, holds=holds)
    d.update(kw)
    return d


# ====================================================================== 1. WAL authentication
WAL_EDIT = '''
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "hfb", "bench"))
from common import record_payload, sign
def before_restart(rundir, port):
    p = os.path.join(rundir, "wal-B.jsonl")
    r = json.loads(open(p).read().splitlines()[0])
    %s
    open(p, "w", newline="\\n").write(json.dumps(r, sort_keys=True) + "\\n")
'''


@test("V01", "WAL verdict BLOCK->ALLOW with stale signature, before replay", "WAL")
def v01():
    repo = hooked_repo("v01")
    rd, p = fresh_run(repo, WAL_EDIT % 'r["verdict"] = "ALLOW"; r["rule"] = None')
    code, rep, out, err = verify(rd, repo)
    b = check_of(rep, "B")
    return res("B fails (stored verdict state unverified, WAL signature invalid)",
               "exit=%s; B=%s; stored_verdict_state=%s; wal_signature_ok=%s" % (
                   code, b["result"], b["evidence"]["stored_verdict_state"], b["evidence"]["wal_signature_ok"]),
               b["result"] == "fails")


@test("V02", "WAL verdict BLOCK->ALLOW and re-signed with the in-source key, before replay", "WAL")
def v02():
    repo = hooked_repo("v02")
    rd, p = fresh_run(repo, WAL_EDIT % 'r["verdict"] = "ALLOW"; r["rule"] = None; r["signature"] = sign(record_payload(r))')
    code, rep, out, err = verify(rd, repo)
    stored = [r for r in load(J(rd, "store.jsonl")) if r.get("action_id") == "B-2001" and r["kind"] == "verdict"][0]
    guard = [e for e in load(J(rd, "host-B.jsonl")) if e["kind"] == "guard_decision"][0]
    return res("B fails because the recovered verdict differs from the host's guard_decision (source-holder case; key is in source)",
               "host guard_decision verdict=%s; store holds verdict=%s state=%s; verify exit=%s, %s" % (
                   guard["verdict"], stored["record"]["verdict"], stored["state"], code, verdict_line(out)),
               code != 0, scope="source holder (documented limit), but the verdict is never compared with guard_decision")


@test("V03", "WAL signature stripped before replay", "WAL")
def v03():
    repo = hooked_repo("v03")
    rd, p = fresh_run(repo, WAL_EDIT % 'r["signature"] = None')
    code, rep, out, err = verify(rd, repo)
    return res("B fails", "exit=%s; failed=%s" % (code, failed(rep)), "B" in (failed(rep) or []))


@test("V04", "Replay re-stamps decision_ts with its own clock step and re-signs (old T09)", "WAL")
def v04():
    repo = copy_repo("v04", {"bench/host.py": [(
        '            aid = record["action_id"]\n            if self.require({"cmd": "verdict", "record": record}',
        '            aid = record["action_id"]\n            record["decision_ts"] = self.clock.step + 1\n'
        '            record["signature"] = sign(record_payload(record))\n'
        '            if self.require({"cmd": "verdict", "record": record}')]})
    rd, p = fresh_run(repo)
    code, rep, out, err = verify(rd, REPO)
    b = check_of(rep, "B")
    ev = b["evidence"]
    return res("B fails: the stored time is the replay-phase step, i.e. arrival time",
               "B=%s guard_step=%s replay_step=%s stored_ts=%s; %s" % (
                   b["result"], ev["guard_step"], ev["replay_step"], ev["stored_ts"], verdict_line(out)),
               b["result"] == "fails")


# ====================================================================== 2. unsigned verdicts vs gaps
@test("V05", "Unsigned verdict row that asserts state=verified, appended and framed", "unsigned")
def v05():
    d = base()
    append_row(J(d, "store.jsonl"), {"kind": "verdict", "action_id": "C-3003", "state": "verified",
                                     "record": {"action_id": "C-3003", "verdict": "ALLOW", "signature": None}})
    v = copy_run(d)                      # verify a copy: our own store start would add a boot record
    code, rep, out, err = verify(v)
    with Store(J(d, "store.jsonl")) as st:
        gaps = [g["action_id"] for g in st.call({"cmd": "reconcile"})["gaps"]]
        lk = st.call({"cmd": "lookup", "action_id": "C-3003"})
    return res("the store recomputes state from the record and keeps C-3003 as a gap (store.py:163-166 comment)",
               "after restart: C-3003 in store gaps=%s; store verdict_state=%s; verify (copy, no restart) exit=%s failed=%s" % (
                   "C-3003" in gaps, lk["verdict_state"], code, failed(rep)),
               "C-3003" in gaps)


@test("V06", "Valid signed record of D-4004 transplanted under outer action_id C-3003", "unsigned")
def v06():
    d = base()
    recs = load(J(d, "store.jsonl"))
    d_rec = [r for r in recs if r.get("action_id") == "D-4004" and r["kind"] == "verdict"][0]["record"]
    append_row(J(d, "store.jsonl"), {"kind": "verdict", "action_id": "C-3003", "record": dict(d_rec)})
    v = copy_run(d)
    code, rep, out, err = verify(v)
    with Store(J(d, "store.jsonl")) as st:
        gaps = [g["action_id"] for g in st.call({"cmd": "reconcile"})["gaps"]]
        lk = st.call({"cmd": "lookup", "action_id": "C-3003"})
    return res("a record signed for D-4004 cannot resolve C-3003 (no key needed for this attack)",
               "after restart: C-3003 still a gap=%s; store verdict_state=%s; verify (copy, no restart) exit=%s failed=%s" % (
                   "C-3003" in gaps, lk["verdict_state"], code, failed(rep)),
               "C-3003" in gaps, note="verify fails only because C-3003 is a scripted row; recompute_gaps (verify.py:144-156) uses the outer id too")


@test("V07", "Unsigned verdict for C-3003 over the protocol, live store", "unsigned")
def v07():
    d = base()
    p = J(d, "store.jsonl")
    with Store(p) as st:
        r = st.call({"cmd": "verdict", "record": {"action_id": "C-3003", "verdict": "ALLOW", "signature": None}})
        gaps = [g["action_id"] for g in st.call({"cmd": "reconcile"})["gaps"]]
    return res("stored as unverified; C-3003 stays a gap", "reply=%s; C-3003 in gaps=%s" % (r, "C-3003" in gaps),
               "C-3003" in gaps and r.get("state") == "unverified")


@test("V08", "Forged unsigned verdict (the f3 mutation) checked by verify.py, not only by the store", "unsigned")
def v08():
    d = base()
    append_row(J(d, "store.jsonl"), {"kind": "verdict", "action_id": "C-3003",
                                     "record": {"action_id": "C-3003", "decided_by": "nobody", "decision_ts": 2,
                                                "descriptor_sha": None, "policy_sha": None, "rule": None,
                                                "signature": None, "verdict": "ALLOW"}})
    code, rep, out, err = verify(d)
    c = check_of(rep, "C")
    return res("(informational) verify keeps C-3003 a gap; the forged row is quarantined, not flagged",
               "exit=%s; %s; C=%s gap=%s" % (code, verdict_line(out), c["result"], c["evidence"]["gap"]),
               c["result"] == "holds", informational=True)


# ====================================================================== 3. missing artifacts
@test("V09", "Each required artifact deleted on its own (18 runs) plus manifest", "artifacts")
def v09():
    names = json.load(open(J(BASE, "manifest.json")))["required"] + ["manifest.json"]
    passed = []
    detail = {}
    for n in names:
        d = base()
        os.remove(J(d, n))
        code, rep, out, err = verify(d)
        detail[n] = (code, failed(rep))
        if code == 0:
            passed.append(n)
    return res("verify exits non-zero for every single missing artifact",
               "%d deletions; passing anyway: %s; sample: %s" % (len(names), passed or "none",
                                                               {k: detail[k] for k in list(detail)[:3]}),
               not passed)


@test("V10", "Artifact deleted and also removed from manifest.required", "artifacts")
def v10():
    d = base()
    os.remove(J(d, "probe-reply", "host-E.jsonl"))
    m = json.load(open(J(d, "manifest.json")))
    m["required"] = [x for x in m["required"] if x != "probe-reply/host-E.jsonl"]
    m["artifacts"] = [x for x in m["artifacts"] if x != "probe-reply/host-E.jsonl"]
    json.dump(m, open(J(d, "manifest.json"), "w"), indent=2, sort_keys=True)
    code, rep, out, err = verify(d)
    return res("still fails: the verifier's own list is authoritative", "exit=%s failed=%s" % (code, failed(rep)), code != 0)


# ====================================================================== 4. duplicates and conflicts
@test("V11", "Identical verdict replayed twice (benign duplicate)", "conflict")
def v11():
    d = base()
    p = J(d, "store.jsonl")
    last = max(r["store_seq"] for r in load(p))
    with Store(p) as st:
        stored = [r for r in load(p) if r.get("action_id") == "B-2001" and r["kind"] == "verdict"][0]["record"]
        r = st.call({"cmd": "verdict", "record": stored})
        state = st.call({"cmd": "state"})
    recs = [x for x in load(p) if not (x["kind"] == "boot" and x["store_seq"] > last)]
    save(p, reframe(recs, renumber=True))
    regenerate_reconciled(d)
    code, rep, out, err = verify(d)
    return res("no conflict; B-2001 stays verified; verify still passes",
               "reply state=%s conflict=%s; B-2001 conflicted=%s; verify exit=%s %s" % (
                   r.get("state"), r.get("conflict"), "B-2001" in state["conflicted_verdicts"], code, verdict_line(out)),
               r.get("state") == "verified" and code == 0)


@test("V12", "An unsigned client puts the verified D-4004 into conflict; does the verifier agree with itself?", "conflict")
def v12():
    d = base()
    p = J(d, "store.jsonl")
    last = max(r["store_seq"] for r in load(p))
    with Store(p) as st:
        r = st.call({"cmd": "verdict", "record": {"action_id": "D-4004", "verdict": "BLOCK", "signature": None}})
    recs = [x for x in load(p) if not (x["kind"] == "boot" and x["store_seq"] > last)]
    save(p, reframe(recs, renumber=True))
    rec, state = regenerate_reconciled(d)
    code, rep, out, err = verify(d)
    dchk = check_of(rep, "D")
    return res("one consistent answer: if D-4004 is unresolved (a gap), check D does not report it verified",
               "reply=%s; store gaps include D-4004=%s; verify D=%s; verify exit=%s %s" % (
                   {k: r[k] for k in ("state", "conflict")}, any(g["action_id"] == "D-4004" for g in rec["gaps"]),
                   dchk["result"], code, verdict_line(out)),
               not (code == 0 and any(g["action_id"] == "D-4004" for g in rec["gaps"])),
               note="also: any unauthenticated client can veto a verified verdict this way")


@test("V13", "Conflict for an action other than the C-9009 probe, conflict record deleted", "conflict")
def v13():
    d = base()
    p = J(d, "store.jsonl")
    last = max(r["store_seq"] for r in load(p))
    rec = [r for r in load(p) if r.get("action_id") == "D-4004" and r["kind"] == "verdict"][0]["record"]
    second = dict(rec, decision_ts=3)
    resign(second)
    with Store(p) as st:
        st.call({"cmd": "verdict", "record": second})
    recs = [x for x in load(p) if not (x["kind"] in ("boot", "conflict") and x["store_seq"] > last)]
    save(p, reframe(recs, renumber=True))
    regenerate_reconciled(d)
    code, rep, out, err = verify(d)
    return res("two signed, different D-4004 verdicts with no conflict record are refused by some check",
               "exit=%s; %s; failed=%s" % (code, verdict_line(out), failed(rep)), code != 0)


# ====================================================================== 5. acknowledgement failures
def fake_store(reply_for):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    stop = []

    def serve():
        srv.settimeout(0.2)
        while not stop:
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            data = c.recv(65536)
            try:
                req = json.loads(data)
            except ValueError:
                req = {}
            reply = reply_for(req)
            if reply is not None:
                c.sendall((json.dumps(reply) + "\n").encode())
            c.close()
    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1], stop


def aid_of(req):
    return req.get("action_id") or (req.get("record") or {}).get("action_id")


def host_events(fn_reply, scenario="D", flags=("--action-id", "D-9")):
    d = tempfile.mkdtemp(prefix="ack-")
    srv, port, stop = fake_store(fn_reply)
    r = run_host(REPO, scenario, port, d, list(flags))
    stop.append(1)
    srv.close()
    jp = J(d, "host-%s.jsonl" % scenario.replace("'", "p"))
    return r, [e["kind"] for e in load(jp)] if os.path.exists(jp) else []


@test("V14", "Store answers ok:false to everything", "ack")
def v14():
    r, kinds = host_events(lambda q: {"ok": False, "action_id": aid_of(q), "error": "refused"})
    return res("no effect_committed", "rc=%s events=%s" % (r.returncode, kinds), "effect_committed" not in kinds)


@test("V15", "Store says ok:true, right id, but stored:false for the verdict", "ack")
def v15():
    def reply(q):
        if q.get("cmd") == "verdict":
            return {"ok": True, "stored": False, "action_id": aid_of(q)}
        return {"ok": True, "action_id": aid_of(q)}
    r, kinds = host_events(reply)
    return res("no effect: the verdict was not stored", "rc=%s events=%s" % (r.returncode, kinds),
               "effect_committed" not in kinds)


@test("V16", "Real store already holds a different D-4004 verdict: reply says state=conflicted", "ack")
def v16():
    d = tempfile.mkdtemp(prefix="conf-")
    p = J(d, "store.jsonl")
    with Store(p) as st:
        st.call({"cmd": "issue", "action_id": "D-4004"})
        pre = {"action_id": "D-4004", "verdict": "BLOCK", "signature": None}
        st.call({"cmd": "verdict", "record": pre})
        r = run_host(REPO, "D", st.port, d, ["--action-id", "D-4004"])
        lk = st.call({"cmd": "lookup", "action_id": "D-4004"})
    kinds = [e["kind"] for e in load(J(d, "host-D.jsonl"))]
    return res("the host withholds the effect when the store reports the verdict conflicted / unresolved",
               "store verdict_state=%s; host events=%s" % (lk["verdict_state"], kinds),
               "effect_committed" not in kinds)


@test("V17", "D' path: store replies state=unverified, host still commits the effect", "ack")
def v17():
    kinds = [e["kind"] for e in load(J(BASE, "host-Dp.jsonl"))]
    st = [r for r in load(J(BASE, "store.jsonl")) if r.get("action_id") == "D-4005" and r["kind"] == "verdict"][0]["state"]
    return res("an effect is not committed on a verdict the store has quarantined",
               "store state=%s; host-Dp events=%s" % (st, kinds), "effect_committed" not in kinds)


@test("V18", "Store closes the connection without replying", "ack")
def v18():
    r, kinds = host_events(lambda q: None, "B", ("--action-id", "B-9"))
    return res("ship failure logged (ship_failed + effect_withheld), no traceback",
               "rc=%s events=%s stderr=%r" % (r.returncode, kinds, last_line(r.stderr)),
               "ship_failed" in kinds and r.returncode == 0)


# ====================================================================== 6. journal I/O failures
STORE_IO = r'''
import os, sys, json
sys.path.insert(0, os.path.join(sys.argv[1], "bench"))
import store as S
j = S.Journal(sys.argv[2]); s = S.Store(j)
s.handle({"cmd": "issue", "action_id": "M-1"})
mode = sys.argv[3]
real_open, real_fsync = open, os.fsync
if mode == "open":
    def bad(*a, **k): raise OSError(5, "Input/output error")
    S.open = bad
elif mode == "fsync":
    def bad(fd): raise OSError(5, "Input/output error")
    S.os.fsync = bad
rec = {"action_id": "M-1", "verdict": "ALLOW", "signature": None}
try:
    reply = s.handle({"cmd": "verdict", "record": rec})
    outcome = "reply"
except Exception as e:
    reply = repr(e); outcome = "exception escaped Store.handle"
if mode == "open": del S.open
else: S.os.fsync = real_fsync
live = s.handle({"cmd": "lookup", "action_id": "M-1"})["verdict"] is not None
nxt = s.handle({"cmd": "issue", "action_id": "M-2"})
rows = [json.loads(l) for l in real_open(sys.argv[2]) if l.strip()]
seqs = [r["store_seq"] for r in rows]
s2 = S.Store(S.Journal(sys.argv[2]))
restart = s2.handle({"cmd": "lookup", "action_id": "M-1"})["verdict"] is not None
print(json.dumps({"outcome": outcome, "reply": reply, "live_knows_verdict": live,
                  "restart_knows_verdict": restart, "store_seqs_on_disk": seqs,
                  "duplicate_seq": len(seqs) != len(set(seqs))}))
'''


def store_io(mode):
    d = tempfile.mkdtemp(prefix="io-")
    sp = J(d, "probe.py")
    open(sp, "w").write(STORE_IO)
    p = subprocess.run([PY, sp, REPO, J(d, "j.jsonl"), mode], capture_output=True, text=True, timeout=60)
    return json.loads(p.stdout.strip().splitlines()[-1]) if p.stdout.strip() else {"stderr": p.stderr}


@test("V19", "Journal open() raises EIO during a verdict append", "journal-io")
def v19():
    r = store_io("open")
    return res("store answers ok:false durable:false; memory and disk agree (neither knows the verdict)",
               "outcome=%s reply=%s live=%s restart=%s" % (r["outcome"], r["reply"], r["live_knows_verdict"], r["restart_knows_verdict"]),
               r["outcome"] == "reply" and not r["live_knows_verdict"] and not r["restart_knows_verdict"])


@test("V20", "fsync raises EIO after the bytes were written", "journal-io")
def v20():
    r = store_io("fsync")
    return res("store answers ok:false; live state and restart state agree; store_seq stays unique",
               "outcome=%s reply=%s live=%s restart=%s seqs=%s duplicate_seq=%s" % (
                   r["outcome"], r["reply"], r["live_knows_verdict"], r["restart_knows_verdict"],
                   r["store_seqs_on_disk"], r["duplicate_seq"]),
               r["outcome"] == "reply" and r["live_knows_verdict"] == r["restart_knows_verdict"] and not r["duplicate_seq"])


@test("V21", "Torn line mid-journal while the store keeps running; later acknowledged records", "journal-io")
def v21():
    d = tempfile.mkdtemp(prefix="torn-")
    p = J(d, "store.jsonl")
    with Store(p) as st:
        st.call({"cmd": "issue", "action_id": "T-1"})
        with open(p, "ab") as fh:
            fh.write(b'{"kind": "issued", "action_id": "T-2", "dig')   # a write that stopped half way
        acks = [st.call({"cmd": "issue", "action_id": "T-%d" % i}) for i in (3, 4, 5)]
    with Store(p) as st:
        state = st.call({"cmd": "state"})
    q = [f for f in os.listdir(d) if ".quarantine-" in f]
    return res("records acknowledged after the torn write survive a restart",
               "acks=%s; after restart issued=%s; quarantine files=%s" % (
                   [a.get("ok") for a in acks], state["issued"], q),
               set(["T-3", "T-4", "T-5"]) <= set(state["issued"]))


@test("V22", "f11 probe coverage: the failpoint only refuses before any byte is written", "journal-io")
def v22():
    src = open(J(REPO, "bench", "store.py")).read()
    return res("(static) probe injects the failure modes that matter",
               "HFB_FAILPOINT checks in store.py: %d; refusal raised before open(): %s" % (
                   src.count("self.failpoint"), src.index('raise JournalError') < src.index('with open(self.path, "a"')),
               False, static=True)


# ====================================================================== 7. host-local evidence loss
LOSS_HOOK = '''
import os
def before_restart(rundir, port):
    for n in ("wal-B.jsonl", "host-B.jsonl"):
        p = os.path.join(rundir, n)
        if os.path.exists(p): os.remove(p)
'''


@test("V23", "Host disk lost between B's crash and recovery (WAL + host journal deleted)", "host-loss")
def v23():
    repo = hooked_repo("v23")
    rd, p = fresh_run(repo, LOSS_HOOK)
    code, rep, out, err = verify(rd, repo)
    gaps = [g["action_id"] for g in json.load(open(J(rd, "reconciled.json")))["gaps"]]
    return res("the run is classified as host-local evidence loss, distinct from process termination; B-2001 is named somewhere",
               "run.py rc=%s; verify exit=%s failed=%s; B-2001 in store gaps=%s; any check naming evidence loss=%s" % (
                   p.returncode, code, failed(rep), "B-2001" in gaps,
                   any("loss" in r["id"] for r in rep["checks"])),
               "B-2001" in gaps)


@test("V24", "Host patched not to die in C/C'/C'' (returns instead of os._exit)", "host-loss")
def v24():
    repo = copy_repo("v24", {"bench/host.py": [("        sys.stdout.flush()\n        os._exit(9)",
                                                 "        sys.stdout.flush()\n        return")]})
    rd, p = fresh_run(repo)
    code, rep, out, err = verify(rd, REPO)
    return res("M3 rows require evidence of termination (exit status)", "host exits=%s; verify exit=%s %s" % (
        [l.split()[-1] for l in p.stdout.splitlines() if l.strip().startswith("host C")], code, verdict_line(out)),
        code != 0)


@test("V25", "External SIGKILL between WAL commit and ship (real kill), store up but silent", "host-loss")
def v25():
    d = tempfile.mkdtemp(prefix="kill-")
    hang = socket.socket()
    hang.bind(("127.0.0.1", 0))
    hang.listen(1)
    held = []
    threading.Thread(target=lambda: held.append(hang.accept()), daemon=True).start()
    proc = subprocess.Popen([PY, J(REPO, "bench", "host.py"), "--scenario", "B", "--port", str(hang.getsockname()[1]),
                             "--workdir", d, "--journal", "host-B.jsonl", "--action-id", "B-2001"])
    t0 = time.time()
    while time.time() - t0 < 5 and not (held and os.path.exists(J(d, "wal-B.jsonl"))):
        time.sleep(0.01)
    time.sleep(0.1)
    proc.send_signal(signal.SIGKILL)
    proc.wait()
    kinds = [e["kind"] for e in load(J(d, "host-B.jsonl"))]
    with Store(J(d, "store.jsonl")) as st:
        r = run_host(REPO, "B", st.port, d, ["--phase", "replay", "--action-id", "B-2001"])
        state = st.call({"cmd": "state"})
    hang.close()
    return res("(informational) WAL survives a real kill; replay lands the verdict",
               "rc=%s events=%s; replay rc=%s; store verdicts=%s unverified=%s" % (
                   proc.returncode, kinds, r.returncode, state["verdicts"], state["unverified_verdicts"]),
               "B-2001" in state["verdicts"], informational=True)


# ====================================================================== 8. false positives / earlier findings
@test("V26", "Benign store restart after the run (one extra boot record) on valid evidence", "false-positive")
def v26():
    d = base()
    with Store(J(d, "store.jsonl")):
        pass
    code, rep, out, err = verify(d)
    return res("valid evidence still verifies after an ordinary restart",
               "exit=%s failed=%s; B.arrived_after_recovery=%s" % (
                   code, failed(rep), check_of(rep, "B")["evidence"]["arrived_after_recovery"]),
               code == 0)


@test("V27", "verify.py run twice on the same valid run", "false-positive")
def v27():
    d = base()
    a = verify(d)[0]
    b = verify(d)[0]
    return res("both exit 0", "first=%s second=%s" % (a, b), a == 0 and b == 0)


@test("V28", "Main-journal repair (torn append before B's restart) is reported", "earlier")
def v28():
    repo = hooked_repo("v28")
    rd, p = fresh_run(repo, '''
def before_restart(rundir, port):
    open(rundir + "/store.jsonl", "ab").write(b'{"action_id": "B-2001", "kind": "verd')
''')
    code, rep, out, err = verify(rd, repo)
    reps = [r for r in load(J(rd, "store.jsonl")) if r["kind"] == "repair"]
    return res("verify flags or at least reports a repaired main journal",
               "main-journal repair records=%d (quarantine=%s); verify exit=%s %s" % (
                   len(reps), reps[0].get("quarantine") if reps else None, code, verdict_line(out)),
               code != 0)


@test("V29", "Store journal truncated at a record boundary (last record removed)", "earlier")
def v29():
    d = base()
    p = J(d, "store.jsonl")
    lines = open(p, "rb").read().splitlines(keepends=True)
    open(p, "wb").write(b"".join(lines[:-1]))
    with Store(p) as st:
        pass
    return res("TECHNICAL-NOTE.md:74: a truncated history is announced",
               "restart stdout=%r; repair records=%d" % (st.out.strip(), sum(1 for r in load(p) if r["kind"] == "repair")),
               any(r["kind"] == "repair" for r in load(p)))


@test("V30", "Mid-file deletion of D-4004 issue+commitment, frames intact", "earlier")
def v30():
    d = base()
    recs = load(J(d, "store.jsonl"))
    save(J(d, "store.jsonl"), [r for r in recs if not (r.get("action_id") == "D-4004" and r["kind"] in ("issued", "commitment"))])
    code, rep, out, err = verify(d)
    return res("store_seq gap detected", "exit=%s %s" % (code, verdict_line(out)), code != 0)


@test("V31", "Invented issued id inserted, frames recomputed, reconciliation regenerated by the store", "earlier")
def v31():
    d = base()
    p = J(d, "store.jsonl")
    recs = load(p)
    i = [k for k, r in enumerate(recs) if r["kind"] == "expectation"][0]
    recs.insert(i + 1, {"kind": "issued", "action_id": "C-3006"})
    # renumbering shifts store_seq, so rewrite the conflict record's references the way a careful editor would
    old = {id(r): r.get("store_seq") for r in recs}
    reframe(recs, renumber=True)
    m = {old[id(r)]: r["store_seq"] for r in recs if old[id(r)] is not None}
    for r in recs:
        if r["kind"] == "conflict":
            r["first_seq"], r["second_seq"] = m[r["first_seq"]], m[r["second_seq"]]
    save(p, reframe(recs))
    regenerate_reconciled(d)
    code, rep, out, err = verify(d)
    return res("an id no host journal mentions is detected", "exit=%s %s" % (code, verdict_line(out)), code != 0,
               scope="needs only the unkeyed frame")


@test("V32", "D-4004 commitment replaced (frame recomputed)", "earlier")
def v32():
    d = base()
    recs = load(J(d, "store.jsonl"))
    for r in recs:
        if r.get("action_id") == "D-4004" and r["kind"] == "commitment":
            r["descriptor_sha"] = "sha256:" + "0" * 64
    save(J(d, "store.jsonl"), reframe(recs))
    code, rep, out, err = verify(d)
    return res("D cross-checks the verdict's descriptor_sha with the preserved commitment",
               "exit=%s %s" % (code, verdict_line(out)), code != 0)


@test("V33", "Expectation registered only after host A finished (old T38)", "earlier")
def v33():
    repo = hooked_repo("v33", {"run.py": [('    ("A", ["--action-id", "A-1042"]),',
                                          '    ("A", ["--action-id", "A-1042", "--no-register"]),')]})
    rd, p = fresh_run(repo, '''
import json, socket
def after_replay(rundir, port):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(json.dumps({"cmd": "expect", "action_id": "A-1042", "policy_sha": "x"}).encode() + b"\\n"); s.recv(1000)
    # make host-A look like it registered, as the verifier only checks event kinds
    p = rundir + "/host-A.jsonl"
    ev = [json.loads(l) for l in open(p)]
    ev.insert(0, dict(ev[0], kind="expectation_registered", phase="EXPECTATION_REGISTERED"))
    open(p, "w").write("".join(json.dumps(e, sort_keys=True) + "\\n" for e in ev))
''')
    code, rep, out, err = verify(rd, repo)
    return res("A requires the expectation to precede the action (verify.py:267-268 claim)",
               "A=%s; %s" % (check_of(rep, "A")["result"], verdict_line(out)), check_of(rep, "A")["result"] == "fails",
               note="host-A journal edited to add the expectation_registered event the new scenarios-ran check requires")


@test("V34", "Verifier robustness: four damaged inputs", "earlier")
def v34():
    out_ = {}
    for name, fn in {
        "torn host-B": lambda d: open(J(d, "host-B.jsonl"), "wb").write(open(J(d, "host-B.jsonl"), "rb").read()[:-30]),
        "reconciled.json malformed": lambda d: open(J(d, "reconciled.json"), "w").write('{"gaps": ['),
        "signature is an int": lambda d: save(J(d, "store.jsonl"), reframe([dict(r, record=dict(r["record"], signature=12345)) if r.get("action_id") == "D-4005" and r["kind"] == "verdict" else r for r in load(J(d, "store.jsonl"))])),
        "host-B deleted": lambda d: os.remove(J(d, "host-B.jsonl")),
    }.items():
        d = base()
        fn(d)
        code, rep, o, e = verify(d)
        out_[name] = (code, rep is not None, (failed(rep) or [])[:4])
    return res("each damage gives exit 1 and a written report, no traceback",
               "; ".join("%s: exit=%s report=%s failed=%s" % (k, *v) for k, v in out_.items()),
               all(v[0] == 1 and v[1] for v in out_.values()))


@test("V35", "regressions.py against the first-audit repository (claim: each mode beat the old verifier)", "runner")
def v35():
    old = os.environ.get("HFB_OLD_REPO")
    if not old:
        return res("n/a", "HFB_OLD_REPO not set", None)
    p = subprocess.run([PY, J(REPO, "audit", "regressions.py"), "f1", "--repo", old], capture_output=True, text=True, timeout=300)
    return res("the shipped script can reproduce 'each mode beat verify.py at 25cd57f'",
               "rc=%s stdout=%r stderr_tail=%r" % (p.returncode, p.stdout.strip()[-120:], last_line(p.stderr)),
               p.returncode == 1 and "MISSED" in p.stdout, scope="the earlier zip is not commit 25cd57f; no git history ships")


@test("V36", "One idle connection blocks the store (old T37, documented as open)", "earlier")
def v36():
    d = tempfile.mkdtemp(prefix="dos-")
    with Store(J(d, "s.jsonl")) as st:
        idle = socket.create_connection(("127.0.0.1", st.port))
        try:
            st.call({"cmd": "state"}, timeout=2)
            r = "answered"
        except socket.timeout:
            r = "timed out after 2 s"
        idle.close()
    return res("(documented open item) second client served", r, r == "answered", informational=True)


def main():
    global BASE
    only = set(sys.argv[1:])
    BASE, p = fresh_run()
    code, rep, out, err = verify(copy_run(BASE))
    print("baseline run %s -> verify exit %s, %s" % (BASE, code, verdict_line(out)), flush=True)
    for tid, title, group, fn in TESTS:
        if only and tid not in only:
            continue
        t0 = time.time()
        try:
            r = fn()
        except subprocess.TimeoutExpired as e:
            r = res("?", "TIMEOUT: %s" % e, None, hang=True)
        except Exception:
            r = res("?", "HARNESS ERROR\n" + traceback.format_exc(), None)
        r.update(id=tid, title=title, group=group, seconds=round(time.time() - t0, 2))
        RESULTS.append(r)
        tag = ("STATIC " if r.get("static") else "INFO   " if r.get("informational") else
               "AS-DOC " if r["holds"] else "DEFECT " if r["holds"] is False else "N/A    ")
        print("\n[%s] %s %s (%.1fs)\n   expected: %s\n   observed: %s%s%s" % (
            tid, tag, title, r["seconds"], r["expected"], r["observed"],
            ("\n   note: " + r["note"]) if r.get("note") else "",
            ("\n   scope: " + r["scope"]) if r.get("scope") else ""), flush=True)
    with open(J(os.path.dirname(os.path.abspath(__file__)), "v2results.json"), "w") as fh:
        json.dump(RESULTS, fh, indent=2, default=str)


if __name__ == "__main__":
    main()
