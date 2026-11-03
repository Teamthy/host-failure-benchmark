"""P2 probes: V04 and clock-skew variants, a fingerprint-based N13, new-regression probes, and a
feasibility check for the "open" completeness cases.

    HFB_REPO=/path/to/006d7ee-checkout python3 p2probes.py [ID ...]

Writes p2probes.json next to this file. Never writes to HFB_REPO.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v2lib import (J, PY, REPO, Store, append_row, check_of, common, copy_repo, copy_run,  # noqa
                   failed, fresh_run, hooked_repo, load, reframe, regenerate_reconciled, resign,
                   save, verdict_line, verify)

OUT = []
TESTS = []


def test(tid, title, kind):
    def deco(fn):
        TESTS.append((tid, title, kind, fn))
        return fn
    return deco


def res(expected, observed, outcome, **kw):
    d = dict(expected=expected, observed=observed, outcome=outcome)
    d.update(kw)
    return d


def bcheck(rep):
    return {k: (check_of(rep, k) or {}).get("result") for k in ("B", "B.wal", "B.decision", "no-wall-clock")}


# ----------------------------------------------------------------------------- V04 family
V04_HOST = {"bench/host.py": [(
    '            aid = record["action_id"]\n            if self.require({"cmd": "verdict", "record": record}',
    '            aid = record["action_id"]\n'
    '            _orig = json.dumps(record, sort_keys=True)\n'
    '            record["decision_ts"] = self.clock.step + int(os.environ.get("AUDIT_DELTA", "1"))\n'
    '            record["signature"] = sign(record_payload(record))\n'
    '            with open(os.path.join(os.path.dirname(self.journal_path), "audit-v04.json"), "w") as _fh:\n'
    '                json.dump({"replay_step": self.clock.step, "new_ts": record["decision_ts"],\n'
    '                           "identical_to_wal": json.dumps(record, sort_keys=True) == _orig}, _fh)\n'
    '            if self.require({"cmd": "verdict", "record": record}')]}


def v04_run(delta):
    repo = copy_repo("v04d%s" % delta, V04_HOST)
    rd, p = fresh_run(repo, env_extra={"AUDIT_DELTA": str(delta)})
    info = json.load(open(J(rd, "audit-v04.json")))
    os.remove(J(rd, "audit-v04.json"))
    code, rep, out, err = verify(rd, REPO)
    return info, code, rep, out


@test("P01", "V04 exactly as shipped (replay stamps step+1)", "V04")
def p01():
    info, code, rep, out = v04_run(1)
    return res("if the mutation is inert, the re-signed record equals the WAL record byte for byte",
               "replay_step=%s new_ts=%s identical_to_wal=%s; verify exit=%s %s" % (
                   info["replay_step"], info["new_ts"], info["identical_to_wal"], code, bcheck(rep)),
               "developer claim reproduced" if info["identical_to_wal"] and code == 0 else "developer claim NOT reproduced")


@test("P02", "Clock-skew variant: replay stamps step+5 and re-signs", "V04")
def p02():
    info, code, rep, out = v04_run(5)
    return res("caught (B and/or B.wal fail)",
               "replay_step=%s new_ts=%s identical_to_wal=%s; verify exit=%s %s" % (
                   info["replay_step"], info["new_ts"], info["identical_to_wal"], code, bcheck(rep)),
               "detected" if code != 0 else "NOT detected")


SKEW_HOOK = '''
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "hfb", "bench"))
from common import record_payload, sign
TS = %d
def before_restart(rundir, port):
    # A source holder shifts the decision time consistently in every host-written artifact.
    w = os.path.join(rundir, "wal-B.jsonl")
    r = json.loads(open(w).read().splitlines()[0])
    r["decision_ts"] = TS
    r["signature"] = sign(record_payload(r))
    open(w, "w", newline="\\n").write(json.dumps(r, sort_keys=True) + "\\n")
    h = os.path.join(rundir, "host-B.jsonl")
    ev = [json.loads(l) for l in open(h) if l.strip()]
    for e in ev:
        if e["run"] == "initial" and e["kind"] == "guard_decision":
            e["step"] = TS
        if e["run"] == "initial" and e["kind"] == "wal_commit":
            e["step"] = TS + 1
            e["decision_ts"] = TS
    open(h, "w", newline="\\n").write("".join(json.dumps(e, sort_keys=True) + "\\n" for e in ev))
'''


@test("P03", "Consistent skew in every host-written artifact (decision_ts 1 instead of 2)", "V04")
def p03():
    repo = hooked_repo("p03")
    rd, p = fresh_run(repo, SKEW_HOOK % 1)
    code, rep, out, err = verify(rd, REPO)
    return res("(attestation test) an independent clock would refuse a decision time the host rewrote",
               "verify exit=%s %s; %s" % (code, bcheck(rep), verdict_line(out)),
               "accepted: divergence detection only" if code == 0 else "rejected")


@test("P04", "Consistent wall-clock decision time (Unix epoch) in every host-written artifact", "V04")
def p04():
    repo = hooked_repo("p04")
    rd, p = fresh_run(repo, SKEW_HOOK % 1793577600)
    code, rep, out, err = verify(rd, REPO)
    return res("no-wall-clock fails, or B refuses a decision time outside the counter's range",
               "verify exit=%s %s; %s" % (code, bcheck(rep), verdict_line(out)),
               "accepted" if code == 0 else "rejected")


# ----------------------------------------------------------------------------- N13 revised
def inventory(d):
    out = {}
    for root, dirs, files in os.walk(d):
        for f in files:
            p = J(root, f)
            out[os.path.relpath(p, d)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return out


def tmp_listing():
    t = tempfile.gettempdir()
    return set(os.listdir(t))


@test("P05", "N13 revised: sha256 inventory of the evidence directory before and after challenge.py", "N13")
def p05():
    results = {}
    for label, src in (("example/run", J(REPO, "example", "run")), ("fresh run", None)):
        d = copy_run(src) if src else copy_run(fresh_run()[0])
        # include a pre-existing report, as a reader's directory would have after verify.py
        subprocess.run([PY, J(REPO, "verify.py"), d], capture_output=True)
        before = inventory(d)
        t0 = tmp_listing()
        p = subprocess.run([PY, J(REPO, "challenge.py"), d], capture_output=True, text=True, timeout=300)
        after = inventory(d)
        leaked = sorted(x for x in tmp_listing() - t0)
        changed = sorted(set(before) ^ set(after)) + sorted(k for k in set(before) & set(after) if before[k] != after[k])
        claim = [l for l in p.stdout.splitlines() if "pointed me at is unchanged" in l]
        results[label] = dict(exit=p.returncode, files=len(before), changed=changed,
                              tool_says=claim[0].split()[-6:] if claim else None, temp_left=leaked)
    ok = all(r["exit"] == 0 and not r["changed"] for r in results.values())
    return res("no file added, removed or rewritten; content hashes identical",
               json.dumps(results), "property holds" if ok else "property fails")


@test("P06", "N13 revised: does challenge.py's own fingerprint catch a challenge that writes into the run?", "N13")
def p06():
    repo = copy_repo("p06", {"challenge.py": [(
        "    after = fingerprint(rundir)\n",
        "    open(os.path.join(rundir, \"stray.txt\"), \"w\").write(\"x\")  # AUDIT\n    after = fingerprint(rundir)\n")]})
    d = copy_run(J(REPO, "example", "run"))
    p = subprocess.run([PY, J(repo, "challenge.py"), d], capture_output=True, text=True, timeout=300)
    line = [l for l in p.stdout.splitlines() if "pointed me at is unchanged" in l]
    return res("the tool reports MISSED and exits 1", "exit=%s; %s" % (p.returncode, line[0].split("  ")[-1].strip() if line else "?"),
               "detected" if p.returncode == 1 and line and "MISSED" in line[0] else "NOT detected")


# ----------------------------------------------------------------------------- new-regression probes
@test("P07", "A torn tail cut out at runtime: is the repair announced in the journal?", "new")
def p07():
    d = tempfile.mkdtemp(prefix="p07-")
    p = J(d, "store.jsonl")
    with Store(p) as st:
        st.call({"cmd": "issue", "action_id": "T-1"})
        with open(p, "ab") as fh:
            fh.write(b'{"kind": "issued", "action_id": "T-2", "dig')
        st.call({"cmd": "issue", "action_id": "T-3"})
    with Store(p) as st:
        state = st.call({"cmd": "state"})
    kinds = [r["kind"] for r in load(p)]
    q = sorted(f for f in os.listdir(d) if ".quarantine-" in f)
    return res("a repair record names the quarantined bytes, as the start-up repair does",
               "journal kinds=%s; quarantine files=%s; issued after restart=%s" % (kinds, q, state["issued"]),
               "announced" if "repair" in kinds else "silent: bytes kept in a side file, no journal record")


IO_CASE = r'''
import json, os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "bench"))
import store as S
j = S.Journal(sys.argv[2]); s = S.Store(j)
s.handle({"cmd": "issue", "action_id": "K-1"})
rec1 = {"action_id": "K-1", "verdict": "BLOCK", "signature": None}
s.handle({"cmd": "verdict", "record": rec1})
real = S.Journal.append
def fail_on_conflict(self, record):
    if record.get("kind") == "conflict":
        raise OSError(28, "No space left on device")
    return real(self, record)
S.Journal.append = fail_on_conflict
rec2 = {"action_id": "K-1", "verdict": "ALLOW", "signature": None}
reply = s.handle({"cmd": "verdict", "record": rec2})
S.Journal.append = real
rows = [json.loads(l) for l in open(sys.argv[2]) if l.strip()]
second_on_disk = sum(1 for r in rows if r["kind"] == "verdict") == 2
live = s.handle({"cmd": "lookup", "action_id": "K-1"})["verdict_state"]
s2 = S.Store(S.Journal(sys.argv[2]))
print(json.dumps({"reply": reply, "second_verdict_on_disk": second_on_disk, "live_state": live,
                  "restart_state": s2.handle({"cmd": "lookup", "action_id": "K-1"})["verdict_state"],
                  "conflict_record": any(r["kind"] == "conflict" for r in rows)}))
'''


@test("P08", "Second verdict written, then the conflict-record append fails", "new")
def p08():
    d = tempfile.mkdtemp(prefix="p08-")
    sp = J(d, "case.py")
    open(sp, "w").write(IO_CASE)
    p = subprocess.run([PY, sp, REPO, J(d, "j.jsonl")], capture_output=True, text=True, timeout=60)
    r = json.loads(p.stdout.strip().splitlines()[-1])
    return res("the reply describes what is on disk",
               json.dumps(r),
               "reply contradicts disk" if r["reply"].get("durable") is False and r["second_verdict_on_disk"] else "consistent")


# ----------------------------------------------------------------------------- open cases: feasibility
CHECKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "extra_checks.py")


def extra(rundir):
    p = subprocess.run([PY, CHECKER, rundir], capture_output=True, text=True, timeout=60)
    return json.loads(p.stdout)


def v28_run():
    repo = hooked_repo("p09")
    rd, p = fresh_run(repo, '''
def before_restart(rundir, port):
    open(rundir + "/store.jsonl", "ab").write(b'{"action_id": "B-2001", "kind": "verd')
''')
    return rd


@test("P09", "Open cases V28, V30, V31, V32: detectable with a few checks and no signed sequence?", "open")
def p09():
    base = fresh_run()[0]
    cases = {"valid run": copy_run(base), "V28 main-journal repair": copy_run(v28_run())}
    d = copy_run(base)
    recs = load(J(d, "store.jsonl"))
    save(J(d, "store.jsonl"), [r for r in recs if not (r.get("action_id") == "D-4004" and r["kind"] in ("issued", "commitment"))])
    cases["V30 deletion, frames intact"] = d
    d = copy_run(base)
    recs = load(J(d, "store.jsonl"))
    recs.append({"kind": "issued", "action_id": "C-3006", "store_seq": max(r["store_seq"] for r in recs) + 1})
    save(J(d, "store.jsonl"), reframe(recs))
    cases["V31 invented id"] = d
    d = copy_run(base)
    recs = load(J(d, "store.jsonl"))
    for r in recs:
        if r.get("action_id") == "D-4004" and r["kind"] == "commitment":
            r["descriptor_sha"] = "sha256:" + "0" * 64
    save(J(d, "store.jsonl"), reframe(recs))
    cases["V32 commitment replaced"] = d
    out = {}
    for k, d in cases.items():
        code = verify(d)[0]
        out[k] = {"verify_exit": code, "extra_checks": extra(d)}
    fp = out["valid run"]["extra_checks"]["findings"]
    det = {k: bool(v["extra_checks"]["findings"]) for k, v in out.items() if k != "valid run"}
    return res("(feasibility) each case flagged, valid run not flagged",
               json.dumps(out), "all four detectable, no false positive" if not fp and all(det.values()) else json.dumps(det))


def main():
    only = set(sys.argv[1:])
    for tid, title, kind, fn in TESTS:
        if only and tid not in only:
            continue
        try:
            r = fn()
        except Exception:
            r = res("?", "HARNESS ERROR\n" + traceback.format_exc(), "error")
        r.update(id=tid, title=title, kind=kind)
        OUT.append(r)
        print("\n[%s] %s\n   expected: %s\n   observed: %s\n   outcome:  %s" % (
            tid, title, r["expected"], r["observed"], r["outcome"]), flush=True)
    json.dump(OUT, open(J(os.path.dirname(os.path.abspath(__file__)), "p2probes.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
