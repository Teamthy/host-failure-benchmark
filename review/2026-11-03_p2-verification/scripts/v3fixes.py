"""Adversarial tests of the two input-handling fixes in df0cf5a (verify.py:735-741, 652-673, 705-716).

    HFB_REPO=/path/to/df0cf5a-checkout python3 v3fixes.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v2lib import REPO, PY, J, copy_run, fresh_run  # noqa

VERIFY = J(REPO, "verify.py")
OUT = []


def run(*args, cwd=None):
    p = subprocess.run([PY, VERIFY] + list(args), capture_output=True, text=True, timeout=120, cwd=cwd)
    tb = "Traceback" in p.stdout + p.stderr
    last = (p.stdout.strip().splitlines() or [""])[-1]
    return p.returncode, tb, last, p


def det(rundir):
    rep = json.load(open(J(rundir, "verify-report.json")))
    row = next((r for r in rep["checks"] if r["id"] == "determinism"), None)
    return (row["result"], row["evidence"]) if row else (None, None)


def t(name, expected, observed, ok):
    OUT.append(dict(name=name, expected=expected, observed=observed, as_documented=ok))
    print("[%s] %s\n   expected: %s\n   observed: %s" % ("AS-DOC" if ok else "DEFECT", name, expected, observed), flush=True)


def main():
    base, _ = fresh_run()
    tmp = tempfile.mkdtemp(prefix="v3fix-")

    code, tb, last, p = run(J(tmp, "does-not-exist"))
    t("N01 nonexistent run directory", "exit 2, message, no traceback, no report",
      "exit=%s traceback=%s last=%r" % (code, tb, last), code == 2 and not tb)

    f = J(tmp, "a-file")
    open(f, "w").write("x")
    code, tb, last, p = run(f)
    t("N02 path is a regular file", "exit 2", "exit=%s traceback=%s" % (code, tb), code == 2 and not tb)

    e = J(tmp, "empty")
    os.makedirs(e)
    code, tb, last, p = run(e)
    t("N03 empty existing directory", "non-zero, no traceback (2 'nothing verified' or 1 'failed')",
      "exit=%s traceback=%s last=%r report_written=%s" % (code, tb, last, os.path.exists(J(e, "verify-report.json"))),
      code != 0 and not tb)

    a = copy_run(base)
    code, tb, last, p = run(a, J(tmp, "nope"))
    r, ev = det(a)
    t("N04 second directory missing", "determinism fails naming the directory; exit 1",
      "exit=%s determinism=%s missing_directories=%s" % (code, r, ev.get("missing_directories")),
      code == 1 and r == "fails")

    a = copy_run(base)
    b = copy_run(base)
    os.remove(J(b, "wal-B.jsonl"))
    code, tb, last, p = run(a, b)
    r, ev = det(a)
    t("N05 second run missing one artifact", "determinism fails", "exit=%s determinism=%s missing=%s" % (
        code, r, ev.get("missing_artifacts")), r == "fails")

    a = copy_run(base)
    code, tb, last, p = run(a, a)
    r, ev = det(a)
    t("N06 a run compared with itself (same path)", "refused: one directory is not two runs",
      "exit=%s determinism=%s" % (code, r), r == "fails")

    a = copy_run(base)
    b = copy_run(base)
    code, tb, last, p = run(a, b)
    r, ev = det(a)
    t("N07 a run compared with a byte copy of itself", "(limit) indistinguishable from two runs",
      "exit=%s determinism=%s" % (code, r), True)

    a = copy_run(base)
    b = copy_run(base)
    with open(J(b, "probe-repair", "journal.jsonl.quarantine-2.bin"), "wb") as fh:
        fh.write(b"extra")
    m = json.load(open(J(b, "manifest.json")))
    m["python"] = "9.9.9"
    json.dump(m, open(J(b, "manifest.json"), "w"))
    code, tb, last, p = run(a, b)
    r, ev = det(a)
    t("N08 second run has an extra file and a different manifest", "(by design) only ARTIFACT_FILES compared",
      "exit=%s determinism=%s" % (code, r), True)

    a = copy_run(base)
    os.makedirs(J(a, "verify-report.json"))
    code, tb, last, p = run(a)
    t("N09 report path unwritable (a directory), valid run", "verdict printed, exit 0, no traceback",
      "exit=%s traceback=%s last=%r" % (code, tb, last), code == 0 and not tb)

    a = copy_run(base)
    os.remove(J(a, "host-A.jsonl"))
    os.makedirs(J(a, "verify-report.json"))
    code, tb, last, p = run(a)
    t("N10 report path unwritable, failing run", "exit 1, no traceback", "exit=%s traceback=%s" % (code, tb),
      code == 1 and not tb)

    a = copy_run(base)
    stale = {"checks": [{"id": "B", "result": "holds"}], "summary": {"failures": []}}
    json.dump(stale, open(J(a, "verify-report.json"), "w"))
    os.remove(J(a, "host-A.jsonl"))
    rc_attr = subprocess.run(["chattr", "+i", J(a, "verify-report.json")], capture_output=True, text=True)
    if rc_attr.returncode == 0:
        code, tb, last, p = run(a)
        left = json.load(open(J(a, "verify-report.json")))
        subprocess.run(["chattr", "-i", J(a, "verify-report.json")])
        t("N11 stale passing report that cannot be overwritten, failing run",
          "a consumer cannot mistake the stale file for this verdict",
          "exit=%s; file left says failures=%s" % (code, left["summary"]["failures"]), False)
    else:
        t("N11 stale unwritable report", "n/a", "not testable here: chattr +i refused (%s)" % rc_attr.stderr.strip(), True)

    # N12 challenge.py's input check uses a fixed temp path
    fixed = J(tempfile.gettempdir(), "hfb-no-such-run-4f2a")
    shutil.rmtree(fixed, ignore_errors=True)
    shutil.copytree(base, fixed)
    a = copy_run(base)
    p = subprocess.run([PY, J(REPO, "challenge.py"), a], capture_output=True, text=True, timeout=300)
    line = [l for l in p.stdout.splitlines() if "not there" in l]
    shutil.rmtree(fixed, ignore_errors=True)
    t("N12 challenge.py when its fixed 'no-such-run' path exists", "the input check still tests a missing path",
      "challenge exit=%s; %s" % (p.returncode, line[0].strip() if line else "?"), p.returncode == 0)

    # N13 challenge.py leaves a failing report in the run it was given
    a = copy_run(base)
    p = subprocess.run([PY, J(REPO, "challenge.py"), a], capture_output=True, text=True, timeout=300)
    left = json.load(open(J(a, "verify-report.json")))
    t("N13 report left in the evidence directory after challenge.py", "the run's own report reflects the run (all hold)",
      "challenge exit=%s; %s/verify-report.json failures=%s" % (p.returncode, "<run>", left["summary"]["failures"]),
      not left["summary"]["failures"])

    json.dump(OUT, open(J(os.path.dirname(os.path.abspath(__file__)), "v3fixes.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
