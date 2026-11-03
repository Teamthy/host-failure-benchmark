"""Helpers for the regression audit of the revised host-failure-benchmark.

Nothing here edits the checkout named by HFB_REPO. Every test works on a copy of a fresh run, or on
a patched copy of the repository.
"""
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

REPO = os.path.abspath(os.environ.get("HFB_REPO", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "hfb")))
PY = sys.executable
IGNORE = shutil.ignore_patterns("artifacts", "__pycache__", "*.pyc", "verify-report.json")


def common_of(repo=REPO):
    spec = importlib.util.spec_from_file_location("hfb_common_%d" % abs(hash(repo)),
                                                  os.path.join(repo, "bench", "common.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


common = common_of()


def J(d, *names):
    return os.path.join(d, *names)


# ------------------------------------------------------------------ repo copies and runs
def copy_repo(name, edits=None):
    dst = os.path.join(tempfile.mkdtemp(prefix="v2-%s-" % name), "hfb")
    shutil.copytree(REPO, dst, ignore=IGNORE)
    for rel, pairs in (edits or {}).items():
        p = J(dst, rel)
        src = open(p, encoding="utf-8").read()
        for old, new in pairs:
            assert src.count(old) == 1, (rel, old[:60], src.count(old))
            src = src.replace(old, new)
        open(p, "w", encoding="utf-8", newline="\n").write(src)
    return dst


HOOKED_RUN = [(
    '    print("[store] restarting from its journal")\n',
    '    _audit_hook("before_restart", rundir, None)\n    print("[store] restarting from its journal")\n'), (
    '    lookups = {}\n    for scenario, flags in SCENARIOS[2:]:',
    '    _audit_hook("after_replay", rundir, store.port)\n    lookups = {}\n    for scenario, flags in SCENARIOS[2:]:'), (
    'def main(argv):\n',
    'def _audit_hook(name, rundir, port):\n'
    '    path = os.environ.get("AUDIT_HOOK_FILE")\n'
    '    if not path:\n        return\n'
    '    import importlib.util as _u\n'
    '    spec = _u.spec_from_file_location("audit_hook", path)\n'
    '    mod = _u.module_from_spec(spec)\n    spec.loader.exec_module(mod)\n'
    '    fn = getattr(mod, name, None)\n'
    '    if fn:\n        fn(rundir, port)\n\n\ndef main(argv):\n')]


def hooked_repo(name, extra_edits=None):
    edits = {"run.py": list(HOOKED_RUN)}
    for k, v in (extra_edits or {}).items():
        edits.setdefault(k, []).extend(v)
    return copy_repo(name, edits)


def fresh_run(repo=REPO, hook_source=None, timeout=180, env_extra=None):
    """Run run.py in a throwaway copy (or in `repo` if it is already a copy). Returns rundir, proc."""
    if repo == REPO:
        repo = copy_repo("run")
    env = dict(os.environ, **(env_extra or {}))
    if hook_source:
        hp = J(os.path.dirname(repo), "audit_hook.py")
        open(hp, "w").write(hook_source)
        env["AUDIT_HOOK_FILE"] = hp
    p = subprocess.run([PY, "run.py"], cwd=repo, capture_output=True, text=True, env=env,
                       timeout=timeout)
    runs = sorted(os.listdir(J(repo, "artifacts")))
    return J(repo, "artifacts", runs[-1]), p


def copy_run(src):
    dst = tempfile.mkdtemp(prefix="v2run-")
    for root, dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        tgt = dst if rel == "." else J(dst, rel)
        os.makedirs(tgt, exist_ok=True)
        for f in files:
            if f != "verify-report.json":
                shutil.copy2(J(root, f), J(tgt, f))
    return dst


def verify(rundir, repo=REPO, timeout=120):
    rp = J(rundir, "verify-report.json")
    if os.path.exists(rp):
        os.remove(rp)
    p = subprocess.run([PY, J(repo, "verify.py"), rundir], capture_output=True, text=True,
                       timeout=timeout)
    rep = json.load(open(rp)) if os.path.exists(rp) else None
    return p.returncode, rep, p.stdout, p.stderr


def failed(rep):
    return sorted(r["id"] for r in rep["checks"] if r["result"] == "fails") if rep else None


def verdict_line(out):
    return next((l for l in out.splitlines() if l.startswith("VERDICT")), "(no VERDICT line)")


def check_of(rep, cid):
    return next((r for r in rep["checks"] if r["id"] == cid), None)


# ------------------------------------------------------------------ journals
def load(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def save(path, recs):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for r in recs:
            fh.write(json.dumps(r, sort_keys=True) + "\n")


def append_row(path, row):
    recs = load(path)
    row = dict(row)
    row["store_seq"] = max(r.get("store_seq", 0) for r in recs) + 1
    row["digest"] = common.frame(row)
    with open(path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")
    return row


def reframe(recs, renumber=False):
    for i, r in enumerate(recs, start=1):
        if renumber:
            r["store_seq"] = i
        r["digest"] = common.frame(r)
    return recs


def resign(record):
    record["signature"] = common.sign(common.record_payload(record))
    return record


# ------------------------------------------------------------------ live store
class Store:
    def __init__(self, journal, repo=REPO, env=None, announce=None):
        self.journal, self.repo, self.env = journal, repo, env
        self.announce = announce or (journal + ".port")

    def __enter__(self):
        if os.path.exists(self.announce):
            os.remove(self.announce)
        self.proc = subprocess.Popen([PY, J(self.repo, "bench", "store.py"), "--journal",
                                      self.journal, "--announce", self.announce],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     env=dict(os.environ, **(self.env or {})))
        t0 = time.time()
        while time.time() - t0 < 15:
            if os.path.exists(self.announce):
                t = open(self.announce).read().strip()
                if t:
                    self.port = int(t)
                    return self
            if self.proc.poll() is not None:
                raise RuntimeError("store died: " + self.proc.stderr.read())
            time.sleep(0.02)
        raise RuntimeError("store did not announce")

    def call(self, req, timeout=5):
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as s:
            s.sendall((json.dumps(req) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                c = s.recv(65536)
                if not c:
                    break
                buf += c
        return json.loads(buf) if buf else None

    def __exit__(self, *a):
        self.proc.terminate()
        try:
            self.out, self.err = self.proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.out, self.err = self.proc.communicate()


def strip_trailing_boots(path, keep_upto_seq):
    """Remove boot records a test's own store start appended after seq `keep_upto_seq`."""
    recs = [r for r in load(path) if not (r.get("kind") == "boot" and r["store_seq"] > keep_upto_seq)]
    save(path, reframe(recs, renumber=True))


def regenerate_reconciled(rundir, repo=REPO):
    """Re-derive reconciled.json and store-state.json with the store's own commands."""
    path = J(rundir, "store.jsonl")
    last = max(r["store_seq"] for r in load(path))
    with Store(path, repo) as st:
        rec = st.call({"cmd": "reconcile"})
        state = st.call({"cmd": "state"})
    recs = [r for r in load(path) if r["store_seq"] <= last]
    save(path, recs)  # drop the boot record our own start appended
    for name, obj in (("reconciled.json", rec), ("store-state.json", state)):
        with open(J(rundir, name), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, indent=2, sort_keys=True)
    return rec, state


def run_host(repo, scenario, port, workdir, flags, timeout=60):
    journal = "host-%s.jsonl" % scenario.replace("'", "p")
    return subprocess.run([PY, J(repo, "bench", "host.py"), "--scenario", scenario, "--port",
                           str(port), "--workdir", workdir, "--journal", journal] + flags,
                          capture_output=True, text=True, timeout=timeout)


def last_line(s):
    s = (s or "").strip().splitlines()
    return s[-1] if s else ""
