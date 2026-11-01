#!/usr/bin/env python3
"""Run every scenario and collect the raw artifacts. It asserts nothing.

That separation is the point. This file produces evidence; `verify.py` reads the evidence and
decides, without trusting anything this file printed. A run that finishes is not a pass.

    python run.py
    python verify.py artifacts/run-20261101T120000Z

Standard library only. No model, no external key, no network beyond loopback.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import time

# What a verifiable run has to produce. Declared here and written into the manifest, so a
# missing artifact is a named missing artifact and not a shorter directory listing.
REQUIRED_ARTIFACTS = ["store.jsonl", "host-A.jsonl", "host-Ap.jsonl", "host-B.jsonl",
                      "host-C.jsonl", "host-Cp.jsonl", "host-Cpp.jsonl", "host-D.jsonl",
                      "host-Dp.jsonl", "wal-B.jsonl", "reconciled.json", "store-state.json",
                      "lookups.json",
                      # The probes: small, separate, and named for the property each one
                      # isolates, so a failure in one does not read as a failure in the suite.
                      "probe-durability/journal.jsonl", "probe-durability/result.json",
                      "probe-repair/journal.jsonl",
                      "probe-repair/journal.jsonl.quarantine-1.bin",
                      "probe-reply/host-E.jsonl"]

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "bench")
STORE = os.path.join(BENCH, "store.py")
HOST = os.path.join(BENCH, "host.py")
STUB = os.path.join(BENCH, "stub_store.py")

sys.path.insert(0, BENCH)
from common import DECIDED_BY, POLICY_SHA, frame, record_payload, sign  # noqa: E402

# scenario name, extra host flags
SCENARIOS = [
    ("A", ["--action-id", "A-1042"]),
    ("A'", ["--action-id", "A-1043", "--no-register"]),
    ("C", ["--action-id", "C-3003"]),
    ("C'", ["--action-id", "C-3004", "--issue-only"]),
    ("C''", ["--action-id", "C-3005", "--local-id"]),
    ("D", ["--action-id", "D-4004"]),
    ("D'", ["--action-id", "D-4005"]),
]


def announce_port(proc, port_file, what="store"):
    """Wait for a process to write its port, and say plainly if it never does."""
    deadline = time.time() + 10
    while time.time() < deadline:
        if os.path.exists(port_file):
            with open(port_file, encoding="utf-8") as fh:
                text = fh.read().strip()
            if text:
                return int(text)
        if proc.poll() is not None:
            raise SystemExit("%s exited during startup: %s" % (what, proc.stderr.read()))
        time.sleep(0.02)
    raise SystemExit("%s did not announce a port within 10 seconds" % what)


class StoreProcess:
    def __init__(self, rundir):
        self.rundir = rundir
        self.port_file = os.path.join(rundir, "port.txt")
        self.proc = None
        self.port = None

    def start(self):
        if os.path.exists(self.port_file):
            os.remove(self.port_file)
        self.proc = subprocess.Popen(
            [sys.executable, STORE, "--journal", os.path.join(self.rundir, "store.jsonl"),
             "--announce", self.port_file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.port = announce_port(self.proc, self.port_file)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None


def call(port, req):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf.decode("utf-8"))


def run_host(scenario, port, rundir, flags):
    journal = "host-%s.jsonl" % scenario.replace("'", "p")
    cmd = [sys.executable, HOST, "--scenario", scenario, "--port", str(port),
           "--workdir", rundir, "--journal", journal] + flags
    proc = subprocess.run(cmd, capture_output=True, text=True)
    print("  host %-3s exit %s" % (scenario, proc.returncode))
    return proc


def stop(proc):
    if proc is None:
        return
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    for stream in (proc.stdout, proc.stderr):
        if stream:
            stream.close()


def launch_store(rundir, journal, env=None, announce_name="port.txt"):
    """Start a store on a named journal, from a named directory, with an environment."""
    announce = os.path.join(rundir, announce_name)
    if os.path.exists(announce):
        os.remove(announce)
    proc = subprocess.Popen(
        [sys.executable, STORE, "--journal", journal, "--announce", announce],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=dict(os.environ, **(env or {})),
    )
    return proc, announce_port(proc, announce)


def write_json(path, payload):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)


def probe_durability(rundir):
    """F11: the journal refuses a verdict write. Nothing may be known that is not on disk.

    The failpoint refuses before the bytes are written, which is the exact moment the order of
    the two operations decides the answer: journal then memory leaves nothing behind, memory
    then journal leaves a store that reports a decision it could not keep.
    """
    pdir = os.path.join(rundir, "probe-durability")
    os.makedirs(pdir, exist_ok=True)
    journal = os.path.join(pdir, "journal.jsonl")
    aid = "P-9001"
    record = {"action_id": aid, "policy_sha": POLICY_SHA, "decided_by": DECIDED_BY,
              "verdict": "BLOCK", "rule": "R7", "descriptor_sha": "sha256:" + "0" * 64,
              "decision_ts": 3}
    record["signature"] = sign(record_payload(record))
    result = {}
    proc, port = launch_store(pdir, journal, {"HFB_FAILPOINT": "verdict"})
    try:
        result["issue"] = call(port, {"cmd": "issue", "action_id": aid})
        result["expect"] = call(port, {"cmd": "expect", "action_id": aid,
                                       "policy_sha": POLICY_SHA})
        result["verdict"] = call(port, {"cmd": "verdict", "record": record})
        result["lookup_same_process"] = call(port, {"cmd": "lookup", "action_id": aid})
    finally:
        stop(proc)
    proc, port = launch_store(pdir, journal)
    try:
        result["lookup_after_restart"] = call(port, {"cmd": "lookup", "action_id": aid})
        result["state_after_restart"] = call(port, {"cmd": "state"})
    finally:
        stop(proc)
    result["action_id"] = aid
    write_json(os.path.join(pdir, "result.json"), result)


def probe_repair(rundir):
    """F7: a torn journal is repaired, and the bytes it loses are kept rather than dropped."""
    pdir = os.path.join(rundir, "probe-repair")
    os.makedirs(pdir, exist_ok=True)
    journal = os.path.join(pdir, "journal.jsonl")
    lines = []
    for seq, aid in ((1, "R-7001"), (2, "R-7002")):
        rec = {"kind": "issued", "action_id": aid, "store_seq": seq}
        rec["digest"] = frame(rec)
        lines.append(json.dumps(rec, sort_keys=True))
    # The third record stops in the middle, the way a crash during an append leaves it.
    torn = '{"action_id": "R-7003", "digest": "half', 0
    with open(journal, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n" + torn[0])
        fh.flush()
        os.fsync(fh.fileno())
    proc, _port = launch_store(pdir, journal)
    stop(proc)


def probe_conflict(port, rundir):
    """F9: two signed verdicts for one action. The store says so instead of picking one."""
    aid = "C-9009"
    call(port, {"cmd": "issue", "action_id": aid})
    call(port, {"cmd": "commit", "action_id": aid, "descriptor_sha": "sha256:" + "1" * 64})
    first = {"action_id": aid, "policy_sha": POLICY_SHA, "decided_by": DECIDED_BY,
             "verdict": "BLOCK", "rule": "R7", "descriptor_sha": "sha256:" + "1" * 64,
             "decision_ts": 4}
    first["signature"] = sign(record_payload(first))
    call(port, {"cmd": "verdict", "record": first})
    second = dict(first, verdict="ALLOW", rule=None, decision_ts=5)
    second.pop("signature")
    second["signature"] = sign(record_payload(second))
    call(port, {"cmd": "verdict", "record": second})


def probe_reply(rundir):
    """F10: a well-formed reply about another action. It must not be read as consent."""
    pdir = os.path.join(rundir, "probe-reply")
    os.makedirs(pdir, exist_ok=True)
    announce = os.path.join(pdir, "port.txt")
    if os.path.exists(announce):
        os.remove(announce)
    proc = subprocess.Popen([sys.executable, STUB, "--announce", announce],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        port = announce_port(proc, announce, what="stub store")
        run_host("E", port, pdir, ["--action-id", "E-6006"])
    finally:
        stop(proc)


def artifact_listing(rundir):
    """Every file the run wrote, as paths relative to the run directory."""
    out = []
    for root, dirs, files in os.walk(rundir):
        dirs.sort()
        for name in sorted(files):
            rel = os.path.relpath(os.path.join(root, name), rundir).replace(os.sep, "/")
            if rel.endswith("port.txt"):
                continue
            out.append(rel)
    return sorted(out)


def main(argv):
    base = time.strftime("run-%Y%m%dT%H%M%SZ", time.gmtime())
    rundir = os.path.join(HERE, "artifacts", base)
    # Two runs inside the same second must not share a journal, or the second run silently
    # appends to the first one's record and every count after that is wrong.
    suffix = 2
    while os.path.exists(rundir):
        rundir = os.path.join(HERE, "artifacts", "%s-%d" % (base, suffix))
        suffix += 1
    os.makedirs(rundir)
    print("artifacts -> %s" % rundir)

    store = StoreProcess(rundir)
    print("[store] starting")
    store.start()
    print("[store] port %d" % store.port)

    for scenario, flags in SCENARIOS[:2]:
        run_host(scenario, store.port, rundir, flags)

    # M1 stays available while M2 needs the store to be gone. Recovery is a restart, because a
    # restart that replays its journal is exactly what the store is supposed to survive.
    print("[store] stopping, so the ship in B can fail for a real reason")
    store.stop()
    run_host("B", store.port, rundir, ["--phase", "initial", "--action-id", "B-2001"])
    print("[store] restarting from its journal")
    store.start()
    print("[store] port %d" % store.port)
    run_host("B", store.port, rundir, ["--phase", "replay", "--action-id", "B-2001"])

    lookups = {}
    for scenario, flags in SCENARIOS[2:]:
        run_host(scenario, store.port, rundir, flags)
        aid = {"C": "C-3003", "C'": "C-3004", "C''": "C-3005",
               "D": "D-4004", "D'": "D-4005"}[scenario]
        lookups[scenario] = call(store.port, {"cmd": "lookup", "action_id": aid})

    print("[probe] conflict: two verdicts for one action id")
    probe_conflict(store.port, rundir)

    reconciled = call(store.port, {"cmd": "reconcile"})
    state = call(store.port, {"cmd": "state"})
    lookups["A"] = call(store.port, {"cmd": "lookup", "action_id": "A-1042"})
    lookups["A'"] = call(store.port, {"cmd": "lookup", "action_id": "A-1043"})
    lookups["B"] = call(store.port, {"cmd": "lookup", "action_id": "B-2001"})

    write_json(os.path.join(rundir, "reconciled.json"), reconciled)
    write_json(os.path.join(rundir, "store-state.json"), state)
    write_json(os.path.join(rundir, "lookups.json"), lookups)

    # The probes run against their own journals except the conflict one, which needs the main
    # store to be able to show what a duplicate verdict does to an action already recorded.
    print("[probe] durability: a journal that refuses a verdict write")
    probe_durability(rundir)
    print("[probe] repair: a torn journal, and where its tail goes")
    probe_repair(rundir)
    print("[probe] reply: a store that confirms the wrong action")
    probe_reply(rundir)

    # Written last, and without the port file: the port changes per run, and the rest of this
    # suite is byte-identical between runs. The manifest is the claim about what should be here.
    manifest = {
        "manifest_version": 2,
        "python": sys.version.split()[0],
        "scenarios": [s for s, _ in SCENARIOS] + ["B"],
        "required": sorted(REQUIRED_ARTIFACTS),
        "artifacts": artifact_listing(rundir),
    }
    with open(os.path.join(rundir, "manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)

    store.stop()
    print("")
    print("run finished. A finished run is not a pass.")
    print("  python verify.py %s" % os.path.relpath(rundir, HERE))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
