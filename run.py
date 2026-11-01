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

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "bench")
STORE = os.path.join(BENCH, "store.py")
HOST = os.path.join(BENCH, "host.py")

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
        deadline = time.time() + 10
        while time.time() < deadline:
            if os.path.exists(self.port_file):
                with open(self.port_file, encoding="utf-8") as fh:
                    text = fh.read().strip()
                if text:
                    self.port = int(text)
                    return
            if self.proc.poll() is not None:
                raise SystemExit("store exited during startup: %s" % self.proc.stderr.read())
            time.sleep(0.02)
        raise SystemExit("store did not announce a port within 10 seconds")

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

    reconciled = call(store.port, {"cmd": "reconcile"})
    state = call(store.port, {"cmd": "state"})
    lookups["A"] = call(store.port, {"cmd": "lookup", "action_id": "A-1042"})
    lookups["A'"] = call(store.port, {"cmd": "lookup", "action_id": "A-1043"})
    lookups["B"] = call(store.port, {"cmd": "lookup", "action_id": "B-2001"})

    manifest = {
        "python": sys.version.split()[0],
        "scenarios": [s for s, _ in SCENARIOS] + ["B"],
        "artifacts": sorted(os.listdir(rundir)),
    }
    with open(os.path.join(rundir, "manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    with open(os.path.join(rundir, "reconciled.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(reconciled, fh, indent=2, sort_keys=True)
    with open(os.path.join(rundir, "store-state.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
    with open(os.path.join(rundir, "lookups.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(lookups, fh, indent=2, sort_keys=True)

    store.stop()
    print("")
    print("run finished. A finished run is not a pass.")
    print("  python verify.py %s" % os.path.relpath(rundir, HERE))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
