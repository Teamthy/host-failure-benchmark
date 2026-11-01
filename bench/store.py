"""Audit store: a separate process with its own journal on its own disk.

It knows only what the host told it. Every command is appended to `store.jsonl` before the
response is sent, so the journal is the record and memory is just a cache rebuilt from it.

Protocol: one JSON object per line in, one JSON object per line out.

    {"cmd": "issue", "action_id": "A-1042"}
    {"cmd": "commit", "action_id": "A-1042", "descriptor_sha": "..."}
    {"cmd": "expect", "action_id": "A-1042", "policy_sha": "..."}
    {"cmd": "verdict", "record": {...}}
    {"cmd": "lookup", "action_id": "A-1042"}
    {"cmd": "reconcile"}
    {"cmd": "state"}

No network beyond loopback, no external key, no model. On start it replays its journal, so a
restart is a recovery rather than a reset.
"""

import argparse
import json
import os
import socketserver
import sys

POLICY_SHA = "sha256:9f2c0d1b7a44e1d5c3b8a6f0e2d4c1b9a7f5e3d1c9b7a5f3e1d0c8b6a4f2e0d1"


class Journal:
    """Append-only, fsynced per record. Read back on start to rebuild state."""

    def __init__(self, path):
        self.path = path
        self.seq = 0

    def append(self, record):
        self.seq += 1
        record = dict(record)
        record["store_seq"] = self.seq
        line = json.dumps(record, sort_keys=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return record

    def replay(self):
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        self.seq = len(out)
        return out


class Store:
    """Issued ids, preserved commitments, expectations, verdicts. Nothing the host did not send."""

    def __init__(self, journal):
        self.journal = journal
        self.issued = {}
        self.commitments = {}
        self.expectations = {}
        self.verdicts = {}
        self.load()

    def load(self):
        for rec in self.journal.replay():
            self.apply(rec, persist=False)

    def apply(self, rec, persist=True):
        kind = rec.get("kind")
        aid = rec.get("action_id")
        if kind == "issued":
            self.issued[aid] = rec
        elif kind == "commitment":
            self.commitments[aid] = rec
        elif kind == "expectation":
            self.expectations[aid] = rec
        elif kind == "verdict":
            self.verdicts[aid] = rec
        if persist:
            return self.journal.append(rec)
        return rec

    # -- commands ---------------------------------------------------------------------------

    def cmd_issue(self, req):
        aid = req["action_id"]
        if aid in self.issued:
            return {"ok": True, "duplicate": True}
        self.apply({"kind": "issued", "action_id": aid})
        return {"ok": True}

    def cmd_commit(self, req):
        aid = req["action_id"]
        if aid not in self.issued:
            return {"ok": False, "error": "unknown action id: a commitment needs an issued id"}
        self.apply({"kind": "commitment", "action_id": aid, "descriptor_sha": req["descriptor_sha"]})
        return {"ok": True}

    def cmd_expect(self, req):
        aid = req["action_id"]
        self.apply({"kind": "expectation", "action_id": aid, "policy_sha": req.get("policy_sha")})
        return {"ok": True}

    def cmd_verdict(self, req):
        rec = req["record"]
        aid = rec["action_id"]
        self.apply({"kind": "verdict", "action_id": aid, "record": rec})
        return {"ok": True, "stored": True}

    def cmd_lookup(self, req):
        aid = req["action_id"]
        return {
            "ok": True,
            "issued": self.issued.get(aid),
            "commitment": self.commitments.get(aid),
            "expectation": self.expectations.get(aid),
            "verdict": self.verdicts.get(aid),
        }

    def cmd_reconcile(self, req):
        """Name what is missing. This is the whole point of the store."""
        gaps = []
        for aid in sorted(set(self.issued) | set(self.expectations)):
            has_verdict = aid in self.verdicts
            if has_verdict:
                continue
            if aid in self.expectations:
                gaps.append({
                    "action_id": aid,
                    "reason": "expected verdict, none recorded",
                    "content": self.commitments.get(aid, {}).get("descriptor_sha"),
                    "strength": "content" if aid in self.commitments else "name only",
                })
            elif aid in self.commitments:
                gaps.append({
                    "action_id": aid,
                    "reason": "proposal committed, no verdict recorded",
                    "content": self.commitments[aid]["descriptor_sha"],
                    "strength": "content",
                })
            else:
                gaps.append({
                    "action_id": aid,
                    "reason": "id issued, never resolved, content unknown",
                    "content": None,
                    "strength": "name only",
                })
        return {"ok": True, "gaps": gaps}

    def cmd_state(self, req):
        return {
            "ok": True,
            "issued": sorted(self.issued),
            "commitments": sorted(self.commitments),
            "expectations": sorted(self.expectations),
            "verdicts": sorted(self.verdicts),
        }

    def handle(self, req):
        cmd = req.get("cmd")
        table = {
            "issue": self.cmd_issue,
            "commit": self.cmd_commit,
            "expect": self.cmd_expect,
            "verdict": self.cmd_verdict,
            "lookup": self.cmd_lookup,
            "reconcile": self.cmd_reconcile,
            "state": self.cmd_state,
        }
        if cmd not in table:
            return {"ok": False, "error": "unknown command: %r" % cmd}
        return table[cmd](req)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        store = self.server.store
        for raw in self.rfile:
            raw = raw.decode("utf-8").strip()
            if not raw:
                continue
            try:
                req = json.loads(raw)
            except ValueError:
                self.wfile.write(b'{"ok": false, "error": "bad json"}\n')
                continue
            resp = store.handle(req)
            self.wfile.write((json.dumps(resp, sort_keys=True) + "\n").encode("utf-8"))
            self.wfile.flush()


class Server(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = False


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--port-stdin", action="store_true", help="take the port from stdin")
    ap.add_argument("--journal", required=True)
    ap.add_argument("--announce", required=True, help="file to write the bound port into")
    args = ap.parse_args(argv[1:])

    store = Store(Journal(args.journal))
    # A boot marker, so a reader can tell what arrived before a recovery and what arrived after.
    store.journal.append({"kind": "boot", "replayed_seq": store.journal.seq})
    srv = Server(("127.0.0.1", 0), Handler)
    srv.store = store
    port = srv.server_address[1]
    with open(args.announce, "w", encoding="utf-8") as fh:
        fh.write(str(port))
    print("store listening on 127.0.0.1:%d" % port, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
