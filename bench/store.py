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
import hashlib
import hmac
import json
import os
import socketserver
import sys

from common import bound_state, record_payload, frame, verify as verify_signature

POLICY_SHA = "sha256:9f2c0d1b7a44e1d5c3b8a6f0e2d4c1b9a7f5e3d1c9b7a5f3e1d0c8b6a4f2e0d1"


class JournalError(Exception):
    """The journal did not take the record. Nothing was persisted, so nothing may be claimed."""


class Journal:
    """Append-only, fsynced per record, framed so a torn write is detectable.

    Every record carries a digest of itself. A crash in the middle of a write leaves a partial
    line, and without a frame the only thing that notices is the JSON parser falling over. So
    replay stops at the last whole record, cuts the file back to that point, and reports how
    many bytes it discarded. Recovery to a known state beats an exception.
    """

    def __init__(self, path):
        self.path = path
        self.seq = 0
        self.discarded = 0
        self.unframed = 0
        self.quarantine = None
        # A failpoint, so a journal that refuses a write can be tested without a full disk.
        # It refuses before anything is written, which is the case the ordering claim is about.
        self.failpoint = os.environ.get("HFB_FAILPOINT", "")

    def append(self, record):
        record = dict(record)
        record["store_seq"] = self.seq + 1
        record["digest"] = frame(record)
        if self.failpoint == "verdict" and record.get("kind") == "verdict":
            raise JournalError("injected: the journal refused a verdict write")
        line = json.dumps(record, sort_keys=True)
        before = self._size()
        if before and not self._ends_clean():
            # Somebody left a partial line at the end of the journal while this store was
            # running. Appending to it would glue this record onto the damaged one, and the
            # record that then failed to survive a restart would be one this store acknowledged.
            # Cut the damaged tail out first, with the same quarantine the start-up repair uses.
            before = self._cut_damaged_tail(before)
        try:
            with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            # A failed write is not a record. The bytes may still be in the page cache and the
            # next reader would see a record this store never acknowledged, so the file is cut
            # back to the length it had before the attempt. Writing failure and write silence
            # are the same claim: nothing was persisted, so nothing may be said to be.
            self._rollback(before, exc)
            raise JournalError("journal did not take the record: %s" % exc)
        # The sequence only advances once the bytes are on disk. A record that was never
        # written must not consume a number, or a gap in the numbering looks like a lost record.
        self.seq = record["store_seq"]
        return record

    def _ends_clean(self):
        try:
            with open(self.path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                if fh.tell() == 0:
                    return True
                fh.seek(-1, os.SEEK_END)
                return fh.read(1) == b"\n"
        except OSError:
            return True

    def _cut_damaged_tail(self, size):
        """Quarantine an unterminated tail and cut the file back to the last whole line."""
        try:
            with open(self.path, "rb") as fh:
                data = fh.read()
        except OSError:
            return size
        cut = data.rfind(b"\n") + 1
        tail = data[cut:]
        if not tail:
            return size
        name = self._quarantine_name()
        with open(os.path.join(os.path.dirname(self.path) or ".", name), "wb") as fh:
            fh.write(tail)
            fh.flush()
            os.fsync(fh.fileno())
        self.quarantine = {"file": name, "bytes": len(tail),
                           "sha256": hashlib.sha256(tail).hexdigest(),
                           "ranges": [{"start": cut, "end": len(data)}]}
        with open(self.path, "r+b") as fh:
            fh.truncate(cut)
            fh.flush()
            os.fsync(fh.fileno())
        return cut

    def _size(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def _rollback(self, size, exc):
        """Cut a failed append back to the length the file had before the attempt."""
        try:
            with open(self.path, "r+b") as fh:
                fh.truncate(size)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as rollback_exc:
            raise JournalError(
                "journal write failed (%s) and the rollback to %d bytes failed too (%s): the "
                "record's state on disk is unknown, so the store will not answer for it"
                % (exc, size, rollback_exc))

    def _quarantine_name(self):
        directory = os.path.dirname(self.path) or "."
        base = os.path.basename(self.path)
        taken = [name for name in os.listdir(directory)
                 if name.startswith(base + ".quarantine-") and name.endswith(".bin")]
        return "%s.quarantine-%d.bin" % (base, len(taken) + 1)

    def replay(self):
        """Read every whole, framed record, and cut out the ones that are damaged.

        Every record carries a digest of itself. A crash in the middle of a write leaves a
        partial line; so does a disk that reorders or a writer that is not this process. The
        repair quarantines the damaged bytes and keeps the records that follow them, because a
        record acknowledged after a torn write is a record this store told the host it had, and
        dropping it because of an unrelated damaged line loses an acknowledgement rather than a
        claim. The discarded bytes are copied out before the file is rewritten, so the repair
        leaves evidence instead of a shorter file.
        """
        if not os.path.exists(self.path):
            return []
        out, good, bad, offset = [], [], [], 0
        with open(self.path, "rb") as fh:
            for line in fh:
                start, offset = offset, offset + len(line)
                stripped = line.strip()
                if not stripped:
                    good.append(line)
                    continue
                try:
                    record = json.loads(stripped)
                except ValueError:
                    bad.append((start, offset, line))
                    continue
                if not isinstance(record, dict):
                    bad.append((start, offset, line))
                    continue
                if "digest" in record:
                    if not hmac.compare_digest(record["digest"], frame(record)):
                        bad.append((start, offset, line))
                        continue
                else:
                    self.unframed += 1
                out.append(record)
                good.append(line)
        if bad:
            tail = b"".join(chunk for _, _, chunk in bad)
            self.discarded = len(tail)
            name = self._quarantine_name()
            with open(os.path.join(os.path.dirname(self.path) or ".", name), "wb") as fh:
                fh.write(tail)
                fh.flush()
                os.fsync(fh.fileno())
            self.quarantine = {
                "file": name,
                "bytes": len(tail),
                "sha256": hashlib.sha256(tail).hexdigest(),
                "ranges": [{"start": start, "end": end} for start, end, _ in bad],
            }
            # Rewrite the whole file rather than truncating at the damage: the records after
            # the damaged line were acknowledged and have to survive the repair.
            tmp = self.path + ".repair"
            with open(tmp, "wb") as fh:
                fh.write(b"".join(good))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        # Numbering follows the records that survived, not a count of them: after a repair the
        # surviving store_seq values are not contiguous, and the next record must not reuse one.
        self.seq = max([r.get("store_seq") or 0 for r in out] or [0])
        return out


class Store:
    """Issued ids, preserved commitments, expectations, verdicts. Nothing the host did not send."""

    def __init__(self, journal):
        self.journal = journal
        self.issued = {}
        self.commitments = {}
        self.expectations = {}
        self.verdicts = {}
        self.verdict_state = {}
        self.conflicts = {}
        self.load()

    def load(self):
        for rec in self.journal.replay():
            self.index(rec)

    def index(self, rec):
        """Update memory from a record that is already on disk. Memory is never ahead of it."""
        kind = rec.get("kind")
        aid = rec.get("action_id")
        if kind == "issued":
            self.issued[aid] = rec
        elif kind == "commitment":
            self.commitments[aid] = rec
        elif kind == "expectation":
            self.expectations[aid] = rec
        elif kind == "verdict":
            first = self.verdicts.get(aid)
            # The journal row is not evidence about itself. The row records what the store
            # thought when it wrote the line; replay recomputes the state from the record's
            # bytes and from the id it is filed under, and discards the claim.
            state = self.state_of(rec.get("record"), aid)
            if first is None:
                self.verdicts[aid] = rec
                # The state is a property of the record, not a claim it makes about itself:
                # a record whose binding does not verify is stored, kept visible, and never
                # allowed to resolve a gap.
                self.verdict_state[aid] = state
            elif first.get("record") != rec.get("record"):
                # Two different verdicts for one action. Whichever one a reader happens to
                # load first must not become the answer, so the state says so and neither
                # record closes the gap.
                self.verdict_state[aid] = "conflicted"
            elif state != "verified":
                self.verdict_state[aid] = state
        elif kind == "conflict":
            self.conflicts[aid] = rec
            self.verdict_state[aid] = "conflicted"
        return rec

    def record(self, rec):
        """Journal first, memory second. The order is the claim: nothing is known here that
        a restart could not also know."""
        stored = self.journal.append(rec)
        self.index(stored)
        return stored

    @staticmethod
    def state_of(record, action_id=None):
        """verified, unverified or unbound, recomputed from the record's own bytes.

        A record signed for one action and filed under another is not verified for the action
        it is filed under, and no key is needed to mount that substitution.
        """
        return bound_state(record, action_id)

    # -- commands ---------------------------------------------------------------------------

    def cmd_issue(self, req):
        aid = req["action_id"]
        if aid in self.issued:
            return {"ok": True, "duplicate": True, "action_id": aid}
        self.record({"kind": "issued", "action_id": aid})
        return {"ok": True, "action_id": aid}

    def cmd_commit(self, req):
        aid = req["action_id"]
        if aid not in self.issued:
            return {"ok": False, "action_id": aid,
                    "error": "unknown action id: a commitment needs an issued id"}
        self.record({"kind": "commitment", "action_id": aid,
                     "descriptor_sha": req["descriptor_sha"]})
        return {"ok": True, "action_id": aid}

    def cmd_expect(self, req):
        aid = req["action_id"]
        # An expectation names an action the host has not necessarily issued yet. It is a
        # promise to look for a decision, so it is allowed to arrive before the id does.
        self.record({"kind": "expectation", "action_id": aid,
                     "policy_sha": req.get("policy_sha")})
        return {"ok": True, "action_id": aid}

    def cmd_verdict(self, req):
        rec = req.get("record")
        if not isinstance(rec, dict) or not isinstance(rec.get("action_id"), str):
            # A verdict with no action id cannot be stored against anything.
            return {"ok": False, "stored": False, "action_id": None,
                    "error": "record needs an action_id"}
        aid = rec["action_id"]
        state = self.state_of(rec)
        first = self.verdicts.get(aid)
        stored = self.record({"kind": "verdict", "action_id": aid, "record": rec,
                              "state": state})
        if first is not None and first.get("record") != rec:
            conflict = self.record({
                "kind": "conflict",
                "action_id": aid,
                "first_seq": first.get("store_seq"),
                "second_seq": stored.get("store_seq"),
                "first_verdict": (first.get("record") or {}).get("verdict"),
                "second_verdict": rec.get("verdict"),
                "rule": "two different verdicts for one action id: neither resolves the gap",
            })
            return {"ok": True, "stored": True, "state": "conflicted", "conflict": True,
                    "action_id": aid, "store_seq": stored.get("store_seq"),
                    "conflict_seq": conflict.get("store_seq")}
        return {"ok": True, "stored": True, "state": self.verdict_state.get(aid, state),
                "action_id": aid, "store_seq": stored.get("store_seq")}

    def cmd_lookup(self, req):
        aid = req["action_id"]
        return {
            "ok": True,
            "action_id": aid,
            "issued": self.issued.get(aid),
            "commitment": self.commitments.get(aid),
            "expectation": self.expectations.get(aid),
            "verdict": self.verdicts.get(aid),
            "verdict_state": self.verdict_state.get(aid),
            "conflict": self.conflicts.get(aid),
        }

    def cmd_reconcile(self, req):
        """Name what is missing. This is the whole point of the store."""
        gaps = []
        for aid in sorted(set(self.issued) | set(self.expectations)):
            # Only a verdict that verifies resolves a gap. Anything else stays visible below
            # as a gap with its reason, because "a record exists" is not "a decision is known".
            if self.verdict_state.get(aid) == "verified":
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
            "conflicted_verdicts": sorted(aid for aid, state in self.verdict_state.items()
                                          if state == "conflicted"),
            "unverified_verdicts": sorted(aid for aid, state in self.verdict_state.items()
                                          if state != "verified"),
            "gaps": self.cmd_reconcile({})["gaps"],
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
        try:
            return table[cmd](req)
        except JournalError as exc:
            # The write did not happen, so nothing is claimed and memory is untouched.
            return {"ok": False, "durable": False, "error": str(exc)}
        except Exception as exc:  # noqa: BLE001 - a store that cannot answer is a store that lies
            # A journal that raises something other than JournalError, a full disk, a closed
            # file descriptor: the host is waiting for an acknowledgement, and the one thing
            # this process may not do is go quiet. An unhandled exception here used to take the
            # connection down without a reply, which the host could only read as a hang.
            return {"ok": False, "durable": False,
                    "error": "%s: %s" % (exc.__class__.__name__, exc)}


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
    # How many records the replay recovered. Named for what it counts: a sequence number here
    # used to be off by one, which made a repair look like it lost one more record than it did.
    replayed = store.journal.seq
    if store.journal.discarded:
        # Say what was lost instead of silently presenting a shorter history as the whole one.
        store.journal.append({"kind": "repair",
                              "discarded_bytes": store.journal.discarded,
                              "replayed_records": replayed,
                              "quarantine": (store.journal.quarantine or {}).get("file"),
                              "quarantine_bytes": (store.journal.quarantine or {}).get("bytes"),
                              "quarantine_sha256": (store.journal.quarantine or {}).get("sha256")})
        print("journal repaired: %d trailing bytes discarded" % store.journal.discarded,
              flush=True)
    # A boot marker, so a reader can tell what arrived before a recovery and what arrived after.
    store.journal.append({"kind": "boot", "replayed_records": replayed})
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
