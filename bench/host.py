"""The host process: one scenario per invocation, then it exits.

It talks to the audit store over loopback, writes its own journal, and can be killed. The
failpoints are flags rather than timing, so a run is deterministic and a failure is a named
mismatch rather than a flake.

    python bench/host.py --scenario A --port 51234 --workdir artifacts/run-... --journal host-A.jsonl

Scenarios:

    A    expectation registered, verdict suppressed            -> absence is nameable
    A'   same, no expectation registered                       -> silence
    B    local commit, ship fails, then replay                 -> verdict lands with its T1 timestamp
    C    issued id plus preserved commitment, host dies        -> named gap carrying content
    C'   issued id only, host dies                             -> named gap, no content
    C''  locally minted id, host dies                          -> silence
    D    full record, binding verifies                         -> verified
    D'   full record with no signature                         -> quarantined, never verified
    E    store replies that are well formed and about another
         action                                                 -> rejected, effect withheld
"""

import argparse
import json
import os
import socket
import sys

from common import Clock, DECIDED_BY, POLICY_SHA, digest, record_payload, sign

HERE = os.path.dirname(os.path.abspath(__file__))


class Transport:
    def __init__(self, port):
        self.port = port

    def call(self, req):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
        return json.loads(buf.decode("utf-8"))


class Host:
    def __init__(self, scenario, port, workdir, journal_name, flags):
        self.scenario = scenario
        self.flags = flags
        self.clock = Clock()
        self.transport = Transport(port)
        self.journal_path = os.path.join(workdir, journal_name)
        self.wal_path = os.path.join(workdir, "wal-%s.jsonl" % scenario.replace("'", "p"))
        self.events = []

    def emit(self, kind, **fields):
        event = {"scenario": self.scenario, "kind": kind, "run": self.flags.phase}
        event.update(self.clock.tick(kind.upper()))
        event.update(fields)
        self.events.append(event)
        with open(self.journal_path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return event

    # -- talking to the store ---------------------------------------------------------------

    def request(self, req, action_id=None):
        """Ask the store, then read the answer as an answer to this question.

        A reply is only consent if it is well formed, says it succeeded, and names the action
        that was asked about. Anything else is returned with the reasons it was refused, and
        the caller decides what that means for the effect. This is the difference between a
        message arriving and a message being a reply.
        """
        try:
            resp = self.transport.call(req)
        except OSError as exc:
            return None, ["store unreachable: %s" % exc.__class__.__name__]
        problems = []
        if not isinstance(resp, dict):
            problems.append("reply is not a JSON object")
        else:
            if resp.get("ok") is not True:
                problems.append("store refused: %s" % resp.get("error"))
            if action_id is not None and resp.get("action_id") != action_id:
                problems.append("reply names %r, the request was %r"
                                % (resp.get("action_id"), action_id))
        return resp, problems

    def require(self, req, action_id=None, purpose=None):
        """A request whose failure is a named event rather than a silent continuation."""
        resp, problems = self.request(req, action_id)
        if problems:
            self.emit("reply_rejected", action_id=action_id, command=req.get("cmd"),
                      purpose=purpose, problems=problems)
            return None
        return resp

    # -- the guard --------------------------------------------------------------------------

    def guard(self, action_id, descriptor):
        """A branch in the code. Under normal conditions its verdict never leaves this process."""
        blocked = descriptor.get("kind") == "state_transition"
        verdict = "BLOCK" if blocked else "ALLOW"
        rule = "R7" if blocked else None
        self.emit("guard_decision", action_id=action_id, verdict=verdict, rule=rule,
                  policy_sha=POLICY_SHA)
        return {"action_id": action_id, "verdict": verdict, "rule": rule,
                "policy_sha": POLICY_SHA, "decided_by": DECIDED_BY}

    def decision_record(self, decision, descriptor_sha, decision_ts, strip_signature=False):
        record = {
            "action_id": decision["action_id"],
            "policy_sha": decision["policy_sha"],
            "decided_by": decision["decided_by"],
            "verdict": decision["verdict"],
            "rule": decision["rule"],
            "descriptor_sha": descriptor_sha,
            "decision_ts": decision_ts,
        }
        record["signature"] = None if strip_signature else sign(record_payload(record))
        return record

    # -- scenarios --------------------------------------------------------------------------

    def run(self):
        getattr(self, "scenario_" + self.scenario.replace("'", "p"))()

    def scenario_A(self):
        return self.expectation_case(register=not self.flags.no_register)

    def scenario_Ap(self):
        return self.expectation_case(register=not self.flags.no_register)

    def expectation_case(self, register):
        aid = self.flags.action_id or "A-1042"
        descriptor = {"kind": "state_transition", "from": "draft", "to": "issued"}
        if register:
            if self.require({"cmd": "expect", "action_id": aid, "policy_sha": POLICY_SHA},
                            action_id=aid, purpose="register an expectation") is not None:
                self.emit("expectation_registered", action_id=aid)
        self.emit("proposal", action_id=aid, descriptor_sha=digest(descriptor))
        decision = self.guard(aid, descriptor)
        # Failpoint: the verdict is decided and then never emitted. This is the default failure.
        self.emit("verdict_suppressed", action_id=aid, verdict=decision["verdict"],
                  note="decided in process, never emitted")
        self.emit("effect_withheld", action_id=aid, reason="guard blocked")

    def scenario_B(self):
        if self.flags.phase == "replay":
            return self.replay_case()
        return self.initial_case()

    def initial_case(self):
        aid = self.flags.action_id or "B-2001"
        descriptor = {"kind": "state_transition", "from": "draft", "to": "issued"}
        desc_sha = digest(descriptor)
        self.emit("proposal", action_id=aid, descriptor_sha=desc_sha)
        decision = self.guard(aid, descriptor)
        record = self.decision_record(decision, desc_sha, decision_ts=self.clock.step)
        # T2: the verdict is durable locally before anything else happens.
        with open(self.wal_path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self.emit("wal_commit", action_id=aid, decision_ts=record["decision_ts"])
        resp, problems = self.request({"cmd": "verdict", "record": record}, action_id=aid)
        if problems and resp is None:
            # T3 failed. The store is unreachable. The effect must not proceed.
            self.emit("ship_failed", action_id=aid, error=problems[0])
            self.emit("effect_withheld", action_id=aid, reason="verdict not durable centrally")
            return
        if problems:
            # The store answered, and the answer was not about this action. That is not consent.
            self.emit("reply_rejected", action_id=aid, command="verdict", problems=problems)
            self.emit("effect_withheld", action_id=aid, reason="store reply rejected")
            return
        self.emit("ship_ok", action_id=aid)
        self.emit("effect_withheld", action_id=aid, reason="guard blocked")

    def replay_case(self):
        if not os.path.exists(self.wal_path):
            raise SystemExit("no write-ahead log to replay at %s" % self.wal_path)
        with open(self.wal_path, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        for record in records:
            self.emit("replay_read", action_id=record["action_id"],
                      decision_ts=record["decision_ts"])
            aid = record["action_id"]
            if self.require({"cmd": "verdict", "record": record}, action_id=aid,
                            purpose="ship the recovered verdict") is None:
                self.emit("effect_withheld", action_id=aid, reason="store reply rejected")
                continue
            self.emit("replay_shipped", action_id=aid, decision_ts=record["decision_ts"])

    def scenario_C(self):
        return self.host_death_case()

    def scenario_Cp(self):
        return self.host_death_case()

    def scenario_Cpp(self):
        return self.host_death_case()

    def host_death_case(self):
        aid = self.flags.action_id or "C-3003"
        descriptor = {"kind": "state_transition", "from": "draft", "to": "issued"}
        desc_sha = digest(descriptor)
        if self.flags.local_id:
            # The id is minted on the host. Its name dies with the host that named it.
            self.emit("local_id_minted", action_id=aid)
        else:
            if self.require({"cmd": "issue", "action_id": aid}, action_id=aid,
                            purpose="register an id") is not None:
                self.emit("id_issued", action_id=aid, source="store")
            if not self.flags.issue_only:
                if self.require({"cmd": "commit", "action_id": aid, "descriptor_sha": desc_sha},
                                action_id=aid, purpose="commit content") is not None:
                    self.emit("commitment_preserved", action_id=aid, descriptor_sha=desc_sha)
        self.emit("proposal", action_id=aid, descriptor_sha=desc_sha)
        self.guard(aid, descriptor)
        self.emit("host_dying", action_id=aid, note="killed before any verdict left the process")
        sys.stdout.flush()
        os._exit(9)

    def scenario_D(self):
        return self.binding_case(strip_signature=False)

    def scenario_E(self):
        """The store is well behaved except that its verdict reply is about another action."""
        return self.binding_case(strip_signature=False)

    def scenario_Dp(self):
        return self.binding_case(strip_signature=True)

    def binding_case(self, strip_signature):
        aid = self.flags.action_id or "D-4004"
        descriptor = {"kind": "read", "target": "order-42"}
        desc_sha = digest(descriptor)
        if self.require({"cmd": "issue", "action_id": aid}, action_id=aid,
                        purpose="register an id") is None:
            return
        if self.require({"cmd": "commit", "action_id": aid, "descriptor_sha": desc_sha},
                        action_id=aid, purpose="commit content") is None:
            return
        self.emit("proposal", action_id=aid, descriptor_sha=desc_sha)
        decision = self.guard(aid, descriptor)
        record = self.decision_record(decision, desc_sha, decision_ts=self.clock.step,
                                      strip_signature=True)
        record["effect_ref"] = "rcpt:" + digest({"action_id": aid, "effect": "read"})
        # Signed last, so the signature covers every field that ships including the receipt.
        record["signature"] = None if strip_signature else sign(record_payload(record))
        if strip_signature:
            self.emit("signature_stripped", action_id=aid)
        resp, problems = self.request({"cmd": "verdict", "record": record}, action_id=aid)
        if problems:
            # The record exists locally, but the store's answer did not confirm this action,
            # so no effect is logged. A reply is not a receipt for whatever was asked.
            self.emit("reply_rejected", action_id=aid, command="verdict", problems=problems)
            self.emit("effect_withheld", action_id=aid, reason="store reply rejected")
            return
        self.emit("ship_ok", action_id=aid, signed=not strip_signature)
        self.emit("effect_committed", action_id=aid, effect_ref=record["effect_ref"])


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--journal", required=True)
    ap.add_argument("--phase", default="initial", choices=["initial", "replay"])
    ap.add_argument("--no-register", action="store_true")
    ap.add_argument("--issue-only", action="store_true")
    ap.add_argument("--local-id", action="store_true")
    ap.add_argument("--action-id", default=None)
    args = ap.parse_args(argv[1:])
    host = Host(args.scenario, args.port, args.workdir, args.journal, args)
    host.run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
