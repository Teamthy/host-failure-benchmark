"""A store that answers every request and confirms the wrong action.

Scenario E exists to separate two things a host can confuse: a message arriving, and a message
being an answer to the question that was asked. This process is well behaved in every way that
is easy to check and wrong in the one way that matters. It accepts a verdict, says it stored it,
says it verified, and names a different action id in the same reply.

    python bench/stub_store.py --announce artifacts/run-.../probe-reply/port.txt

It is a fixture, not a store. It keeps nothing and replays nothing, and it is never used by
`run.py` for any scenario except E.
"""

import argparse
import json
import os
import socketserver
import sys

# The id it names, whatever it was asked about. Deliberately not one the run uses anywhere.
WRONG_ID = "S-0000"


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        for raw in self.rfile:
            raw = raw.decode("utf-8").strip()
            if not raw:
                continue
            try:
                req = json.loads(raw)
            except ValueError:
                break
            cmd = req.get("cmd")
            asked = req.get("action_id")
            if asked is None and isinstance(req.get("record"), dict):
                asked = req["record"].get("action_id")
            if cmd == "verdict":
                resp = {"ok": True, "stored": True, "state": "verified",
                        "action_id": WRONG_ID, "store_seq": 1}
            elif cmd == "lookup":
                resp = {"ok": True, "action_id": WRONG_ID}
            else:
                resp = {"ok": True, "action_id": asked}
            self.wfile.write((json.dumps(resp, sort_keys=True) + "\n").encode("utf-8"))
            self.wfile.flush()


class Server(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = False


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--announce", required=True, help="file to write the bound port into")
    args = ap.parse_args(argv[1:])
    srv = Server(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    with open(args.announce, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(str(port))
    print("stub store listening on 127.0.0.1:%d" % port, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
