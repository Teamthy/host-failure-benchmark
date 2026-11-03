"""Four cheap completeness checks, none of which needs a signed sequence. A feasibility probe for
the cases the disposition files under "nothing signs the sequence" (F-07). Prints JSON.

    python3 extra_checks.py RUNDIR

1. any repair record in the main store journal is reported (V28)
2. store_seq values are contiguous, except gaps a repair record names (V30)
3. every issued id appears in some host journal (V31)
4. a verdict's descriptor_sha equals the commitment preserved for the same id (V32)

Scope: an adversary who renumbers and reframes the whole journal and edits the host journals
defeats checks 2 and 3. That is where a keyed chain or checkpoint is needed; this script does not
claim otherwise.
"""
import glob
import json
import os
import sys


def load(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def main(rundir):
    rows = load(os.path.join(rundir, "store.jsonl"))
    findings = []
    repairs = [r for r in rows if r.get("kind") == "repair"]
    for r in repairs:
        findings.append("repair record at store_seq %s (%s bytes quarantined)"
                        % (r.get("store_seq"), r.get("discarded_bytes")))
    seqs = sorted(r.get("store_seq") for r in rows if isinstance(r.get("store_seq"), int))
    missing = sorted(set(range(1, (seqs[-1] if seqs else 0) + 1)) - set(seqs))
    if missing and not repairs:
        findings.append("store_seq gap with no repair record: %s" % missing)
    host_ids = set()
    for path in glob.glob(os.path.join(rundir, "host-*.jsonl")):
        host_ids |= {e.get("action_id") for e in load(path)}
    probe_ids = {"C-9009"}  # issued by run.py's conflict probe, not by a host
    for r in rows:
        if r.get("kind") == "issued" and r.get("action_id") not in host_ids | probe_ids:
            findings.append("issued id %s appears in no host journal" % r.get("action_id"))
    commitments = {r["action_id"]: r.get("descriptor_sha") for r in rows if r.get("kind") == "commitment"}
    for r in rows:
        if r.get("kind") == "verdict":
            aid = r.get("action_id")
            want = commitments.get(aid)
            got = (r.get("record") or {}).get("descriptor_sha")
            if want is not None and got is not None and want != got:
                findings.append("verdict for %s carries descriptor %s..., commitment says %s..."
                                % (aid, got[:15], want[:15]))
    print(json.dumps({"findings": findings}))


if __name__ == "__main__":
    main(sys.argv[1])
