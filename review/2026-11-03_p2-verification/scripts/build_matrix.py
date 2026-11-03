"""Build the machine-readable results matrix (JSON + CSV) for the P2 verification of 006d7ee.

Inputs: v2results.json (V01-V36 on 006d7ee), v3fixes.json if present, p2probes.json, and the
fixed entries below for N-checks, runner tests and document findings, each transcribed from the
logs in this folder. Usage: python3 build_matrix.py
"""
import csv
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
V = {r["id"]: r for r in json.load(open(os.path.join(HERE, "v2results.json")))}
PR = {r["id"]: r for r in json.load(open(os.path.join(HERE, "p2probes.json")))}
TARGET = "006d7ee71aa6599521d6675c32f496c5427a846b"

CLASS_BY_V = {
    # id: (category, severity, developer_status, agreement, refs, note)
    "V01": ("as documented", None, "unchanged", "agree", "verify.py:313-338", ""),
    "V02": ("verified correction", None, "fixed", "agree", "verify.py:340-354 (B.decision)",
            "internal consistency with the host journal only; a key holder can edit both"),
    "V03": ("as documented", None, "unchanged", "agree", "verify.py:313-338", ""),
    "V04": ("disputed: dispute upheld", None, "disputed", "agree with developer",
            "bench/host.py:221-235, common.py:48-56", "mutation inert (P01); see P02-P04"),
    "V05": ("verified correction", None, "fixed", "agree", "bench/store.py:246, common.py:64-85", ""),
    "V06": ("verified correction", None, "fixed", "agree", "common.py:64-85, verify.py:96-105", ""),
    "V07": ("as documented", None, "unchanged", "agree", "bench/store.py", ""),
    "V08": ("informational", None, "informational", "agree", "", ""),
    "V09": ("as documented", None, "unchanged", "agree", "verify.py:589-600", ""),
    "V10": ("as documented", None, "unchanged", "agree", "verify.py:589-600", ""),
    "V11": ("as documented", None, "unchanged", "agree", "", ""),
    "V12": ("verified correction", None, "fixed", "agree", "verify.py:420-432",
            "availability limit remains: an unauthenticated client can force a conflict"),
    "V13": ("verified correction", None, "fixed", "agree", "verify.py:420-432", ""),
    "V14": ("as documented", None, "unchanged", "agree", "", ""),
    "V15": ("verified correction", None, "fixed", "agree", "bench/host.py:118-127", ""),
    "V16": ("verified correction", None, "fixed", "agree", "bench/host.py:118-127", ""),
    "V17": ("verified correction", None, "fixed", "agree", "bench/host.py:118-127, verify.py:455-466", ""),
    "V18": ("verified correction", None, "fixed", "agree", "bench/host.py:40-68", ""),
    "V19": ("verified correction", None, "fixed", "agree", "bench/store.py:56-82, 129-140", ""),
    "V20": ("verified correction", None, "fixed", "agree", "bench/store.py:56-82, 129-140", ""),
    "V21": ("verified correction", None, "fixed", "agree", "bench/store.py:66-69, 98-127, 149-211",
            "but the runtime cut writes no repair record (P07)"),
    "V22": ("static: open", "Low", "open", "agree", "bench/store.py:60-61", ""),
    "V23": ("documented scope limitation", "Medium", "scope", "partly agree",
            "TECHNICAL-NOTE.md:192-198; README.md:1, 7",
            "documented in the note; the title still promises host-death survivability"),
    "V24": ("documented scope limitation", "Medium", "scope", "partly agree",
            "bench/host.py:262-264; run.py:113-114", "same as V23"),
    "V25": ("informational", None, "informational", "agree", "", ""),
    "V26": ("verified correction", None, "fixed", "agree", "verify.py:298-308", ""),
    "V27": ("as documented", None, "unchanged", "agree", "", ""),
    "V28": ("independently reproduced", "Medium", "open (F-07, needs signed sequence)", "disagree",
            "verify.py:494-520 (repair-quarantine reads probe-repair only)",
            "detectable by one verifier check without signing (P09)"),
    "V29": ("independently reproduced; scope", "Medium", "open (F-07)", "agree",
            "bench/store.py:149-211", "needs a count, checkpoint or chain"),
    "V30": ("independently reproduced", "Low", "open (F-07)", "partly agree", "verify.py:626-640",
            "contiguity check detects the modelled edit (P09); a renumbering adversary needs a chain"),
    "V31": ("independently reproduced", "Low", "open (F-07)", "partly agree", "verify.py:123-165 (recompute_gaps)",
            "host-journal cross-check detects it (P09); an adversary editing host journals needs a chain"),
    "V32": ("independently reproduced", "Medium", "open (F-07)", "disagree", "verify.py:421-430",
            "a verdict/commitment comparison detects it; no signing needed (P09)"),
    "V33": ("independently reproduced; scope", "Low", "open (F-07)", "agree",
            "verify.py:260-270 (check A)", "needs ordering across host and store; no common clock"),
    "V34": ("as documented", None, "unchanged", "agree", "", ""),
    "V35": ("independently reproduced", "Low", "not testable", "disagree",
            "audit/regressions.py:206-212",
            "testable: 25cd57f is public and matches the first ZIP; the script cannot run there"),
    "V36": ("documented scope limitation", "Low", "open", "agree", "bench/store.py:436-438", ""),
}

N_ROWS = [
    ("N01", "verifier on a nonexistent path", "exit 2, no traceback", "exit=2, no traceback", "as documented", None, "unchanged", "agree", "verify.py:791-795"),
    ("N02", "path is a regular file", "exit 2", "exit=2", "as documented", None, "unchanged", "agree", "verify.py:791-795"),
    ("N03", "empty directory", "non-zero, no traceback", "exit=1, report written", "as documented", None, "unchanged", "agree", "verify.py:226-230"),
    ("N04", "second directory missing", "determinism fails", "exit=1, determinism fails", "as documented", None, "unchanged", "agree", "verify.py:692-720"),
    ("N05", "second run missing an artifact", "determinism fails", "exit=1, determinism fails", "as documented", None, "unchanged", "agree", "verify.py:692-720"),
    ("N06", "same directory twice", "refused", "exit=1, determinism fails", "verified correction", None, "fixed", "agree", "verify.py:703-704"),
    ("N07", "byte copy of a run", "(limit) indistinguishable", "exit=0, holds", "documented scope limitation", None, "unchanged", "agree", ""),
    ("N08", "extra file, different manifest", "(by design) holds", "exit=0, holds", "as documented", None, "unchanged", "agree", ""),
    ("N09", "report path is a directory, valid run", "exit 0, no traceback", "exit=0", "as documented", None, "unchanged", "agree", "verify.py:752-770"),
    ("N10", "report path unwritable, failing run", "exit 1, no traceback", "exit=1", "as documented", None, "unchanged", "agree", "verify.py:752-770"),
    ("N11", "stale passing report that cannot be overwritten (chattr +i), failing run",
     "a consumer cannot mistake the stale file for this verdict",
     "exit=1; stdout now warns the old file describes an earlier run, then still says 'the report file is missing'; the file still says failures=[]",
     "partial correction", "Low", "untestable as written", "disagree: executed here and in the differential audit", "verify.py:752-770"),
    ("N12", "fixed temp path exists", "input check still tests a missing path", "held, challenge exit 0", "verified correction", None, "fixed", "agree", "challenge.py:238"),
    ("N13", "original N13 (reads <run>/verify-report.json after challenge)", "n/a", "harness raises FileNotFoundError, as the developer predicted", "test obsolete", None, "fixed, check needs updating", "agree", "challenge.py:190-203"),
    ("N13r", "revised N13: sha256 inventory before/after challenge.py (P05) and detection self-test (P06)",
     "no file added, removed or rewritten; the tool flags a planted write",
     "P05: 0 changed files in example/run (20 files) and a fresh run (24 files); P06: planted stray.txt reported MISSED, exit 1",
     "verified correction", None, "fixed", "agree", "challenge.py:266-276, 304-312"),
]

EXTRA = [
    # id, test, expected, observed, category, severity, refs, command
    ("NEW-1", "runtime torn-tail cut (P07)", "a repair record announces the quarantined bytes",
     "journal kinds after restart ['boot','issued','issued','boot']; quarantine file present; no repair record",
     "new defect (P2)", "Low", "bench/store.py:66-69, 98-127; repair record written only at start-up, bench/store.py:441-460", "p2probes.py P07"),
    ("NEW-2", "conflict-record append fails after the second verdict is durable (P08)", "reply describes the disk",
     "reply ok:false durable:false; second verdict on disk; live and restart both 'conflicted'; no conflict record",
     "new defect (P2)", "Low", "bench/store.py:307-336 (two appends), 404-416 (catch-all reply)", "p2probes.py P08"),
    ("NEW-3", "verify.py broken: campaign behaviour (R7)", "every mode reported, no traceback",
     "f22 raises FileNotFoundError reading verify-report.json; f2a-f9 never run; exit 1",
     "new defect (P2)", "Low", "audit/regressions.py:609", "runner_extra.sh R7"),
    ("NEW-4", "temporary directories left behind", "modes clean up after themselves",
     "after 9 campaigns: 9 hfb-f20-benign, 9 hfb-f20-old, 18 hfb-f21-, 9 hfb-f22- full copies (~15 MB); one hfb-absent- per challenge run",
     "new defect (P2)", "Low", "audit/regressions.py:441-447 (fresh_copy, never removed); challenge.py:238", "ls /tmp after campaigns"),
    ("U10", "runner: no per-mode timeout, abort on slow store start, buffered output, failing driver ends campaign",
     "bounded, isolated, observable modes",
     "R2: 2784 bytes at 17.03 s, nothing before; R3a: exit 1 after 15 s, 5 modes reported, aborted at f16; R5: killed by outer timeout, 0 bytes; R6: exit 1, 0 modes reported",
     "independently reproduced (not in register)", "Medium", "audit/regressions.py:232, 257-275, 426-428, 690-697", "runner_checks.sh, runner_extra.sh"),
    ("N5", "regressions green on a broken build (R9, R9b)", "campaign fails when the unmutated build fails",
     "R9 and R9b: exit 1, via f20 and f22 MISSED (their benign halves require a passing run)",
     "verified correction (incidental)", None, "audit/regressions.py custom_f20, custom_f22", "runner_extra.sh R9, R9b"),
    ("P01", "V04 exactly as shipped", "inert if bytes identical", PR["P01"]["observed"], "disputed: dispute upheld", None, "bench/host.py replay_case", "p2probes.py P01"),
    ("P02", "clock-skew variant +5", "detected", PR["P02"]["observed"], "verified detection (divergence)", None, "verify.py:313-338", "p2probes.py P02"),
    ("P03", "consistent skew in all host-written artifacts", "an attesting clock would refuse", PR["P03"]["observed"],
     "documented scope limitation (no attestation)", "Medium", "verify.py:313-338; TECHNICAL-NOTE.md:42", "p2probes.py P03"),
    ("P04", "consistent Unix-epoch decision time", "no-wall-clock or B refuses", PR["P04"]["observed"],
     "independently reproduced", "Low", "verify.py:652-660", "p2probes.py P04"),
    ("P09", "cheap completeness checks on V28, V30, V31, V32", "flag each, not the valid run", PR["P09"]["outcome"],
     "feasibility evidence", None, "extra_checks.py", "p2probes.py P09"),
    ("DOC-1", "Class V count", "docs say three", "README.md:17 'Two checks'; TECHNICAL-NOTE.md:44 'two checks'; verify reports 3 of 3",
     "documentation defect", "Low", "README.md:17, TECHNICAL-NOTE.md:44", "grep"),
    ("DOC-2", "remaining-deviation count", "one number", "TECHNICAL-NOTE.md:150-151 says 10; register and disposition say 9",
     "documentation defect", "Low", "TECHNICAL-NOTE.md:150-151", "grep"),
    ("DOC-3", "timestamp claim", "consistent with source-asserted time", "TECHNICAL-NOTE.md:42 still says the verdict 'carries the timestamp from the moment of decision rather than the moment of arrival'; P03 accepts a rewritten decision time",
     "documentation defect", "Medium", "TECHNICAL-NOTE.md:42", "p2probes.py P03"),
    ("DOC-4", "cited evidence", "available at a pinned revision", "evidence/2026-11-01/ (incl. v04-inert-proof.log, regressions-19-modes.log) is in no commit up to 20e3ebf",
     "unverifiable", "Medium", "audit/DISPOSITION-2026-11-01.md:11-13, 47-50; FINDINGS-REGISTER.md:20, 62", "git ls-tree -r 20e3ebf"),
    ("DOC-5", "attribution", "independent verification and adversarial testing credited in the authorship record",
     "CONTRIBUTION.md unchanged since first commit, no row for either; register never names Behar Dalipi; disposition names him only as 'Reviewer: Behar (independent)'; register R1-R3 claimed as found before the package, no artifact supports it, the same defects are D1, D3, D4 of the 41013f0 regression audit",
     "documentation defect", "Medium", "CONTRIBUTION.md; FINDINGS-REGISTER.md:32-41; DISPOSITION-2026-11-01.md:3", "read"),
    ("DOC-6", "review status", "note reviewed before publication", "TECHNICAL-NOTE.md:3 'Draft. Not yet reviewed by the second author.'; CONTRIBUTION.md:20-21 likewise",
     "procedural blocker", "Medium", "TECHNICAL-NOTE.md:3; CONTRIBUTION.md:20-21", "read"),
]


def main():
    rows = []
    for vid in sorted(V):
        r = V[vid]
        cat, sev, dev, agree, refs, note = CLASS_BY_V[vid]
        rows.append(dict(id=vid, test=r["title"], expected=r["expected"], observed=r["observed"],
                         category=cat, severity=sev or "", developer_status=dev, agreement=agree,
                         source_refs=refs, reproducible="yes", command="v2tests.py %s" % vid,
                         note=note, target=TARGET))
    for nid, test, exp, obs, cat, sev, dev, agree, refs in N_ROWS:
        rows.append(dict(id=nid, test=test, expected=exp, observed=obs, category=cat,
                         severity=sev or "", developer_status=dev, agreement=agree,
                         source_refs=refs, reproducible="yes",
                         command="v3fixes.py" if nid != "N13r" else "p2probes.py P05 P06",
                         note="", target=TARGET))
    for eid, test, exp, obs, cat, sev, refs, cmd in EXTRA:
        rows.append(dict(id=eid, test=test, expected=exp, observed=obs, category=cat,
                         severity=sev or "", developer_status="not in register" if eid in ("NEW-1", "NEW-2", "NEW-3", "NEW-4", "U10", "P03", "P04") else "",
                         agreement="", source_refs=refs,
                         reproducible="no (evidence absent)" if eid == "DOC-4" else "yes",
                         command=cmd, note="", target=TARGET))
    json.dump({"target_commit": TARGET, "rows": rows},
              open(os.path.join(HERE, "p2-results-matrix.json"), "w"), indent=2)
    with open(os.path.join(HERE, "p2-results-matrix.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    from collections import Counter
    print(len(rows), "rows;", Counter(r["category"] for r in rows))


if __name__ == "__main__":
    main()
