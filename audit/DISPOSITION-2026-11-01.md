# Disposition of the differential review, v1.2

Reviewer: Behar (independent). Package received 1 November 2026:
`HFB_Teste_Diferenciale.zip`, 41,754 bytes, sha256 `b2a39986c4ad238446e9d2a4928e58a35cba2ff7ceed8fda3e357ac14db90ed4`.
That is the hash declared in the review, measured on the file before anything was unpacked: match.

Base commit `df0cf5a`, P2 applied as commit `006d7ee` on `main` of
`Teamthy/host-failure-benchmark` (patch `P2-DIFFERENTIAL-FIXES.patch.txt`, sha256
`96d3e59aa016a534dcb694506ed954b624c1667ea783797b78d80a1169895e09`). Every result below was
reproduced on a Windows 11 machine from that commit, and the outputs are in
`evidence/2026-11-01/`. All numbers below come
from running the reviewer's own scripts, unchanged, with `HFB_REPO` pointed at the tree under
test. The logs are in `evidence/2026-11-01/`.

## Headline

Counted from the two results files, not from prose. His `v2results.json` marks 23 outcomes as
defects, 9 as documented, 3 informational and 1 static; the review text calls that 25 deviations
because it counts the static case and, it appears, one of the informational ones. The counts
below are the files'.

| | before P2 (df0cf5a) | after P2 |
| --- | --- | --- |
| Outcomes behaving as documented | 9 of 36 | 22 of 36 |
| Outcomes marked as defects | 23 | 9 |
| Static outcome (probe coverage, V22) | 1 | 1 |
| Informational | 3 | 3 |
| Not testable here | 0 | 1 (V35) |
| Input and verifier checks as documented | 9 of 13 | 12 of 13 |
| Input-check defects | 3 (N06, N12, N13) | 0, with N13's subject removed |

The 9 remaining defects are V04 (disputed below), V23, V24, V28, V29, V30, V31, V32 and V33,
plus V22 which is static: the failpoint still refuses before any byte is written, so the probe
tests refusal and the audit tests tearing. V23 and V24 are the host-side group (no disk-loss
test, no proof of death). V28 to V33 are the completeness group (nothing signs the sequence).

Nothing here is described as fixed unless the reviewer's own case reports "as documented" on the
patched tree, an `audit/regressions.py` mode fails without the fix, and the benign run still
verifies: `run.py` then `verify.py` gives 13 of 13 Class P
and 3 of 3 Class V, two runs are byte-identical, and `challenge.py` catches every mutation it
names. Those four outputs are in `evidence/2026-11-01/`.

## The one case I dispute

V04 says that a replay which re-stamps `decision_ts` with its own clock step and re-signs goes
uncaught. In this run the replay step and the decision step are both 2, so the mutation writes
the value the field already held: the stored record is byte-identical to the WAL record,
signature included (evidence `v04-inert-proof.log`, case `delta=+1`). The mutation is a no-op,
so the outcome says nothing about the check. The same mutation with the replay clock five steps
away is caught: `B` fails, `B.wal` fails, exit 1 (case `delta=+5`). `B.wal` compared the stored
timestamp with the WAL before this patch; after it, `B` requires that agreement too.

## The one case his harness can no longer run

N13 required `challenge.py` to leave a passing `verify-report.json` in the evidence directory
it was pointed at. I removed that behaviour: the report was written by verifying the run
under test, which is how a failing report ended up sitting in evidence. `challenge.py` now
verifies copies, writes nothing into the evidence directory, and fingerprints that directory at
start and end, printing `the run you pointed me at is unchanged`. His N13 opens the file the
defect used to leave and now raises `FileNotFoundError`. The property he wanted is asserted,
more strongly, by the tool; the check itself needs rewriting to assert the fingerprint.

## Threat-model notes, in his terms

- V02, V04 and the V08/V25 probes are source-holder cases. The key is in the source, by design,
  and the note has said so since the first version. A holder of that key can forge records and
  edit the host journal. What the suite can do is require internal agreement, which it now
  does (`B.decision`). It cannot attest.
- V23 and V24 are host-side. The suite observes host *artifacts*; it does not authenticate that
  a host process died, and it has no independently recorded kill receipt. That was in the
  earlier scope note and is now stated as a limit of the survivability claim, not as a gap in
  a guarantee.
- V28-V33 need authenticated sequence numbers and checkpoints. Nothing in the current design
  provides them, and adding them changes the architecture rather than a check. Open.

## Modes, so a fix can break loudly

Seven modes were written for these six findings, nineteen in all, and every one is caught:
`f16` and `f17` for F-01, `f18` for F-02, `f19` for F-03, `f21` for F-04, `f20` for F-05, `f22`
for F-09. `f20` tests both directions, because a check that fires on an ordinary restart is not
a check: the benign restart has to verify and the binding P2 replaced has to fail on it. The run
is in `evidence/2026-11-01/regressions-19-modes.log`.

## Case by case

| id | what it tests | his outcome | after P2 | disposition | note |
| --- | --- | --- | --- | --- | --- |
| V01 | WAL verdict BLOCK->ALLOW with stale signature, before replay | holds | holds | unchanged | Unauthenticated record with a stale signature still fails B. |
| V02 | WAL verdict BLOCK->ALLOW and re-signed with the in-source key, before replay | DEFECT | holds | fixed | New check `B.decision` compares the recovered verdict and rule with the `guard_decision` the host logged when it decided. Host said BLOCK, store held ALLOW: exit 1 now, exit 0 before. Residual, stated in the same breath: a holder of the in-source key can edit the host journal too, so this is internal consistency, not attestation. |
| V03 | WAL signature stripped before replay | holds | holds | unchanged | Signature stripped still fails B. |
| V04 | Replay re-stamps decision_ts with its own clock step and re-signs (old T09) | DEFECT | DEFECT | disputed | The mutation is inert. Replay step 2 equals the decision step 2 in this run, so `record["decision_ts"] = self.clock.step + 1` writes the value the field already held and the re-signed record is byte-identical to the WAL (evidence: v04-inert-proof.log, first case). The same mutation at +5 is caught: B and B.wal both fail, exit 1 (second case). `B.wal` already compared the stored timestamp with the WAL before this patch. |
| V05 | Unsigned verdict row that asserts state=verified, appended and framed | DEFECT | holds | fixed | Replay no longer reads `state` off the row: it recomputes from the record bytes and the id the row is filed under. The forged row leaves C-3003 a gap. |
| V06 | Valid signed record of D-4004 transplanted under outer action_id C-3003 | DEFECT | holds | fixed | `bound_state()` in bench/common.py requires the id inside the record to equal the id it is filed under; store and verifier both import it. A record signed for D-4004 cannot resolve C-3003. |
| V07 | Unsigned verdict for C-3003 over the protocol, live store | holds | holds | unchanged | Unsigned verdict over the protocol against a live store is still refused. |
| V08 | Forged unsigned verdict (the f3 mutation) checked by verify.py, not only by the store | INFO | INFO | informational | Forged unsigned verdict, checked by verify.py. No change. |
| V09 | Each required artifact deleted on its own (18 runs) plus manifest | holds | holds | unchanged | Each required artifact deleted on its own is still caught. |
| V10 | Artifact deleted and also removed from manifest.required | holds | holds | unchanged | Artifact removed from manifest.required as well is still caught. |
| V11 | Identical verdict replayed twice (benign duplicate) | holds | holds | unchanged | Identical verdict replayed twice still holds. |
| V12 | An unsigned client puts the verified D-4004 into conflict; does the verifier agree with itself? | DEFECT | holds | fixed | Check D now refuses to report D-4004 verified while the same journal lists it as an unresolved gap. Exit 1. Availability limit stays: an unauthenticated client can still force a conflict, which is a veto, and the store answers `conflicted` rather than a silent pass. |
| V13 | Conflict for an action other than the C-9009 probe, conflict record deleted | DEFECT | holds | fixed | Same change: two different signed records make D-4004 a gap, and D refuses to pass on a gap it also reports. Exit 1. |
| V14 | Store answers ok:false to everything | holds | holds | unchanged | Control: store answering ok:false to everything still withholds. |
| V15 | Store says ok:true, right id, but stored:false for the verdict | DEFECT | holds | fixed | A verdict reply must say `stored: true` and `state: "verified"`. `stored: false` withholds the effect and logs `reply_rejected`. |
| V16 | Real store already holds a different D-4004 verdict: reply says state=conflicted | DEFECT | holds | fixed | Reply `state: "conflicted"` withholds the effect. |
| V17 | D' path: store replies state=unverified, host still commits the effect | DEFECT | holds | fixed | Reply `state: "unverified"` withholds the effect. This changed the shipped run: `example/run/host-Dp.jsonl` now shows `reply_rejected`/`effect_withheld` instead of `effect_committed`, and D' is documented as "quarantined and the effect stops". |
| V18 | Store closes the connection without replying | DEFECT | holds | fixed | A store that closes without replying is now `ship_failed` + `effect_withheld`, exit 0, no traceback. Before: json.loads on an empty buffer escaped as a traceback. |
| V19 | Journal open() raises EIO during a verdict append | DEFECT | holds | fixed | A journal open() that raises returns `ok:false, durable:false`; memory and disk agree that the verdict is unknown. |
| V20 | fsync raises EIO after the bytes were written | DEFECT | holds | fixed | A failed fsync cuts the file back to its previous length, so the bytes do not survive as an unacknowledged record; live and restart agree; store_seq stays unique. |
| V21 | Torn line mid-journal while the store keeps running; later acknowledged records | DEFECT | holds | fixed | A partial line is quarantined before the next append instead of being written onto, and repair keeps the records that follow damage instead of truncating at it. All three acknowledged ids survive the restart. |
| V22 | f11 probe coverage: the failpoint only refuses before any byte is written | STATIC | STATIC | open | Unchanged and not disputed: the f11 failpoint still refuses before any byte is written, so the probe exercises "refused", not "torn". Only damage in the audit does. Named as open in the note. |
| V23 | Host disk lost between B's crash and recovery (WAL + host journal deleted) | DEFECT | DEFECT | open | No host-disk-loss test and no independently recorded kill receipt. Out of the current claim; the note says so. |
| V24 | Host patched not to die in C/C'/C'' (returns instead of os._exit) | DEFECT | DEFECT | open | Nothing in the suite authenticates that the host died. A host patched to return instead of exiting is indistinguishable from a host that crashed, and the artifacts still pass. Not fixed; the survivability claim is narrowed accordingly. |
| V25 | External SIGKILL between WAL commit and ship (real kill), store up but silent | INFO | INFO | informational | External SIGKILL between WAL commit and ship. No change. |
| V26 | Benign store restart after the run (one extra boot record) on valid evidence | DEFECT | holds | fixed | B binds to the epoch the verdict landed in (the boot record in front of it) instead of the last boot in the file, so a routine restart after a valid run verifies again: exit 0, failed []. |
| V27 | verify.py run twice on the same valid run | holds | holds | unchanged | verify.py run twice on the same valid run still holds. |
| V28 | Main-journal repair (torn append before B's restart) is reported | DEFECT | DEFECT | open | F-07. Deletions and rewrites inside a framed journal are not detected because nothing signs the sequence. Not fixed. |
| V29 | Store journal truncated at a record boundary (last record removed) | DEFECT | DEFECT | open | F-07, same cause: a journal truncated at a record boundary still verifies. |
| V30 | Mid-file deletion of D-4004 issue+commitment, frames intact | DEFECT | DEFECT | open | F-07, same cause: a mid-file deletion with frames intact still verifies. |
| V31 | Invented issued id inserted, frames recomputed, reconciliation regenerated by the store | DEFECT | DEFECT | open | F-07, same cause: an invented issued id with recomputed frames and a store-regenerated reconciliation still verifies. |
| V32 | D-4004 commitment replaced (frame recomputed) | DEFECT | DEFECT | open | F-07, same cause: a replaced commitment still verifies. |
| V33 | Expectation registered only after host A finished (old T38) | DEFECT | DEFECT | open | F-07: an expectation registered after host A finished still verifies. |
| V34 | Verifier robustness: four damaged inputs | holds | holds | unchanged | Four damaged inputs still produce a report rather than a crash. |
| V35 | regressions.py against the first-audit repository (claim: each mode beat the old verifier) | DEFECT | n/a | not testable | Needs HFB_OLD_REPO, the first-audit repository. It was not set here and that repository is not in the package, so this one outcome is unmeasured rather than fixed. |
| V36 | One idle connection blocks the store (old T37, documented as open) | INFO | INFO | open | One idle connection still blocks the single-threaded store. Documented as open; unchanged. |

| id | his outcome on df0cf5a | after P2 | disposition | note |
| --- | --- | --- | --- | --- |
| N01 | holds | holds | unchanged | Exit 2, message, no traceback, no report. |
| N02 | holds | holds | unchanged | A path that is a regular file is still refused. |
| N03 | holds | holds | unchanged | Empty directory still exits non-zero without a traceback. |
| N04 | holds | holds | unchanged | Missing second directory still fails determinism and names it. |
| N05 | holds | holds | unchanged | Second run missing one artifact still fails determinism. |
| N06 | DEFECT | holds | fixed | `verify.py run run` is refused: the same directory is compared with itself, and determinism now says so instead of reporting a pass. |
| N07 | holds | holds | unchanged | A byte copy of the same run is still indistinguishable from a second run. Stated limit. |
| N08 | holds | holds | unchanged | Only ARTIFACT_FILES are compared; an extra file is still ignored by design. |
| N09 | holds | holds | unchanged | A report path that is a directory still prints the verdict and exits 0. |
| N10 | holds | holds | unchanged | A report path that cannot be written on a failing run still exits 1 without a traceback. |
| N11 | untestable | held, tested another way | untestable as written | chattr +i is refused in this sandbox exactly as in his. Tested another way: a stale verify-report.json, chmod 444, inside a read-only directory. Result: verdict printed, exit 0, no traceback, the file left untouched, and new text naming it as an older run so it is not read as this one. |
| N12 | DEFECT | holds | fixed | The "not a run" path is generated under a fresh temporary directory instead of a fixed name, so it is absent whatever is lying around in the temp directory. |
| N13 | DEFECT | raises in his harness | fixed, his check needs updating | challenge.py no longer writes a report into the directory it was pointed at; it verifies copies and ends by fingerprinting the evidence directory and printing that it is unchanged. His N13 now raises FileNotFoundError because it opens the file the defect used to leave. The property he was testing is now asserted by the tool itself, and that assertion is printed in every run. |
