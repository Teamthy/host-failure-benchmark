# Findings register

Olusanya Timothy, 1 November 2026. Against `Teamthy/host-failure-benchmark`. The base was
`df0cf5a`; P2 is commit `006d7ee` on `main`, applied from the patch whose sha256 is
`96d3e59aa016a534dcb694506ed954b624c1667ea783797b78d80a1169895e09`. Every row can be checked
out, not just reproduced from a patch.

## Attribution

- **Reviewer.** Behar Dalipi, research collaborator, conducted the independent technical
  verification, the failure-model analysis and the adversarial testing recorded here. His 36
  outcome tests and 13 input checks are the source of every case in this register.
- **Author.** Olusanya Timothy implemented the benchmark and the remediation, and wrote this
  register and the disposition that accompanies it. The findings are the reviewer's; the fixes,
  the verdicts and the reasoning against a finding are the author's.
- **What the reviewer's contribution is and is not.** It is verification and adversarial testing.
  It is not an endorsement of the benchmark, and no row here should be read as one. Where a row is
  disputed, the reviewer's position and the author's are both recorded in the row.
- **State at the time of writing.** The reviewer's independent rerun against `006d7ee` was in
  progress. No result from that rerun is included in this document, and nothing here should be read
  as reporting one.
- **Provenance of this section.** Added on 1 November 2026 at the reviewer's request, so that the
  permanent record names him and keeps his verification separate from the author's remediation.

One row per finding. A row is **closed** only when a mode in `audit/regressions.py` fails
without the fix. That rule has not changed since the first version of this register. Six rows now
meet it: F-01, F-02, F-03, F-04, F-05 and F-09, each with a mode named in the row. The rest stay
open, including the ones a patch has touched.

Status words mean one thing each:

- **open**: reproduced or accepted, no fix in any tree I control
- **patched**: fix written and verified against the reviewer's own case, which now behaves as
  documented; the in-repo mode that would close the row is not written yet
- **disputed**: I believe the case does not test the property it names, or tests something
  outside the stated threat model; the reasoning is in the row and the evidence is in
  `evidence/2026-11-01/`
- **scope**: nothing to patch; the claim is narrowed and the narrowing is written in
  `TECHNICAL-NOTE.md`
- **closed**: patched, and a mode in `audit/regressions.py` fails without it

## Where the numbers come from

The reviewer shipped 36 outcome tests and 13 input checks. Re-run unchanged against `df0cf5a`,
the reviewer's own results file marks 23 outcomes as defects and 9 as documented. Against P2 it marks 9 as
defects and 22 as documented. The per-case table, with the disposition of every one of the 49
cases, is `DISPOSITION-2026-11-01.md`. Every count in this register comes from that table.

## My own three, found before the package arrived

All three were reproduced on `df0cf5a` by hand, and all three turned out to be cases in his
package: R1 is V05, R2 is V17, R3 is V19. Each now behaves as documented under P2.

| id | finding | the reviewer's case | fix | status |
| --- | --- | --- | --- | --- |
| R1 | Recovery authenticated by trust: replay took `state` from the journal row instead of recomputing it, so an unsigned record that says `verified` closed a gap after a restart | V05, V06 | store recomputes state from the record bytes and the id the row is filed under, through one `bound_state()` in `bench/common.py` that the store and the verifier both import | closed, `f16` and `f17` |
| R2 | An effect committed on a qualified acknowledgement: the host read `ok: true` without reading `state`, so the unsigned D' verdict still logged `effect_committed` | V15, V16, V17, V18 | a verdict reply must say `stored: true` and `state: "verified"`; anything else, including a closed connection, withholds the effect and names the reason | closed, `f19` |
| R3 | I/O failure had no answer: a journal that could not be written raised inside the handler, printed a traceback and closed the connection with no reply | V19, V20, V21 | a failed append cuts the file back to its previous length and the store answers `ok: false, durable: false`; a damaged tail is quarantined before the next append; repair keeps the records that follow damage | closed, `f21` |

## Findings raised by Behar Dalipi, as F-numbered in his review

| id | finding | cases | fix | status |
| --- | --- | --- | --- | --- |
| F-01 | journal state and action-ID binding | V05, V06 | as R1 | closed, `f16` and `f17` |
| F-02 | conflicting verdicts and verifier self-consistency | V12, V13 | check `D` refuses to report a record verified while the same journal lists its action as an unresolved gap | closed, `f18` |
| F-03 | acknowledgement and effect admission | V15-V18 | as R2, plus `D'.effect`, which fails if an effect is committed for a record the store could not resolve | closed, `f19` |
| F-04 | durable journal I/O, torn writes | V19-V22 | as R3 for V19-V21; V22 stays open: the failpoint still refuses before any byte is written, so only damage tests tearing | closed for V19-V21 (`f21`), V22 open |
| F-05 | false rejection after a routine restart | V26 | `B` binds the recovered verdict to the epoch it landed in, not to the last boot record in the file | closed, `f20`, which also requires the benign restart to verify |
| F-06 | host loss and proof of crash | V23, V24 | none. No independently recorded kill receipt, no named host-disk-loss test, and nothing in the suite authenticates that the host died | scope |
| F-07 | completeness of earlier evidence | V28-V33 | none. Nothing signs the sequence or checkpoints the journal, so a deletion or a rewrite inside framed records still verifies | open |
| F-08 | timestamp semantics and the shared fixture key | V02, V04 | `B.decision` compares the recovered verdict and rule with the guard decision the host logged; V04 is disputed: its mutation writes the value the field already holds, and the re-signed record is byte-identical to the WAL | patched, V04 disputed |
| F-09 | runner trustworthiness | V35, N06, N11-N13 | `verify.py run run` is refused; `challenge.py` writes nothing into the evidence directory, derives its absent path, and fingerprints the directory to prove it is unchanged | closed for N06, N12 and N13 (`f22`); V35 not testable here |
| F-10 | idle connection blocks the store; client-selected ids | V36, F6 | none | open |

## Disputed, with the evidence beside it

| case | why |
| --- | --- |
| V04 | Replay step and decision step are both 2 in this run, so `record["decision_ts"] = self.clock.step + 1` rewrites the field with the value it already held, and re-signing produces identical bytes. `evidence/2026-11-01/v04-inert-proof.log` prints `record_identical_to_wal=True` for the reviewer's exact mutation and `B=fails, B.wal=fails, exit=1` for the same mutation with the clocks five steps apart. `B.wal` compared the stored timestamp with the WAL before P2 as well. |
| N13 | The reviewer's check requires `challenge.py` to leave a passing report in the directory it was pointed at. I removed that behaviour, so the file it opens no longer exists and the check raises. The property is now asserted by the tool, every run, in its last line. |

## Carried over, unchanged

| id | finding | status |
| --- | --- | --- |
| F6 | identifiers are chosen by the caller and registered, not minted. Minting changes the scenario table, so it is a question rather than a patch | open, asked 1 November |
| F15 | an idle connection can hold the store | open |
| V1 | the verifier still imports the encoder it checks, so the correlated-oracle problem stays until there is a second encoder | open |
| H1 | no CI matrix. The cross-platform claim is two machines compared by hand | open |

## How the six rows closed

Seven modes in `audit/regressions.py`, nineteen in all, every one caught:

| mode | the counterexample | what has to catch it |
| --- | --- | --- |
| f16 | a journal row asserting `state: verified` over an unsigned record, then a restart | the gap stays named |
| f17 | a record signed for D-4004 filed under C-3003, then a restart | the gap stays named |
| f18 | a second, differently signed D-4004 verdict with the conflict record removed | D |
| f19 | the host's acknowledgement requirement disabled, as it was before P2 | `D'.effect` |
| f20 | a routine restart after a valid run, against the binding P2 replaced | B holds with the fix, B fails without it |
| f21 | open() and fsync() raising EIO during an append, in process | the store answers, and memory and disk agree |
| f22 | one directory compared with itself, and a challenge over the evidence | the refusal, and the directory unchanged |

The reviewer's acceptance rule is both halves, so f20 tests both: the benign restart has to verify and the
old binding has to fail on it. The other half is measured by the suite itself, which P2 leaves at
13 of 13 Class P and 3 of 3 Class V, two runs byte-identical, and every mutation in
`challenge.py` still caught.
