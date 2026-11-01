# Contribution record

Kept from the first commit, so that author order and venue at finalisation rest on something written down rather than on memory. Dates are the date the contribution was made, not the date it was edited.

Repository: https://github.com/Teamthy/host-failure-benchmark
First commit `5bb8a7c`, 2026-11-01. Line endings pinned to LF in `.gitattributes` so a clone on Windows produces the same bytes as a clone on Linux.

## Per file

| File | Written by | First version | Basis |
| --- | --- | --- | --- |
| `SPEC v0.1` (working note, outside this folder) | Behar Dalipi | 2026-10-30 | His own framing: guarantee columns, failure-assumption columns, four rows |
| `spec-v0.2-integrated-guarantee-analysis.md` (outside this folder) | Olusanya Timothy | 2026-10-31 | Integration of v0.1 rows with the recovery and residual columns |
| `bench/store.py` | Olusanya Timothy | 2026-11-01 | Implemented from the agreed row definitions |
| `bench/common.py` | Olusanya Timothy | 2026-11-01 | Clock, encoding, signature |
| `bench/host.py` | Olusanya Timothy | 2026-11-01 | Scenario harness |
| `run.py` | Olusanya Timothy | 2026-11-01 | Driver |
| `verify.py` | Olusanya Timothy | 2026-11-01 | Checks, written as claim and counterclaim |
| `challenge.py` | Olusanya Timothy | 2026-11-01 | Mutation test of the checks themselves |
| `README.md` | Olusanya Timothy | 2026-11-01 | Draft, not yet reviewed by Behar |
| `TECHNICAL-NOTE.md` | Olusanya Timothy | 2026-11-01 | Draft, not yet reviewed by Behar |
| `LICENSE` | agreed jointly | 2026-11-01 | MIT for code, CC BY 4.0 for the note |

## Per claim

| Claim | Proposed by | State |
| --- | --- | --- |
| Four failure rows, each with its own test | Behar Dalipi | Agreed |
| Detectable-when, must-survive, recovery and residual columns | Behar Dalipi, integration Olusanya Timothy | Agreed |
| The M3 split into C, C', C'' | Joint, in the 2026-10-31 exchange | Agreed |
| Strength of the named gap is a reported dimension, not a binary | Joint | Agreed |
| An issued id does not prove an action was proposed | Behar Dalipi | Agreed, implemented as C vs C' |
| A signature plus a policy hash is not policy correctness, authorisation, or execution | Behar Dalipi | Agreed, stated in README and note |
| Class P and Class V reported separately | Olusanya Timothy | Proposed, no objection raised |
| Determinism by counter clock rather than wall clock | Olusanya Timothy | Proposed |
| Verification must re-derive from raw artifacts and never read a pass flag | Olusanya Timothy | Proposed |
| The checks must be able to fail, tested by mutation | Olusanya Timothy | Proposed |

## Open decisions

**The timestamp question. CLOSED 2026-11-01, 1:27 PM.** Confirmed by Behar Dalipi in writing: "Class P preserves the original T1 timestamp through replay without independently establishing its accuracy or authenticity as the actual decision time. The distinction between a source-asserted timestamp and an independently verified timestamp should remain explicit in the specification and benchmark results."

Acting on that: `verify.py` prints the distinction in every result, the JSON report carries it as a field named `timestamp`, and the note states it in the results section rather than only in the limitations. The claim is a carried time, not an attested one.

**Author order.** Unsettled by design. It is fixed at finalisation against the tables above.

**Venue.** Unsettled. The note is written so that it can go to a workshop or stay a repository document without rewriting.

## What is not claimed

This is the authors' own work. It is not an industry standard, no body has adopted it, and it should be cited by commit hash rather than by title alone.
