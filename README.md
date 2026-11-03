# What survives when the host dies

A small local suite about one question: when an agent's guard decides something and the record of that decision does not reach the audit store, what can still be known afterwards?

Repository: https://github.com/Teamthy/host-failure-benchmark

There is no model here. There is no network beyond loopback and no external key. Two processes talk over a socket for about one second, one of them exits deliberately in the middle of its work (`os._exit(9)`, not a signal from outside), and the artifacts are checked by a separate program that trusts none of them.

## What this shows, and what it does not

Four failure rows, each with a test. Row M1 is a decision made and never emitted. M2 is a decision emitted and lost. M3 is the host dying before anything was ingested. M4 is a record that survived but cannot be verified.

The suite reports two classes separately, because they fail for different reasons and a single score would hide that.

Class P is persistence and recovery: whether the evidence outlives the process that made it. Thirteen checks. Six further checks cover completeness, framing, line endings and the counter clock; a missing artifact or a journal that does not parse is a failure, not a shorter history.

Class V is verification: whether a record that survived is the record it says it is, from who it says, under the policy version it names. This claim rests on a key derived from a fixed seed written in the source, which shows the binding is internally consistent and is not evidence of production key security or of anyone's institutional trust. Three checks.

One distinction runs through both classes and is reported by the suite rather than assumed: a decision time carried through replay is source-asserted, not independently verified. `verify.py` prints that in every result, and the JSON report carries it as its own field.

## The named gap

Row M3 was the interesting one, and it splits three ways. The split is the result, not a footnote.

| Case | What the store still holds | What the record can say afterwards |
| --- | --- | --- |
| C | the issued id and a commitment to the descriptor | a gap, with its content |
| C' | the issued id only | a gap, with no content |
| C'' | nothing | nothing at all |

Strength of the named gap is reported. What the record knows is what was written down before the host died.

The third case is silence, and silence is the strongest statement in the table: the benchmark itself cannot tell that an action happened. That is stated as a limit rather than hidden, because a suite that claims to detect C'' would be reporting its own cleverness.

Strength of the named gap is a reported dimension. It is not a score, and the three cases are not gradations of one result.

## Running it

Python 3.9 or newer, standard library only. On Windows, in PowerShell (use `python3` on systems where that is the name):

```powershell
cd host-failure-benchmark
python run.py
python verify.py artifacts\run-20261101T120000Z
python challenge.py artifacts\run-20261101T120000Z
```

On any other system the same three commands with `artifacts/run-...` in place of the backslash.

`run.py` prints the directory it wrote. `verify.py` takes that directory and re-derives every assertion from the raw files inside it: the store journal, the write-ahead log, the per-scenario host journals. It does not read a pass flag, because nothing writes one.

`challenge.py` takes a finished run and damages it ten ways, then requires that the check claiming to catch each kind of damage does catch it. It also points the verifier at a directory that is not a run, and compares a run against a copy missing artifacts; both have to be refused. A checker that cannot fail is decoration.

`audit/regressions.py` is the same idea with harder mutations, one per finding in the November 2026 review. Each of them passed verification before that review and has to be caught now:

Whole thing runs in seconds, well inside the thirty minutes the spec allowed.

## Three probes, and why they are separate

Four of the properties here are about what a component does when the thing it depends on
misbehaves, and a scenario inside the normal run cannot show them without corrupting the record
the rest of the suite is built on. So `run.py` runs three short probes and keeps them in their own
directories, each with its own journal where it needs one:

| probe | what it forces | what the verifier requires |
| --- | --- | --- |
| `probe-durability` | the store's journal refuses a verdict write | the verdict is not reported as known, in memory or after a restart |
| `probe-repair` | a journal that stops mid-record | the repair names a file holding the discarded bytes, and its digest matches |
| `probe-reply` | a store that answers, well formed, about a different action | the host refuses the reply and logs no effect |

The third one is the only place in the suite where a process other than the two under test sends
bytes, and it is `bench/stub_store.py`: six lines of behaviour, no state, no replay, never used
for anything else.

## A finished run is included

`example/run/` is one complete run, exactly as the programs wrote it, with one exception: `port.txt` is left out, because the port changes between runs and every other file in the directory is byte-identical. You can check the checks without running anything:

```powershell
python verify.py example\run
python challenge.py example\run
```

Both should pass. If they do not, the code you have is not the code that produced the folder.

## What a pass is not

`run.py` finishing is not a pass. `verify.py` printing `VERDICT: every check holds` is a pass, and only for the artifacts it was given.

Every check in `verify.py` is written as a claim paired with the counterclaim that would refute it. When one fails, the output names the thing that refused it.

## Standard practice, honestly

Durability before acknowledgement, replay over reset, journal before memory in the store, repair that keeps the bytes it removes, a named conflict instead of a silent winner when two verdicts disagree, a reply checked against the request it answers, identifiers registered by a separate store, reconciliation against a prior expectation, canonical encoding, per-record framing, and a verifier that reads no pass flag: all implemented. The identifier is chosen by the caller and the store records the registration, which is a weaker thing than minting an id and is named that way here since the review of 1 November. Tamper evidence against someone holding the source, managed keys, trusted time, and operational controls: not implemented, and the note says which pattern each would need. The section in `TECHNICAL-NOTE.md` is the long version.

## The two distinctions this suite keeps

An issued action id does not prove an action was proposed. A proposal needs an independently preserved commitment to what was proposed, which is why C and C' are separated.

A signature plus a policy hash proves integrity and provenance. It does not prove the policy was correct, that the decision was institutionally authorised, or that the effect was executed. `D'` tests the first of those and nothing else.

## Files

```
bench/common.py     fixed clock, canonical encoding, signature
bench/store.py      audit store process, append-only journal, replays on start
bench/host.py       the host process, one scenario per run, killable
bench/stub_store.py a fixture that answers every request and confirms the wrong action
run.py              runs every scenario, asserts nothing
verify.py           reads artifacts, decides, writes verify-report.json
challenge.py        damages a run and confirms the damage is caught
example/run/        one finished run, unedited
```

## Licence

Code is MIT, see `LICENSE`. The note in `TECHNICAL-NOTE.md` is CC BY 4.0.

## Authorship

Written jointly by Behar Dalipi and Olusanya Timothy. Order and venue are settled at finalisation, on the record kept in `CONTRIBUTION.md` from the first commit.

This is the authors' own work. It is not an industry standard and should be cited by the commit it was taken from.
