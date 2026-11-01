# What survives when the host dies: a small local suite for decision-time evidence

**Draft. Not yet reviewed by the second author.**

Behar Dalipi and Olusanya Timothy. Order and venue to be settled at finalisation, on the record in `CONTRIBUTION.md`.

Licence: CC BY 4.0.

---

## The question

An agent proposes an action. A guard decides whether to allow it. The decision is written down somewhere, and the action either proceeds or does not. Most of the discussion about this stops at the moment of decision, where everything is present and the guarantees look clean.

The interesting failures happen after that moment, when the process that decided is no longer available. This note asks one narrow question about those failures: when a decision is made and the record of it does not reach the audit store, what can still be known afterwards?

The answer turned out to depend less on cryptography than on what was written down before the process died, and on where it was written.

## What was built

Two processes on one machine, talking over loopback. A host proposes actions, decides verdicts, and writes a journal. A store issues action identifiers, preserves commitments, registers expectations, and holds verdicts. The store has its own append-only journal, fsynced per record, and it replays that journal on start, so a restart is a recovery rather than a reset.

There is no model in the loop, no external key, and no wall clock. The clock is a counter. Two runs on two machines produce byte-identical artifacts, which is checked directly by comparing two runs file by file.

Eight scenarios, each one invocation of the host, each with a named failure rather than a timing window:

| Test | What happens | What is being asked |
| --- | --- | --- |
| A | expectation registered, verdict suppressed | is the absence nameable |
| A' | same, no expectation registered | is it nameable without one |
| B | verdict committed locally, ship fails, store recovers | does the record carry the time it was decided |
| C | issued id plus preserved commitment, host killed | can the gap be described with content |
| C' | issued id only, host killed | can it be named without content |
| C'' | locally minted id, host killed | is there anything at all |
| D | full record, binding verifies | is it the record it claims to be |
| D' | full record, no binding | is it quarantined rather than accepted |

## Results

The suite reports two classes separately, because they fail for different reasons.

Class P, persistence and recovery: eight checks, all holding. The verdict in B is written to a local write-ahead log before the ship is attempted, the ship fails because the store is genuinely stopped, and the effect is withheld. On restart the store replays, the verdict lands, and it carries the timestamp from the moment of decision rather than the moment of arrival. The write-ahead log is a separate file and agrees with the store, so the timestamp is not reconstructed after the fact. Removing the local commit makes the check fail, which is how we know the log is doing the work.

Class V, verification: two checks, both holding. A complete record verifies against the key it carries, and the descriptor digest recomputes from the action rather than being taken on trust. A record whose binding does not verify stays visible and is counted as quarantined, never as verified.

The claim in Class V rests on a key derived from a fixed seed in the source. That shows a binding is internally consistent. It is not evidence of production key security and it says nothing about institutional trust.

## The finding that mattered

Row M3 was written as one failure and behaved as three. The difference is not the severity of the failure but how much was written down before the host died.

Case C registered the id and preserved a commitment to the descriptor. The store can name the gap and carry its content. Case C' issued the id and nothing else. The store can name the gap and cannot say what it was. Case C'' minted the identifier locally. The store holds nothing, and afterwards the action is indistinguishable from an action that never happened.

Silence is the strongest statement in the table, and it is also the one that limits the suite. A benchmark that claimed to detect C'' would be measuring itself, not the failure, so we report it as undetectable and stop there.

Strength of the named gap is therefore a reported dimension, not a binary and not a score. The three cases are not gradations of one result. They are three different amounts of foreknowledge, and the only one an audit store can act on is the one where something was promised in advance.

## What this does not show

Two distinctions are worth keeping in view, because they are easy to lose when the demonstration looks tidy.

An issued action identifier does not prove an action was proposed. It proves a name exists. The commitment is what makes the proposal evidence, and C' exists precisely to show what remains without one.

A signature plus a policy hash proves integrity and provenance. It does not prove the policy was correct, that the decision was institutionally authorised, or that the effect was executed. Class V covers integrity and provenance. The other three need a different mechanism each: policy review for the first, an authorisation record outside the signing key for the second, a receipt from the system of record for the third.

The suite also only tests two processes on one machine. It says nothing about a store that is itself partitioned, an attacker with the host's filesystem, or a clock that can move backwards.

## Reproducing it

Python 3.9 or newer, standard library only. `run.py` produces a run directory and asserts nothing. `verify.py` reads that directory and recomputes every assertion from the raw artifacts, with no pass flag anywhere in the pipeline. `challenge.py` damages a finished run six ways and requires that each kind of damage be caught by the check that claims to catch it.

Every check is written as a claim paired with the counterclaim that would refute it. When one fails, the output names the thing that refused it.

One reading is still open. The build assumes Class P carries the time a decision was made and claims nothing about whether that time is true. If that reading is wrong, C and C' stand unchanged and the timestamp claim is withdrawn.

## Citation

This is the authors' own work and is not an industry standard. Cite it by commit hash rather than by title, so a reader gets the version that was actually tested.
