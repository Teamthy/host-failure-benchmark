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
| B | verdict committed locally, ship fails, store recovers | does the record carry the source-asserted decision time |
| C | issued id plus preserved commitment, host process exits | can the gap be described with content |
| C' | issued id only, host process exits | can it be named without content |
| C'' | locally minted id, host process exits | is there anything at all |
| D | full record, binding verifies | is it the record it claims to be |
| D' | full record, no binding | is it quarantined rather than accepted |

## Results

The suite reports two classes separately, because they fail for different reasons.

Class P, persistence and recovery: eight checks, all holding. The verdict in B is written to a local write-ahead log before the ship is attempted, the ship fails because the store is genuinely stopped, and the effect is withheld. On restart the store replays, the verdict lands, and it carries the timestamp from the moment of decision rather than the moment of arrival. The write-ahead log is a separate file and agrees with the store, so the timestamp is not reconstructed after the fact. Removing the local commit makes the check fail, which is how we know the log is doing the work.

Class V, verification: two checks, both holding. A complete record verifies against the key it carries, the descriptor digest recomputes from the action rather than being taken on trust, the actor and policy hash match the trusted constants, and the decision timestamp matches a counter step the host journal actually contains. A record whose binding does not verify stays visible, is counted as quarantined, never counts as verified, and never resolves a gap.

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

## What of standard practice this implements

Worth stating plainly, because a reviewer will ask and because the answer is uneven.

Implemented, and implemented the way the relevant practice says to: durability before acknowledgement, so a verdict is fsynced locally before any effect is attempted; recovery by replay rather than by reset, with a marker saying what arrived before a recovery and what arrived after; identifiers registered by a separate store rather than minted where the action happens, which is registration and not issuance: the caller chooses the id, and the review of 1 November is right that this is the weaker of the two claims; reconciliation against an expectation registered beforehand, which is the same idea as a control total; canonical encoding before any binding is computed; and a verifier that is a separate program reading only raw artifacts, never a pass flag written by the thing it judges.

Also implemented, and this one was added after the first version of this note would have claimed otherwise: per-record framing. A crash in the middle of an append leaves a partial line, and without a frame the only thing that notices is the parser falling over. Each record now carries a digest of itself, replay stops at the last whole record, the journal is cut back to that point, and a repair record states how many bytes were discarded. A truncated history is announced rather than silently presented as the whole one.

Not implemented, and these are the expensive ones:

Tamper evidence against an adversary who has the source. Records are framed but not chained, so anything that can rewrite the file can rewrite it consistently, and the binding key is a literal in `common.py`, so it can re-sign what it rewrote. The pattern that addresses this is the transparent log: a hash chain over records, signed checkpoints, and an external witness. None of that is here. What is here catches accident and casual editing, not intent.

Key management. A key derived from a seed in the repository is a test fixture. No hardware or managed key store, no rotation, no per-actor keys.

Trusted time. The clock is a counter, deliberately, and the decision time is source-asserted. Time synchronisation is the control that would change this, and it would cost the determinism, so the trade is stated rather than hidden.

Operational practice: rotation, retention, immutable storage, access control, privilege separation. The two processes run as the same user on the same disk. This is a demonstration of a discipline, not a deployment of one.

It is also not tested the way a production component would be: eight scenarios, one machine, no fuzzing, no continuous integration. Which is how the torn-journal case above went unnoticed until it was looked for.

## Reproducing it

Python 3.9 or newer, standard library only. `run.py` produces a run directory and asserts nothing. `verify.py` reads that directory and recomputes every assertion from the raw artifacts, with no pass flag anywhere in the pipeline. `challenge.py` damages a finished run nine ways and requires that each kind of damage be caught by the check that claims to catch it.

Every check is written as a claim paired with the counterclaim that would refute it. When one fails, the output names the thing that refused it.

The timestamp distinction, which the second author asked to remain explicit in both the specification and the results, is closed and reported. Class P preserves the original decision time through replay without independently establishing that it is the true moment of decision. That time is source-asserted. The suite prints this on every run, and the result file carries it as a field, so a reader cannot mistake a carried timestamp for an attested one. A mechanism that would bring independent attestation inside the claim would need a clock the host cannot set, which this suite deliberately does not have.

## What the review of 1 November changed

An independent review found four things wrong with the checks, and one of them
was the difference between what the note said and what the verdict line
printed. The following changed in response, each with a counterexample in
`audit/regressions.py` that failed before and is caught now:

- WAL records and recovered verdicts are signature-checked, at ingest and in
  the verifier. A record that does not verify is still stored and still
  visible, and it cannot resolve a gap.
- The verifier recomputes a record's state from the record itself instead of
  reading a state off the journal, compares the actor and the policy hash
  against the trusted constants in `bench/common.py`, and requires the
  decision timestamp to match a counter step the host journal contains.
- `run.py` writes a versioned manifest naming every required artifact, and the
  verifier checks each scenario's event chain. A missing journal used to be
  read as a scenario with nothing to say. It is now a failure.
- The timestamp question is now two tests rather than one, because it was
  being asked at two different moments. Changing the write-ahead log before the
  store replays makes the recovered record agree with it, and what fails is the
  binding between the timestamp and the host journal: `B` fails, `B.wal` holds.
  Changing the log after replay makes the two files disagree, and `B.wal`
  fails. F2's substance is untouched by the distinction: neither case shows the
  timestamp was independently attested, and the note says so in the same
  sentence as the result.
- The verifier no longer raises. An unreadable artifact produces a report with
  an explicit unreadable state, and the report is written either way.

Four things the review found and this patch does not fix, in the order they
matter: memory is still updated before the journal append in one path;
truncation on repair still discards bytes without keeping the original
journal; duplicate verdicts still resolve to whichever record a component
happens to read; and the host still does not validate the store's reply before
logging an effect. Those are the P1 items, and the note will say so until they
are done.

## Citation

This is the authors' own work and is not an industry standard.

Repository: https://github.com/Teamthy/host-failure-benchmark

Cite it by commit hash rather than by title, so a reader gets the version that was actually tested. The suite has been run on Windows with Python 3.14.5 and on Linux and the artifacts were compared by hand; there is no published digest trail for that comparison yet, and a CI matrix running both is the fix.
