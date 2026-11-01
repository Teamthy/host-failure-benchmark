# audit

The counterexamples from the technical review of 1 November 2026, kept as
tests.

Each mode in `regressions.py` beat `verify.py` at commit `25cd57f`. Each one
now has to be caught by a named check, and the script fails if any of them is
accepted again.

```
python3 audit/regressions.py          # all twelve
python3 audit/regressions.py f5       # one, with the detail
```

| mode | what it does | has to be caught by |
| --- | --- | --- |
| f1 | WAL verdict flipped BLOCK to ALLOW, stale signature, replayed | B |
| f2a | WAL timestamp changed before replay and re-signed | B (B.wal holds) |
| f2b | WAL timestamp changed after replay, store untouched | B.wal |
| f3 | unsigned verdict appended for C-3003, frame recomputed | the gap stays named |
| f5 | the seven host journals deleted | artifacts-complete |
| f8 | D-4004 actor and policy rewritten and re-signed | D |
| f13 | host-B.jsonl cut mid-line | artifacts-parse |
| f14 | D-4004 decision timestamp set to a Unix epoch value, re-signed | D |
| f7 | the bytes a repair removed deleted from the quarantine file | repair-quarantine |
| f9 | the conflict record removed, leaving the first verdict as the answer | conflict |
| f10 | the host's reply check disabled, as it was before the patch | reply-checked |
| f11 | the store indexing memory before the journal, as it was before | journal-first |

f7 and f9 damage the evidence; f10 and f11 damage the code, because those two
findings are about the order a process acts in and there is no artifact that
could carry the bug. Each mode says which kind it is, so a reader can tell
whether the counterexample is a bad record or a bad program.

Every mode copies the repository into a temporary directory and works there.
Nothing here modifies the checkout it is run from, and nothing here needs a
network, a key or a model.

The modes are named after the findings in the review, not after the tests:
the reviewer's numbering is the one a reader will have to hand.

f2a and f2b are the two intervention points around replay. Changing the WAL
before the store restarts makes the recovered record agree with it, so the
timestamp binding is what fails. Changing it afterwards makes the two
disagree, so `B.wal` fails. The first is the timestamp property; the second is
consistency between two files. They are not the same test and are not
interchangeable.
