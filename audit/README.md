# audit

The counterexamples from the two reviews of 1 November 2026, kept as tests.

The first twelve modes beat `verify.py` at commit `25cd57f`. The seven after them are the
differential review's F-01 to F-05 and F-09, which beat `df0cf5a`. Each one now has to be
caught by a named check, and the script fails if any of them is accepted again.

```
python3 audit/regressions.py          # all nineteen
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
| f16 | a journal row asserting `state: verified` over an unsigned record, then a restart | the gap stays named |
| f17 | a record signed for D-4004 filed under C-3003, framed and appended | the gap stays named |
| f18 | a second, differently signed D-4004 verdict with the conflict record removed | D |
| f19 | the host's acknowledgement requirement disabled, as it was before P2 | D'.effect |
| f20 | a routine restart after a valid run, both with the P2 binding and with the old one | B holds with the fix, B fails without it |
| f21 | open() and fsync() raising EIO during a verdict append, in process | the store answers `ok:false, durable:false` |
| f22 | one directory compared with itself, and a challenge run over the evidence directory | the refusal, and the directory unchanged |

f7 and f9 damage the evidence; f10, f11, f19 and f20 damage the code, because those findings
are about the order a process acts in and there is no artifact that could carry the bug. f16,
f17 and f18 damage the store journal and then ask a restarted store, which is how the reviewer
posed them. f21 runs the store in process, because a failed write cannot be arranged by editing
a finished run. f22 tests the tools rather than a run, and f20 tests both directions: a benign
restart has to verify, and the pre-P2 binding has to fail on it, or a check that always fires
would read as a fix. Each mode says which kind it is, so a reader can tell
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
