# S1 to S5 reproduction, 3 November: results

Reviewer: Olusanya Timothy. Run date: 3 November 2026, evening.
Evaluation target: `006d7ee71aa6599521d6675c32f496c5427a846b`.
Documentation commit, not used as the code baseline: `759834945147152bcf2259477ec48425cce5d9f1`.

## Summary

| ID | Finding | Status |
|---|---|---|
| S1 | Conflict record append failure (NEW-2 / P08) | **Reproduced** |
| S2 | Quarantine without repair provenance (NEW-1 / P07) | **Reproduced** |
| S3 | Regression-runner robustness (U10 / NEW-3) | **Reproduced**, one tooling limitation noted |
| S4 | Stale positive report after write failure (N11) | **Environment-limited**, not executed |
| S5 | Leftover temporary fixtures (NEW-4) | **Reproduced** |

Four reproduced, one environment-limited, none not-reproduced. Under the reviewer's own rule, S4 stays
unreconciled until the immutable-file condition can be established on a filesystem that permits it. S5 is
reproduced but its scope note stands: it was observed as a temporary-directory listing, not as a
cryptographically anchored cross-environment result.

## The integrity position, stated plainly

The archive digest `e34c35c8a9269dddfd0ec9452b5a3b3e5894246362ce031c36be3d5b26b33f98` could not be
checked, and the reason is structural rather than an omission by either side.

The 42 files that arrived at `ec6e46f` are the archive's contents, so the working set is complete. A zip's
SHA-256 hashes the container, not the contents: the compression stream, the headers, the timestamps and the
file order. Extraction discards all of that, so the digest cannot be recomputed from the files and it
cannot be verified against them. A fresh re-zip would not match either, because the timestamps differ.

So the position is: **content complete and pinned by manifest, container digest unverified.** The
reproduction below ran against those 42 files and against `006d7ee` extracted from git, so the results do
not depend on the container being the one that was hashed.

To convert that into the stronger claim, one of two things is needed. Either the manifest is checked on the
sender's extracted copy, forty-two hashes matching, which proves the content sets are equal. Or the original
zip is published as a release asset, which is the only way to satisfy the digest itself.

## Environment

| Item | Value |
|---|---|
| OS | Debian GNU/Linux 12 (bookworm) |
| Kernel | Linux 6.1.158+ |
| Python | 3.11.2 (GCC 12.2.0) |
| Cores | 2 |
| Filesystem for the run | ext4, `/dev/root` |
| `bc` | absent |
| `chattr` | present, `+i` refused with `Operation not permitted` |
| Source tree | fresh `git archive` of `006d7ee`, separate from the working clone |
| Evidence tree | copy of the 42 uploaded files, never the same directory as the source |

Source identity was checked before any probe ran, with the reviewer's own assertion:

```
python3 -c 'import os; assert os.path.isfile(os.path.join(os.environ["HFB_REPO"], "bench", "store.py"))'
```

## S1. Conflict record append failure

| Field | Value |
|---|---|
| Command | `python3 p2probes.py P08` |
| Exit code | 0 |
| Expected | the reply describes what is on disk |
| Observed | `{"reply": {"ok": false, "durable": false, "error": "OSError: [Errno 28] No space left on device"}, "second_verdict_on_disk": true, "live_state": "conflicted", "restart_state": "conflicted", "conflict_record": false}` |
| Log | `logs/s1-p08.log` |
| Status | **Reproduced** |

The reply reports `ok:false, durable:false` while a second verdict is already durable on disk, and both the
live and restarted states are conflicted with no conflict row. That is the reviewer's recorded observation
exactly, including the error string.

The decision criterion stands and is not softened: a two-append operation needs transactional semantics or
an explicit uncertainty response, because "failed acknowledgement" and "no persisted bytes" are different
facts and the caller cannot tell them apart from this reply.

## S2. Quarantine without repair provenance

| Field | Value |
|---|---|
| Command | `python3 p2probes.py P07` |
| Exit code | 0 |
| Expected | a repair record names the quarantined bytes, as the start-up repair does |
| Observed | `journal kinds=['boot', 'issued', 'issued', 'boot']; quarantine files=['store.jsonl.quarantine-1.bin']; issued after restart=['T-1', 'T-3']` |
| Log | `logs/s2-p07.log` |
| Status | **Reproduced** |

The quarantined bytes exist in a side file and the journal contains no repair row for the runtime cut. The
second `boot` record shows the restart happened without announcing what was removed from the log.

## S3. Regression-runner robustness

| Field | Value |
|---|---|
| Commands | `HFB_REPO=$HFB_REPO bash runner_checks.sh` then `HFB_REPO=$HFB_REPO bash runner_extra.sh` |
| Exit codes | 0 and 0 (the labelled conditions inside them are expected to fail) |
| Expected | the injected faults are reported as labelled outcomes, not as a runner that dies silently |
| Observed | see below |
| Logs | `logs/s3-runner_checks.log`, `logs/s3-runner_extra.log` |
| Status | **Reproduced**, with `bc` absent |

Observed, per label:

- **R2**, piped output: `exit=0 chunks(t, bytes)=[(15.63, 2784)]`. Nothing arrives before completion, so a
  long campaign has no progress output.
- **R3a**, 11 second store start: `rc=1 after 15 s`, `store did not announce a port`, while f1, f10, f11,
  f13 and f14 print "caught".
- **R3b**, 3 second store start: `rc=0` for f1, f11 and f3.
- **R4**, full campaign on a disposable copy: `campaign rc=0`, `R4: identical`, so the checkout is unchanged.
- **R5**, child that never returns: `rc=124 after 45 s; output bytes: 0`.
- **R6**, `run.py` always exits 3: `rc=1; modes reported: 0; the suite did not complete for this mode: run.py
  produced no artifact directory (exit 3)`.
- **R7**, `verify.py` raises on import: `rc=1`, with f1, f10, f11, f13, f14, f18, f19 and f20 reported
  MISSED, and f16, f17 and f21 caught. That is the reviewer's "MISSED instead of a complete error or
  NOT-RUN classification" reproduced.
- **R9 and R9b**, the recovery and unsigned-scenario contrasts: `regressions rc=1` in both, with f20 and f22
  MISSED in both and f2a MISSED in R9 only.

**The tooling limitation.** `bc` is not installed in this environment, so the elapsed-time columns print
`s: command not found` and the durations are blank. Every labelled classification was still produced, so
the limitation affects the timing columns only and does not change any status. Anyone re-running on a host
with `bc` present will get the durations filled in.

## S4. Stale positive report after write failure

| Field | Value |
|---|---|
| Command | `PYTHONUNBUFFERED=1 python3 v3fixes.py 2>&1 \| tee s4-n11-run.log` |
| Exit code | 1, from the known obsolete tail, not from N11 |
| Expected | report made immutable, then the verifier must refuse to present the old report as a fresh result |
| Observed | `[AS-DOC] N11 stale unwritable report ... observed: not testable here: chattr +i refused (chattr: Operation not permitted while setting flags on /tmp/v2run-qnhszyg6/verify-report.json)` |
| Log | `logs/s4-n11-run.log` |
| Status | **Environment-limited**, not executed |

`chattr +i` was refused independently of the script, with a bare probe on an empty file in `/tmp`:
`chattr: Operation not permitted while setting flags`. The kernel blocks the immutable flag for this
container's user namespace, so the condition N11 needs cannot be established here.

The labelled N11 line is produced before the obsolete N13 tail, exactly as the reviewer warned. The
`FileNotFoundError` on `verify-report.json` that follows it is that tail and is not evidence about N11.

This finding stays unreconciled. It is not reproduced here, it is not disputed, and it should not be
described as passing.

## S5. Leftover temporary fixtures

| Field | Value |
|---|---|
| Command | `TMPDIR=$TMPROOT PYTHONDONTWRITEBYTECODE=1 python3 audit/regressions.py f20` on a disposable copy |
| Exit code | 0 |
| Expected | no disposable fixture directory remains unless it is retained and named as an artifact |
| Observed | two directories left behind: `hfb-f20-benign-xvqqvqc7` and `hfb-f20-old-n2ip13b4`, 58 files and 384 KiB each |
| Log | `logs/s5-f20.log` |
| Status | **Reproduced** |

The run succeeded, the checkout was a copy, `TMPDIR` was a fresh parent, and two full copies of the tree
were still on disk afterwards. The `f20` mode alone leaves two. The reviewer's note that repeated campaigns
also leave `hfb-f21*` and `hfb-f22*` was not re-run here, because the finding is already established by the
two directories this single mode produced.

## What this changes in the register

S1, S2, S3 and S5 move from unreconciled to reproduced. S4 stays unreconciled and is now recorded as
environment-limited rather than untested.

Reproduced is not the same as fixed, and none of these are agreed as fixed. The register keeps them as
findings with a reproduction date until the maintainer either ships a correction or states the behaviour is
intended, and neither has happened yet.
