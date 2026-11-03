# P2 verification kit and the S1 to S5 reproduction

Everything the independent P2 review supplied on 3 November, plus the reproduction results produced
against the pinned baseline the same evening.

**Evaluation target:** `006d7ee71aa6599521d6675c32f496c5427a846b`
**Documentation commit, not a code baseline:** `759834945147152bcf2259477ec48425cce5d9f1`

## The digest covers the container, the manifest covers the content

The review states `hfb-p2-verification.zip` hashes to:

```
e34c35c8a9269dddfd0ec9452b5a3b3e5894246362ce031c36be3d5b26b33f98
```

The 42 files delivered here are the archive's contents, so nothing is missing from the working set. What is
missing is the container. A SHA-256 of a zip covers the compression stream, the local and central directory
headers, the modification timestamps, the extra fields and the file order. None of that survives extraction,
so the digest cannot be recomputed from the files, and it cannot be checked against them either.

It also means a fresh re-zip will not match. Re-zipping the same folder produces a different digest because
the timestamps and ordering differ. Only the original file can satisfy that number.

Two ways to close it:

1. **Fast path.** Run `MANIFEST-delivered.sha256` against the extracted copy on the sender's side. Forty-two
   matching hashes prove the content sets are equal, which is what the reproduction results actually depend
   on, and lets both sides state the position precisely: content verified equal, container digest
   unverified.
2. **Record path.** Put the original zip in a release asset. Then the bytes anyone fetches are the bytes the
   digest describes.

`MANIFEST.sha256` pins the files at their paths in this repository, after the move and the rename.
`MANIFEST-delivered.sha256` pins them at the names they arrived with, so it can be checked against an
extracted copy directly:

```
sha256sum -c MANIFEST-delivered.sha256
```

## Layout

```
review/2026-11-03_p2-verification/
  README.md                  this file
  MANIFEST.sha256            hashes of all 42 files, at their paths below
  MANIFEST-delivered.sha256  the same 42 hashes at the names they arrived with
  scripts/                   the runners and fixtures
    p2probes.py               S1 (P08) and S2 (P07)
    runner_checks.sh          S3, checks R1 to R5
    runner_extra.sh           S3, checks R6 to R9b
    extra_checks.py           helper used by the runners
    v2lib.py, v2tests.py      shared library and the V-series probes
    v3fixes.py                S4 (N11), with an obsolete N13 tail
    build_matrix.py           the results matrix builder
  recorded/                  the review's own recorded outputs, kept byte for byte
    p2probes.delivered.json   the delivered capture, renamed so a re-run cannot overwrite it
    p2probes.log, p2-n-rerun.log, p2-v-rerun.log
    runner_checks.log, runner_extra.log
    p2-results-matrix.json, p2-results-matrix.csv, v2results.json
    campaign-1.out to campaign-3.out, reg-*.out, challenge-example.out, verify-*.out
  results-2026-11-03/        the reproduction run described below
    RESULTS.md               one row per finding, with commands, environment and status
    logs/                    the six logs behind that file
```

## Two changes from the delivered layout, and why

1. **The files moved out of the repository root.** They were uploaded flat, next to `verify.py`, `run.py`
   and `bench/`, which put an independent reviewer's fixtures inside the maintainer's tree at the top level.
   They now sit under `review/`, which is where a review belongs.
2. **`p2probes.json` was renamed to `p2probes.delivered.json`.** `p2probes.py` writes `p2probes.json` next
   to itself, so the first re-run overwrites the review's recorded capture. The delivered copy is preserved
   under the new name and the working file is ignored by git.

Nothing inside the 42 files was edited. `MANIFEST.sha256` was generated from the delivered bytes before the
rename, and a move does not change a hash.

## How to run it

Source and evidence must be two different trees, and the source must be the pinned commit, not the
repository head.

```
git archive 006d7ee71aa6599521d6675c32f496c5427a846b | tar -x -C /tmp/p2/source
export HFB_REPO=/tmp/p2/source
python3 -c 'import os; assert os.path.isfile(os.path.join(os.environ["HFB_REPO"], "bench", "store.py"))'

cd review/2026-11-03_p2-verification/scripts
export PYTHONDONTWRITEBYTECODE=1
python3 p2probes.py P08          # S1
python3 p2probes.py P07          # S2
HFB_REPO=$HFB_REPO bash runner_checks.sh
HFB_REPO=$HFB_REPO bash runner_extra.sh
PYTHONUNBUFFERED=1 python3 v3fixes.py    # S4, needs chattr +i
```

S5 needs a disposable checkout and a fresh temporary parent:

```
TMPROOT="$(mktemp -d)"; mkdir -p "$TMPROOT/checkout"
cp -a "$HFB_REPO/." "$TMPROOT/checkout/"
( cd "$TMPROOT/checkout" && TMPDIR="$TMPROOT" python3 audit/regressions.py f20 )
find "$TMPROOT" -maxdepth 1 -type d -name 'hfb-f2*' -print
```

Requirements: Python 3 with the standard library, bash and coreutils, `bc` for the timing columns in the
runners, and a filesystem that permits `chattr +i` for S4.

## Result

Four of the five findings reproduced on 3 November. S4 could not be executed because `chattr +i` is
refused in the container it ran in, so N11 stays unreconciled rather than reproduced or disputed. Details
and the per-finding rows are in `results-2026-11-03/RESULTS.md`.
