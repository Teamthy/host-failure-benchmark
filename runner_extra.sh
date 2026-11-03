#!/usr/bin/env bash
# R6, R7, R9, R9b: how audit/regressions.py reports a failing driver, a broken verifier and a broken
# implementation. Usage: HFB_REPO=/path/to/clean/checkout ./runner_extra.sh   (HFB_REPO is never written)
set -u
: "${HFB_REPO:?set HFB_REPO to a clean checkout}"
export PYTHONDONTWRITEBYTECODE=1
W=$(mktemp -d)
copy() { rm -rf "$W/$1"; cp -r "$HFB_REPO" "$W/$1"; }
patch() { python3 - "$@" <<'EOF'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read(); assert s.count(old) == 1, (path, old)
open(path, "w").write(s.replace(old, new))
EOF
}
modes() { grep -E " caught | MISSED " "$1" | awk '{print $1, $2}' | tr '\n' ' '; echo; }

echo "== R6: run.py always exits 3"
copy r6; patch "$W/r6/run.py" $'def main(argv):\n' $'def main(argv):\n    raise SystemExit(3)\n'
cd "$W/r6"; timeout 300 python3 audit/regressions.py > "$W/r6.out" 2> "$W/r6.err"
echo "rc=$?; modes reported: $(grep -cE ' caught | MISSED ' "$W/r6.out"); $(tail -1 "$W/r6.err")"

echo "== R7: verify.py raises on import"
copy r7; patch "$W/r7/verify.py" $'import hashlib\n' $'raise RuntimeError("broken verifier")\nimport hashlib\n'
cd "$W/r7"; timeout 300 python3 audit/regressions.py > "$W/r7.out" 2>&1; echo "rc=$?"; modes "$W/r7.out"

echo "== R9: recovery silently replays nothing"
copy r9; patch "$W/r9/bench/host.py" $'        for record in records:\n            self.emit("replay_read"' \
  $'        records = []\n        for record in records:\n            self.emit("replay_read"'
cd "$W/r9"; timeout 120 python3 run.py > /dev/null 2>&1; echo "unmutated: $(python3 verify.py artifacts/run-* | tail -1)"; rm -rf artifacts
timeout 300 python3 audit/regressions.py > "$W/r9.out" 2>&1; echo "regressions rc=$?"; modes "$W/r9.out"

echo "== R9b: scenario D ships unsigned"
copy r9b; patch "$W/r9b/bench/host.py" $'    def scenario_D(self):\n        return self.binding_case(strip_signature=False)' \
  $'    def scenario_D(self):\n        return self.binding_case(strip_signature=True)'
cd "$W/r9b"; timeout 120 python3 run.py > /dev/null 2>&1; echo "unmutated: $(python3 verify.py artifacts/run-* | tail -1)"; rm -rf artifacts
timeout 300 python3 audit/regressions.py > "$W/r9b.out" 2>&1; echo "regressions rc=$?"; modes "$W/r9b.out"; tail -1 "$W/r9b.out"
