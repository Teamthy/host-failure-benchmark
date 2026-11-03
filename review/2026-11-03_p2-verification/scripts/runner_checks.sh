#!/usr/bin/env bash
# Runner checks R1-R5 for audit/regressions.py. Usage: HFB_REPO=/path/to/clean/checkout ./runner_checks.sh
# Every check works on a throwaway copy; HFB_REPO is never written to.
set -u
: "${HFB_REPO:?set HFB_REPO to a clean checkout}"
export PYTHONDONTWRITEBYTECODE=1
W=$(mktemp -d)

copy() { rm -rf "$W/$1"; cp -r "$HFB_REPO" "$W/$1"; }

echo "== R1: each mode alone, 240 s timeout"
copy r1; cd "$W/r1"
for m in f1 f2a f2b f3 f5 f7 f8 f9 f10 f11 f13 f14; do
  s=$(date +%s.%N); timeout 240 python3 audit/regressions.py "$m" > "$W/$m.out" 2>&1; rc=$?
  printf "%-4s rc=%-3s %6.2fs  %s\n" "$m" "$rc" "$(echo "$(date +%s.%N) - $s" | bc)" "$(sed -n 2p "$W/$m.out" | tr -s ' ')"
done

echo "== R2: when does piped output arrive? (PYTHONUNBUFFERED unset)"
env -u PYTHONUNBUFFERED python3 - <<'EOF'
import subprocess, sys, time, os
env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
t0 = time.time(); p = subprocess.Popen([sys.executable, "audit/regressions.py"], stdout=subprocess.PIPE, env=env)
chunks = []
while True:
    b = p.stdout.read1(65536)
    if not b: break
    chunks.append((round(time.time() - t0, 2), len(b)))
p.wait(); print("exit=%s chunks(t, bytes)=%s" % (p.returncode, chunks))
EOF

echo "== R3: simulated slow store start"
copy r3; cd "$W/r3"
python3 - <<'EOF'
p = 'bench/store.py'; s = open(p).read()
old = '    args = ap.parse_args(argv[1:])\n\n    store = Store(Journal(args.journal))'
new = ('    args = ap.parse_args(argv[1:])\n    import time as _t\n'
       '    _t.sleep(float(os.environ.get("AUDIT_STORE_DELAY", "0")))\n'
       '    if args.announce.endswith("port-regression.txt"):\n'
       '        _t.sleep(float(os.environ.get("AUDIT_F3_DELAY", "0")))\n\n'
       '    store = Store(Journal(args.journal))')
assert s.count(old) == 1; open(p, 'w').write(s.replace(old, new))
EOF
s=$(date +%s); AUDIT_F3_DELAY=11 timeout 600 python3 audit/regressions.py > "$W/r3a.out" 2> "$W/r3a.err"
echo "R3a (f3's own store start takes 11 s): rc=$? after $(( $(date +%s) - s )) s"
grep -E " caught | MISSED " "$W/r3a.out" | awk '{print $1, $2}' | tr '\n' ' '; echo; tail -1 "$W/r3a.err"
for m in f1 f11 f3; do
  s=$(date +%s.%N); AUDIT_STORE_DELAY=3 timeout 600 python3 audit/regressions.py "$m" > /dev/null 2>&1
  echo "R3b $m with 3 s per store start: rc=$? $(echo "$(date +%s.%N) - $s" | bc | cut -c1-5) s"
done

echo "== R4: the checkout is unchanged by a full campaign"
copy r4; cd "$W/r4"; python3 audit/regressions.py > /dev/null 2>&1; echo "campaign rc=$?"
diff -r "$HFB_REPO" "$W/r4" > /dev/null && echo "R4: identical" || echo "R4: CHANGED"

echo "== R5: a child that never returns"
copy r5; cd "$W/r5"
python3 - <<'EOF'
p = 'bench/host.py'; s = open(p).read()
old = '    def scenario_A(self):\n'
assert s.count(old) == 1
open(p, 'w').write(s.replace(old, old + '        import time; time.sleep(10**6)\n'))
EOF
s=$(date +%s); env -u PYTHONUNBUFFERED timeout 45 python3 audit/regressions.py f1 > "$W/r5.out" 2>&1
echo "R5: rc=$? after $(( $(date +%s) - s )) s; output bytes: $(wc -c < "$W/r5.out")"
