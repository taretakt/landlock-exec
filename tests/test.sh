#!/usr/bin/env bash
# landlock-exec smoke suite: both directions must pass.
# The denied case alone is vacuous — if restrict_self fails, the child never
# runs and "denied" is meaningless. Allow case must pass FIRST.
set -euo pipefail
cd "$(dirname "$0")/.."

cc -O2 -Wall -Wextra -o landlock-exec landlock-exec.c

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/data/public" "$WORK/data/private"
echo public-content > "$WORK/data/public/open.txt"
echo secret-content > "$WORK/data/private/secret.txt"

# 1. allowed read inside the allow-list must succeed
OUT="$(./landlock-exec --ro "$WORK/data/public" -- cat "$WORK/data/public/open.txt")"
[ "$OUT" = "public-content" ] || { echo "FAIL: allowed read gave '$OUT'"; exit 1; }

# 2. read outside the allow-list must fail with Permission denied
if ./landlock-exec --ro "$WORK/data/public" -- cat "$WORK/data/private/secret.txt" \
    >"$WORK/denied.out" 2>"$WORK/denied.err"; then
  echo "FAIL: outside read succeeded (vacuous deny?)"; exit 1
fi
grep -qi "permission denied" "$WORK/denied.err" \
  || { echo "FAIL: unexpected deny error: $(cat "$WORK/denied.err")"; exit 1; }

# 3. write outside any allow-list must fail
if ./landlock-exec --ro "$WORK/data/public" -- sh -c "echo x >> '$WORK/data/private/secret.txt'"; then
  echo "FAIL: outside write succeeded"; exit 1
fi

echo "PASS: allow works, deny enforced (read + write)"