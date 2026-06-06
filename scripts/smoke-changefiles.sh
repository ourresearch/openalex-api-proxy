#!/usr/bin/env bash
#
# Post-deploy smoke test for the /changefiles endpoints (zd#8865).
#
# Asserts the contract that unit tests can't reach because it lives in the
# fetch handler + the live Cloudflare edge:
#   - listing is free, keyless, 200, and 0 credits
#   - listing is edge-cached for 1h (MISS then HIT, Cache-Control max-age=3600)
#   - actual downloads stay plan-gated (401 without a key)
#
# Usage:
#   scripts/smoke-changefiles.sh                  # listing checks only
#   API_KEY=xxxxx scripts/smoke-changefiles.sh    # also checks the keyed path
#   BASE=https://api.openalex.org scripts/smoke-changefiles.sh
#
# Exits non-zero on the first failed assertion.

set -uo pipefail

BASE="${BASE:-https://api.openalex.org}"
API_KEY="${API_KEY:-}"
fails=0

# Print PASS/FAIL for a condition.
check() {
  local desc="$1" cond="$2"
  if [ "$cond" = "1" ]; then
    printf '  \033[32mPASS\033[0m  %s\n' "$desc"
  else
    printf '  \033[31mFAIL\033[0m  %s\n' "$desc"
    fails=$((fails + 1))
  fi
}

# hdr <captured-headers> <name> -> the matching header line (case-insensitive)
hdr() { printf '%s\n' "$1" | grep -i "^$2:" | tr -d '\r' | head -1; }
status() { printf '%s\n' "$1" | grep -i '^http/' | head -1; }

echo "== Changefiles smoke test against $BASE =="

# 1. Keyless listing: 200, free, no key required.
echo "[1] Keyless listing (/changefiles)"
H=$(curl -sS -D - -o /dev/null "$BASE/changefiles")
check "returns HTTP 200" "$([[ "$(status "$H")" == *" 200"* ]] && echo 1 || echo 0)"
check "costs 0 credits"  "$(hdr "$H" x-ratelimit-credits-used | grep -q ': 0' && echo 1 || echo 0)"

# 2. Edge cache: a fresh path should MISS then HIT, with a 1h TTL.
echo "[2] Edge cache (1h TTL, MISS -> HIT)"
P="$BASE/changefiles?smoke=$(date +%s)-$$"
H1=$(curl -sS -D - -o /dev/null "$P")
sleep 2
H2=$(curl -sS -D - -o /dev/null "$P")
check "Cache-Control is max-age=3600" "$(hdr "$H2" cache-control | grep -q 'max-age=3600' && echo 1 || echo 0)"
check "second hit is cf-cache-status: HIT" "$(hdr "$H2" cf-cache-status | grep -qi 'hit' && echo 1 || echo 0)"

# 3. Download path stays gated without a key (401).
echo "[3] Download path is plan-gated"
DL="$BASE/changefiles/2026-06-05/works_2026-06-05.jsonl.gz"
H=$(curl -sS -D - -o /dev/null "$DL")
check "unauthenticated download returns 401" "$([[ "$(status "$H")" == *" 401"* ]] && echo 1 || echo 0)"

# 4. Keyed listing (only if API_KEY provided): honored + still 0 credits.
if [ -n "$API_KEY" ]; then
  echo "[4] Keyed listing (valid API key honored)"
  H=$(curl -sS -D - -o /dev/null "$BASE/changefiles" -H "Authorization: Bearer $API_KEY")
  check "returns HTTP 200" "$([[ "$(status "$H")" == *" 200"* ]] && echo 1 || echo 0)"
  check "costs 0 credits"  "$(hdr "$H" x-ratelimit-credits-used | grep -q ': 0' && echo 1 || echo 0)"
else
  echo "[4] Keyed listing: skipped (set API_KEY=... to enable)"
fi

echo
if [ "$fails" -eq 0 ]; then
  printf '\033[32mAll checks passed.\033[0m\n'; exit 0
else
  printf '\033[31m%d check(s) failed.\033[0m\n' "$fails"; exit 1
fi
