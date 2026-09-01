#!/usr/bin/env bash
#
# A scripted run of the whole pipeline against a live server: submit an intent,
# watch it cross the lifecycle to final_proven, read its evidence bundle, and
# watch the gate refuse a replay. Everything here goes over HTTP — nothing
# reaches into the process.
#
# Needs only curl. `make demo`.

set -euo pipefail

PORT="${PORT:-3000}"
BASE="http://127.0.0.1:${PORT}"
SERVER_PID=""

bold() { printf '\n\033[1m%s\033[0m\n' "$1"; }
step() { printf '  %s\n' "$1"; }

cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# `jq` would be neater, but it is not a given on a reviewer's machine and this
# is the only field the script has to pull out of a response.
field() { grep -o "\"$1\":\"[^\"]*\"" | head -1 | cut -d'"' -f4; }

if curl -sf -o /dev/null "$BASE/health" 2>/dev/null; then
  echo "Something is already serving on :$PORT — stop it, or set PORT=xxxx." >&2
  exit 1
fi

bold "Building"
cargo build --quiet
step "ok"

bold "Starting the pipeline on :$PORT"
cargo run --quiet >/tmp/zequencer-demo.log 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 60); do
  curl -sf -o /dev/null "$BASE/health" 2>/dev/null && break
  sleep 0.25
done
curl -sf -o /dev/null "$BASE/health" || {
  echo "server never became healthy; see /tmp/zequencer-demo.log" >&2
  exit 1
}
step "/health -> ok   (sequencer, attester, prover and projector are running as tasks)"

NOW=$(( $(date +%s) * 1000 ))
INTENT=$(cat <<JSON
{"submitter":"aa11111111111111111111111111111111111111","nonce":1,
 "market":{"base":"ETH","quote":"USDC"},"side":"buy",
 "size":1000000000000000000,"max_slippage_bps":50,"priority_fee":7,
 "timestamp_ms":${NOW},"deadline_ms":$(( NOW + 600000 ))}
JSON
)

bold "1. submitIntent — POST /intents"
SUBMIT=$(curl -s -X POST "$BASE/intents" -H 'content-type: application/json' -d "$INTENT")
step "$SUBMIT"
ID=$(printf '%s' "$SUBMIT" | field intent_id)
[ -n "$ID" ] || { echo "submit failed: $SUBMIT" >&2; exit 1; }
step "the id is keccak over the intent's own fields, so a client can recompute it"

bold "2. getStatus — GET /intents/{id}, polled until it settles"
LAST=""
for _ in $(seq 1 80); do
  STATUS=$(curl -s "$BASE/intents/$ID")
  STATE=$(printf '%s' "$STATUS" | field status)
  if [ "$STATE" != "$LAST" ]; then
    step "$STATUS"
    LAST="$STATE"
  fi
  case "$STATE" in final_proven|failed|expired) break ;; esac
  sleep 0.25
done

bold "3. getReceipt — GET /intents/{id}/receipt"
RECEIPT=$(curl -s "$BASE/intents/$ID/receipt")
if command -v python3 >/dev/null 2>&1; then
  printf '%s' "$RECEIPT" | python3 -m json.tool | sed 's/^/  /'
else
  step "$RECEIPT"
fi
step ""
step "sequence   — rank inside the slot's ordering, not a log offset"
step "guarantee  — the window promised at admission, and whether it was met"
step "preconf    — the TEE quote and signature, verifiable without this server"
step "proof      — the slot range the final proof covers"

bold "4. Failure behaviour — the same intent submitted twice"
REPLAY=$(curl -s -w ' (HTTP %{http_code})' -X POST "$BASE/intents" \
  -H 'content-type: application/json' -d "$INTENT")
step "$REPLAY"
step "the reason is a tag, not prose, so a client branches on it"

bold "Done"
step "the failure path is opt-in:  FAIL_SLOTS=200-209 cargo run"
step "server log: /tmp/zequencer-demo.log"
