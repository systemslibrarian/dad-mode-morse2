#!/bin/bash
# run10x.sh - Run all test suites 10 times to verify consistency
# Tests: Encryption (50) + Extended (50) + WAV Decode (16) = 116 tests per run
# Includes: AES-256-GCM, Argon2id, HKDF, Signal Key, Ed25519 signing, Morse codec, WAV decode

cd /workspaces/dad-morse2

echo "=============================================="
echo "Dad's Morse v5 - Full Test Suite (10x)"
echo "=============================================="
echo "Tests per run:"
echo "  - Crypto (50 tests):   AES-256-GCM, Argon2id, HKDF, Ed25519, Morse, Base64"
echo "  - Extended (50 tests): Semantic security, stress, edge cases, isolation"
echo "  - WAV Decode (16 tests): Morse synthesis, round-trip, speed variants"
echo ""
echo "Started: $(date)"
echo ""

CRYPTO_PASS=0
CRYPTO_FAIL=0
EXTENDED_PASS=0
EXTENDED_FAIL=0
DECODE_PASS=0
DECODE_FAIL=0

for i in 1 2 3 4 5 6 7 8 9 10; do
  printf "\n=== Run $i/10 ===\n"

  echo "🔐 Encryption tests..."
  CRYPTO_OUT=$(node test_crypto.mjs 2>&1) && CRYPTO_RC=0 || CRYPTO_RC=$?
  echo "$CRYPTO_OUT" | tail -5
  if [ $CRYPTO_RC -eq 0 ]; then
    ((CRYPTO_PASS++))
  else
    ((CRYPTO_FAIL++))
    echo "   ❌ Crypto tests FAILED on run $i"
  fi

  echo "🔒 Extended tests..."
  EXTENDED_OUT=$(node test_extended.mjs 2>&1) && EXTENDED_RC=0 || EXTENDED_RC=$?
  echo "$EXTENDED_OUT" | tail -5
  if [ $EXTENDED_RC -eq 0 ]; then
    ((EXTENDED_PASS++))
  else
    ((EXTENDED_FAIL++))
    echo "   ❌ Extended tests FAILED on run $i"
  fi

  echo "📡 WAV decode tests..."
  DECODE_OUT=$(python3 test_decode.py 2>&1) && DECODE_RC=0 || DECODE_RC=$?
  echo "$DECODE_OUT" | tail -3
  if [ $DECODE_RC -eq 0 ]; then
    ((DECODE_PASS++))
  else
    ((DECODE_FAIL++))
    echo "   ❌ Decode tests FAILED on run $i"
  fi
done

echo ""
echo "=============================================="
echo "SUMMARY"
echo "=============================================="
echo "Crypto tests:   $CRYPTO_PASS/10 passed, $CRYPTO_FAIL failed"
echo "Extended tests: $EXTENDED_PASS/10 passed, $EXTENDED_FAIL failed"
echo "Decode tests:   $DECODE_PASS/10 passed, $DECODE_FAIL failed"
TOTAL_FAIL=$((CRYPTO_FAIL + EXTENDED_FAIL + DECODE_FAIL))
TOTAL_PASS=$((CRYPTO_PASS + EXTENDED_PASS + DECODE_PASS))
echo "Overall:        $TOTAL_PASS/30 suite runs passed"
echo ""

if [ $TOTAL_FAIL -eq 0 ]; then
  echo "✅ ALL 10 RUNS PASSED - All capabilities verified!"
  exit 0
else
  echo "❌ SOME RUNS FAILED"
  exit 1
fi
