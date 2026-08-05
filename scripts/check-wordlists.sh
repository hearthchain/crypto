#!/usr/bin/env bash
# Guard against drift between the BIP-39 English wordlist copies embedded by each
# implementation. Every copy must equal the official file's SHA-256. The wordlist
# is frozen by the BIP-39 standard, so any mismatch means a corrupted/edited copy.
#
# Five implementations, five copies (see FILES below).
#
# Run from the repo root:  scripts/check-wordlists.sh
set -euo pipefail

OFFICIAL="2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

FILES=(
  "java/src/main/resources/bip39/english.txt"
  "python/src/hearth/data/english.txt"
  "go/hearth/english.txt"
  "rust/src/english.txt"
  "typescript/src/english.txt"
)

hash_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

status=0
for f in "${FILES[@]}"; do
  if [ ! -f "$f" ]; then
    echo "MISSING  $f"
    status=1
    continue
  fi
  sum="$(hash_of "$f")"
  if [ "$sum" = "$OFFICIAL" ]; then
    echo "ok       $f"
  else
    echo "DRIFT    $f"
    echo "         got  $sum"
    echo "         want $OFFICIAL"
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo "wordlist drift detected" >&2
fi
exit "$status"
