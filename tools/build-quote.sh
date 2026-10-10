#!/usr/bin/env bash
# Re-encrypt the sales quote builder from plaintext source kept OUTSIDE the repo, then commit + push.
# Usage: COTHE_SALES_PASSWORD must be set. Optional: SRC=/path (default /workspace/cothe-quote-src), NO_PUSH=1.
# Source files: builder.html, builder.css, tax-data.js, quote.js (edit prices in quote.js).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${SRC:-/workspace/cothe-quote-src}"
[ -n "${COTHE_SALES_PASSWORD:-}" ] || { echo "COTHE_SALES_PASSWORD not set" >&2; exit 1; }
for f in builder.html builder.css tax-data.js quote.js; do [ -f "$SRC/$f" ] || { echo "missing $SRC/$f" >&2; exit 1; }; done
node "$REPO/tools/encrypt-quote.mjs" "$SRC" "$REPO/quote/quote.enc.json"
cd "$REPO"
git add quote/quote.enc.json
if git diff --cached --quiet; then echo "nothing to commit"; exit 0; fi
git commit -q -m "Re-encrypt sales quote builder"
[ -n "${NO_PUSH:-}" ] || git push -q
echo "done"
