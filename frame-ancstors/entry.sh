#!/usr/bin/env bash
set -euo pipefail

echo "Fetching frame-ancestors allowlist from Azure App Configuration..."

FRAME_ANCESTORS=$(node fetch-config.js)

if [ -z "$FRAME_ANCESTORS" ]; then
  echo "WARNING: frame-ancestors value empty, falling back to 'self'"
  FRAME_ANCESTORS="'self'"
fi

export CSP_FRAME_ANCESTORS="$FRAME_ANCESTORS"
echo "frame-ancestors set to: $CSP_FRAME_ANCESTORS"

exec node server.cjs