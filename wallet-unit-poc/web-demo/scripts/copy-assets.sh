#!/bin/bash
# Copy circuit assets from the circom build directory to the web-demo public assets
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WEB_DEMO_DIR="$(dirname "$SCRIPT_DIR")"
CIRCOM_DIR="$WEB_DEMO_DIR/../circom"
ASSETS_DIR="$WEB_DEMO_DIR/public/assets"

mkdir -p "$ASSETS_DIR"

# Copy circom witness calculator WASM (11MB)
if [ -f "$CIRCOM_DIR/build/rs256/rs256_js/rs256.wasm" ]; then
  cp "$CIRCOM_DIR/build/rs256/rs256_js/rs256.wasm" "$ASSETS_DIR/rs256.wasm"
  echo "Copied rs256.wasm ($(du -h "$ASSETS_DIR/rs256.wasm" | cut -f1))"
else
  echo "WARNING: rs256.wasm not found at $CIRCOM_DIR/build/rs256/rs256_js/rs256.wasm"
  echo "Run circom compilation first: cd ../circom && npx circomkit compile rs256"
fi

# Copy witness calculator JS
if [ -f "$CIRCOM_DIR/build/rs256/rs256_js/witness_calculator.js" ]; then
  cp "$CIRCOM_DIR/build/rs256/rs256_js/witness_calculator.js" "$ASSETS_DIR/witness_calculator.js"
  echo "Copied witness_calculator.js"
fi

# Copy test input JSON
if [ -f "$CIRCOM_DIR/inputs/rs256/input.json" ]; then
  cp "$CIRCOM_DIR/inputs/rs256/input.json" "$ASSETS_DIR/rs256-input.json"
  echo "Copied rs256-input.json ($(du -h "$ASSETS_DIR/rs256-input.json" | cut -f1))"
fi

echo "Assets ready."
