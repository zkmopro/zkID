#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WEB_DEMO="$(dirname "$SCRIPT_DIR")"
SDK_DIR="$WEB_DEMO/../openac-sdk"
SPARTAN_DIR="$WEB_DEMO/../ecdsa-spartan2"

echo "=== zkID Web Demo (WASM) — Asset Setup ==="
echo ""

# 1. Copy WASM module files
#    Vite bundles the JS glue from src/wasm/, serves the .wasm binary from public/
echo "1. Copying WASM module..."
mkdir -p "$WEB_DEMO/src/wasm"
cp "$SDK_DIR/wasm/pkg/openac_wasm.js"      "$WEB_DEMO/src/wasm/"
cp "$SDK_DIR/wasm/pkg/openac_wasm.d.ts"    "$WEB_DEMO/src/wasm/"
cp "$SDK_DIR/wasm/pkg/openac_wasm_bg.wasm.d.ts" "$WEB_DEMO/src/wasm/" 2>/dev/null || true
cp "$SDK_DIR/wasm/pkg/openac_wasm_bg.wasm" "$WEB_DEMO/public/"
# package.json needed for workerHelpers.js import('../../..') resolution
echo '{"type":"module","main":"openac_wasm.js","sideEffects":["./snippets/*"]}' > "$WEB_DEMO/src/wasm/package.json"
if [ -d "$SDK_DIR/wasm/pkg/snippets" ]; then
  cp -r "$SDK_DIR/wasm/pkg/snippets" "$WEB_DEMO/src/wasm/"
  echo "   ✓ snippets/ → src/wasm/snippets/"
fi
echo "   ✓ openac_wasm.js → src/wasm/"
echo "   ✓ openac_wasm_bg.wasm → public/"

# 2. Copy and patch witness_calculator.js (CJS → ESM)
#    Vite only does CJS→ESM for node_modules, not src/ files.
echo ""
echo "2. Copying witness_calculator.js (patched to ESM)..."
mkdir -p "$WEB_DEMO/src/assets"
cp "$SDK_DIR/assets/witness_calculator.js" "$WEB_DEMO/src/assets/witness_calculator.js"
# Patch: replace `module.exports = ...` with `export default ...`
sed -i '' 's/module\.exports = async function builder/export default async function builder/' \
  "$WEB_DEMO/src/assets/witness_calculator.js"
echo "   ✓ witness_calculator.js → src/assets/ (ESM patched)"

# 3. Set up keys directory (optional — keys are generated at runtime in the browser)
echo ""
echo "3. Checking for local keys..."
if [ -d "$SPARTAN_DIR/keys" ]; then
  rm -rf "$WEB_DEMO/public/keys"
  ln -s "$SPARTAN_DIR/keys" "$WEB_DEMO/public/keys"
  echo "   ✓ keys/ → public/keys (symlink, for local dev)"
else
  echo "   ℹ No local keys found. Keys will be generated at runtime via setup_rs256() in the browser."
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "To verify:"
echo "  ls -la public/openac_wasm_bg.wasm"
echo "  ls -la src/wasm/openac_wasm.js src/assets/witness_calculator.js"
echo ""
echo "To start:"
echo "  pnpm dev"
