#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WEB_DEMO="$(dirname "$SCRIPT_DIR")"
SDK_DIR="$WEB_DEMO/../openac-sdk"
SPARTAN_DIR="$WEB_DEMO/../ecdsa-spartan2-jwt"

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
echo "   ✓ openac_wasm.js → src/wasm/"
echo "   ✓ openac_wasm_bg.wasm → public/"

# 2. Copy circuit WASM files (witness calculators)
#    These are circom-compiled WASM, not the Spartan2 WASM module.
#    Using 1k variant — key sizes must match.
echo ""
echo "2. Copying circuit WASM files (1k variant)..."
cp "$SDK_DIR/assets/jwt.wasm"  "$WEB_DEMO/public/jwt.wasm"
cp "$SDK_DIR/assets/show.wasm" "$WEB_DEMO/public/show.wasm"
echo "   ✓ jwt.wasm → public/"
echo "   ✓ show.wasm → public/"

# 3. Copy and patch witness_calculator.js (CJS → ESM)
#    Vite only does CJS→ESM for node_modules, not src/ files.
echo ""
echo "3. Copying witness_calculator.js (patched to ESM)..."
mkdir -p "$WEB_DEMO/src/assets"
cp "$SDK_DIR/assets/witness_calculator.js" "$WEB_DEMO/src/assets/witness_calculator.js"
# Patch: replace `module.exports = ...` with `export default ...`
sed -i '' 's/module\.exports = async function builder/export default async function builder/' \
  "$WEB_DEMO/src/assets/witness_calculator.js"
echo "   ✓ witness_calculator.js → src/assets/ (ESM patched)"

# 4. Symlink keys directory
echo ""
echo "4. Setting up keys directory..."
if [ -d "$SPARTAN_DIR/keys" ]; then
  rm -rf "$WEB_DEMO/public/keys"
  ln -s "$SPARTAN_DIR/keys" "$WEB_DEMO/public/keys"
  echo "   ✓ keys/ → public/keys (symlink)"
else
  echo "   ⚠ Keys directory not found at $SPARTAN_DIR/keys"
  echo "     Run 'cargo run -- jwt setup' in ecdsa-spartan2-jwt/ first"
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "To verify:"
echo "  ls -la public/openac_wasm_bg.wasm public/jwt.wasm public/show.wasm"
echo "  ls -la src/wasm/openac_wasm.js src/assets/witness_calculator.js"
echo ""
echo "To start:"
echo "  pnpm dev"
