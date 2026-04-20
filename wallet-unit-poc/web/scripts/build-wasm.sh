#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WASM_DIR="${SCRIPT_DIR}/../../spartan2-wasm"

cd "${WASM_DIR}"
cargo +nightly build --target wasm32-unknown-unknown --release -Z build-std=panic_abort,std
wasm-bindgen --target web --out-dir pkg \
  target/wasm32-unknown-unknown/release/spartan2_wasm.wasm
echo "WASM build complete: ${WASM_DIR}/pkg/"
