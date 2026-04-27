#!/usr/bin/env bash
# Stage /keys/*.gz + manifest.json into public/keys for `pnpm preview` (no proxy).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
STAGE_DIR="${WEB_DIR}/public/keys"
RELEASE_BASE="${ZKID_RELEASE_BASE:-https://github.com/zkmopro/zkID/releases/download/latest}"

ASSETS=(
  "cert_chain_rs2048_proving.key"
  "cert_chain_rs4096_proving.key"
  "device_sig_rs2048_proving.key"
  "cert_chain_rs2048.wasm"
  "cert_chain_rs4096.wasm"
  "device_sig_rs2048.wasm"
)

mkdir -p "${STAGE_DIR}"

download() {
  local name="$1"
  local gz="${name}.gz"
  local dst="${STAGE_DIR}/${gz}"
  if [ -f "${dst}" ]; then
    echo "have ${gz} (skip)" >&2
    return
  fi
  echo "fetch ${gz}" >&2
  curl -fL --output "${dst}" "${RELEASE_BASE}/${gz}"
}

for name in "${ASSETS[@]}"; do
  download "${name}"
done

MANIFEST="${STAGE_DIR}/manifest.json"
if curl -fsSL -o "${MANIFEST}" "${RELEASE_BASE}/manifest.json"; then
  echo "fetched manifest.json from Release" >&2
else
  echo "Release has no manifest.json; generating from decompressed hashes" >&2
  python3 - "${STAGE_DIR}" "${MANIFEST}" <<'PY'
import gzip
import hashlib
import json
import os
import sys

stage_dir, out = sys.argv[1], sys.argv[2]
assets = {}
for name in sorted(os.listdir(stage_dir)):
    if not name.endswith(".gz"):
        continue
    with gzip.open(os.path.join(stage_dir, name), "rb") as f:
        assets[name] = {"sha256_decompressed": hashlib.sha256(f.read()).hexdigest()}
with open(out, "w") as f:
    json.dump({"assets": assets}, f, indent=2)
    f.write("\n")
PY
fi

echo "staged at ${STAGE_DIR}" >&2
