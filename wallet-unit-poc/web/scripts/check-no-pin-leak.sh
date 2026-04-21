#!/usr/bin/env bash
# Static check: no `console.*` call may take a `pin` / `Pin` reference, and
# no template literal may interpolate one. The Pin class redacts via
# toString/toJSON/valueOf/Symbol.toPrimitive, so an interpolation prints
# "[REDACTED]" rather than the digits — but a developer typing
# `console.log(rawPinString)` directly bypasses every guard. This script
# catches that pattern in CI before it ships.
#
# False positives are tolerated by the rules below; if you trip one, prefer
# renaming the variable over editing the regex.
#
# Exit non-zero on hits so CI / pre-commit hooks block the change.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="${SCRIPT_DIR}/.."
SRC_DIR="${WEB_DIR}/src"
E2E_DIR="${WEB_DIR}/e2e"

if [ ! -d "${SRC_DIR}" ]; then
  echo "check-no-pin-leak: src dir not found at ${SRC_DIR}" >&2
  exit 1
fi

# `console.<method>(...)` calls referencing pin / Pin in the argument list.
# Match `pin` or `Pin` as a whole token (word boundary or property access).
PATTERN_CONSOLE='console\.(log|info|warn|error|debug|trace)\([^)]*\b[Pp]in\b'

# Template literals that interpolate `pin` / `Pin` / camelCase like rawPin.
# Pin's toString returns "[REDACTED]" so this is defense in depth in case
# someone subclasses Pin or assigns the raw string into a same-named slot.
PATTERN_TEMPLATE='\$\{[^}]*\b(raw|user|input|candidate)?[Pp]in\b[^}]*\}'

hits=0

scan() {
  local label="$1"
  local pattern="$2"
  local dir="$3"
  if [ ! -d "${dir}" ]; then return; fi
  local matches
  if matches=$(grep -RInE \
      --include='*.ts' --include='*.tsx' --include='*.js' \
      --exclude='pin.ts' \
      --exclude='pin.test.ts' \
      --exclude='check-no-pin-leak.sh' \
      "${pattern}" "${dir}" 2>/dev/null); then
    echo "PIN LEAK SUSPECTED (${label}):"
    echo "${matches}"
    hits=$((hits + 1))
  fi
}

scan "console-pin"   "${PATTERN_CONSOLE}"  "${SRC_DIR}"
scan "console-pin"   "${PATTERN_CONSOLE}"  "${E2E_DIR}"
scan "template-pin"  "${PATTERN_TEMPLATE}" "${SRC_DIR}"
scan "template-pin"  "${PATTERN_TEMPLATE}" "${E2E_DIR}"

if [ "${hits}" -gt 0 ]; then
  echo ""
  echo "check-no-pin-leak: found ${hits} suspect pattern(s). Either rename" >&2
  echo "the variable or, if intentional, exclude its file in scripts/check-no-pin-leak.sh." >&2
  exit 1
fi

echo "check-no-pin-leak: clean."
