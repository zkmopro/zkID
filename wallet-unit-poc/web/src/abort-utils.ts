// Small helpers shared by HTTP clients (verifier, SMT) that need to combine
// a caller-supplied AbortSignal with a per-request timeout, and that read
// their timeouts from `VITE_*_TIMEOUT_MS` env vars.

/** Combine a caller's AbortSignal (if any) with a per-request timeout so a
 *  hung server never leaves the UI spinning forever. `AbortSignal.any`
 *  short-circuits as soon as either source aborts. */
export function composeSignal(
  caller: AbortSignal | undefined,
  timeoutMs: number,
): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  return caller ? AbortSignal.any([caller, timeout]) : timeout;
}

/** Parse a `VITE_*` env var into a positive integer, falling back when the
 *  value is missing, non-numeric, or non-positive. Vite injects unset env
 *  vars as `undefined`, so the `unknown` parameter type matches reality. */
export function parsePositiveInt(raw: unknown, fallback: number): number {
  if (typeof raw !== "string") return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}
