// PIN wrapper. Every observable surface (`toString`, `toJSON`, `valueOf`,
// `Symbol.toPrimitive`, Node's util.inspect) returns `"[REDACTED]"` so a
// stray `${pin}` or `console.log(pin)` can't leak the digits.
//
// Two read paths match two call sites:
//   - `consume()`  — single-use sink for the PIN-verify scratch wrapper in
//                    setup.ts. Throws on reuse so an errant re-verify can't
//                    silently re-sign without the user clicking Verify.
//   - `read()`     — multi-use read for the session-locked Pin held in the
//                    `$pin` atom. Proving reuses the same Pin across retries
//                    ("Prove again" / "Retry proving") without requiring the
//                    user to re-type. Call `destroy()` on session teardown
//                    to null the internal slot explicitly.
//
// Taiwan Citizen Card locks after three wrong PIN attempts; retry accounting
// is at the UI layer, not here.

const REDACTED = "[REDACTED]";

export class Pin {
  #value: string | null;

  constructor(value: string) {
    this.#value = value;
  }

  /** Single-use read: returns the value, then clears the slot. */
  consume(): string {
    if (this.#value === null) {
      throw new Error("Pin.consume(): already consumed");
    }
    const v = this.#value;
    this.#value = null;
    return v;
  }

  /** Multi-use read. Does NOT clear the slot — the session-locked Pin is
   *  reused across retry proving runs. Call `destroy()` on teardown. */
  read(): string {
    if (this.#value === null) {
      throw new Error("Pin.read(): already destroyed");
    }
    return this.#value;
  }

  /** Explicit teardown. Idempotent; subsequent read/consume throws. */
  destroy(): void {
    this.#value = null;
  }

  /** True after `consume()` or `destroy()` has been called. */
  get consumed(): boolean {
    return this.#value === null;
  }

  toString(): string {
    return REDACTED;
  }
  toJSON(): string {
    return REDACTED;
  }
  valueOf(): string {
    return REDACTED;
  }
  [Symbol.toPrimitive](): string {
    return REDACTED;
  }
}
