// Single-use PIN wrapper. `consume()` returns the value and clears the
// internal store — the object is dead after one read. Every observable
// surface (`toString`, `toJSON`, `valueOf`, `Symbol.toPrimitive`,
// Node's util.inspect) returns `"[REDACTED]"` so a stray `${pin}` or
// `console.log(pin)` can't leak the digits.
//
// One Pin per sign request. After a proving run consumes the session Pin,
// a fresh Verify is required before the next run — the FSM routes Retry
// proving / Prove again through setup so the user re-enters the PIN.
// Taiwan Citizen Card locks after three wrong attempts; retry accounting
// is at the UI layer, not here.

const REDACTED = "[REDACTED]";

export class Pin {
  #value: string | null;

  constructor(value: string) {
    this.#value = value;
  }

  /** Returns the raw PIN once, then clears the internal slot. Throws on reuse. */
  consume(): string {
    if (this.#value === null) {
      throw new Error("Pin.consume(): already consumed");
    }
    const v = this.#value;
    this.#value = null;
    return v;
  }

  /** True after `consume()` has been called. Does not reveal the value. */
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
