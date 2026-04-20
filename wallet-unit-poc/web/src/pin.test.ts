import { describe, expect, it } from "vitest";

import { Pin } from "./pin";

describe("Pin", () => {
  it("consume() returns the value exactly once", () => {
    const p = new Pin("123456");
    expect(p.consume()).toBe("123456");
    expect(() => p.consume()).toThrow(/already consumed/);
  });

  it("consumed flag flips after consume()", () => {
    const p = new Pin("123456");
    expect(p.consumed).toBe(false);
    p.consume();
    expect(p.consumed).toBe(true);
  });

  it("toString never reveals the value", () => {
    const p = new Pin("secret-pin-999999");
    expect(p.toString()).toBe("[REDACTED]");
    expect(`${p}`).toBe("[REDACTED]");
    expect(String(p)).toBe("[REDACTED]");
  });

  it("JSON.stringify never reveals the value", () => {
    const p = new Pin("secret-pin-999999");
    expect(JSON.stringify(p)).toBe('"[REDACTED]"');
    expect(JSON.stringify({ pin: p, other: 1 })).toBe(
      '{"pin":"[REDACTED]","other":1}',
    );
  });

  it("template literal coercion never reveals the value", () => {
    const p = new Pin("secret-pin-999999");
    const msg = `pin=${p}`;
    expect(msg).toBe("pin=[REDACTED]");
    expect(msg).not.toContain("secret-pin-999999");
  });

  it("valueOf / Symbol.toPrimitive never reveals the value", () => {
    const p = new Pin("secret-pin-999999");
    // + "x" triggers Symbol.toPrimitive with hint "default"
    expect(p + "x").toBe("[REDACTED]x");
    expect(p.valueOf()).toBe("[REDACTED]");
  });
});
