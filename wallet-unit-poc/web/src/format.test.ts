import { describe, expect, it } from "vitest";
import { truncateMiddle } from "./format";

describe("truncateMiddle", () => {
  it("returns placeholder when value is undefined", () => {
    expect(truncateMiddle(undefined, 10, 6)).toBe("—");
  });

  it("returns placeholder when value is null", () => {
    expect(truncateMiddle(null, 10, 6)).toBe("—");
  });

  it("returns the input untouched when short enough", () => {
    expect(truncateMiddle("0xabcdef", 10, 6)).toBe("0xabcdef");
  });

  it("ellipsises the middle when longer than head + tail", () => {
    const out = truncateMiddle("0xdeadbeefcafebabe1234567890", 6, 4);
    expect(out).toBe("0xdead…7890");
  });
});
