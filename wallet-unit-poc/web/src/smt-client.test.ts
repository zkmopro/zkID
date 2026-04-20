import { describe, expect, it, vi } from "vitest";

import {
  convertSmtProofToCircuitInputs,
  fetchSmtProof,
  SMT_DEPTH,
  type SmtProofResponse,
} from "./smt-client";
import { setupFetchMock } from "./test-utils";

const SMT = "http://localhost:3000";

describe("smt-client", () => {
  setupFetchMock({ VITE_SMT_BASE_URL: SMT, VITE_SMT_ISSUER: "g2" });

  describe("convertSmtProofToCircuitInputs", () => {
    it("converts 0x-prefixed hex to decimal across every field", () => {
      const resp: SmtProofResponse = {
        root: "0x2a", // 42
        entry: ["0x270f"], // 9999
        matchingEntry: ["0x7", "0xb"], // 7, 11
        siblings: ["0x64", "0x65", "0xff"], // 100, 101, 255
      };
      const out = convertSmtProofToCircuitInputs(resp);
      expect(out.smt_root).toBe("42");
      expect(out.serial_number).toBe("9999");
      expect(out.smt_old_key).toBe("7");
      expect(out.smt_old_value).toBe("11");
      expect(out.smt_is_old0).toBe("0");
      expect(out.smt_siblings.slice(0, 3)).toEqual(["100", "101", "255"]);
      expect(out.smt_siblings).toHaveLength(SMT_DEPTH);
      expect(out.smt_siblings.slice(3).every((s) => s === "0")).toBe(true);
    });

    it("passes through values that are already decimal", () => {
      const resp: SmtProofResponse = {
        root: "42",
        entry: ["9999"],
        siblings: ["100", "101"],
      };
      const out = convertSmtProofToCircuitInputs(resp);
      expect(out.smt_root).toBe("42");
      expect(out.serial_number).toBe("9999");
      expect(out.smt_siblings[0]).toBe("100");
    });

    it("pads siblings to SMT_DEPTH with zeros", () => {
      const resp: SmtProofResponse = {
        root: "0x1",
        entry: ["0x2"],
        siblings: ["0x3"],
      };
      const out = convertSmtProofToCircuitInputs(resp);
      expect(out.smt_siblings).toHaveLength(SMT_DEPTH);
      expect(out.smt_siblings[0]).toBe("3");
      expect(out.smt_siblings[127]).toBe("0");
    });

    it("truncates siblings longer than depth", () => {
      // Use plain decimal strings so assertions are readable; pass-through
      // preserves them unchanged.
      const siblings = Array.from({ length: SMT_DEPTH + 5 }, (_, i) =>
        String(i + 1),
      );
      const resp: SmtProofResponse = {
        root: "0x1",
        entry: ["0x2"],
        siblings,
      };
      const out = convertSmtProofToCircuitInputs(resp);
      expect(out.smt_siblings).toHaveLength(SMT_DEPTH);
      expect(out.smt_siblings[0]).toBe("1");
      expect(out.smt_siblings[SMT_DEPTH - 1]).toBe(String(SMT_DEPTH));
    });

    it("sets smt_is_old0=1 when matchingEntry is absent", () => {
      const resp: SmtProofResponse = {
        root: "0x1",
        entry: ["0x2"],
        siblings: [],
      };
      const out = convertSmtProofToCircuitInputs(resp);
      expect(out.smt_old_key).toBe("0");
      expect(out.smt_old_value).toBe("0");
      expect(out.smt_is_old0).toBe("1");
    });

    it("sets smt_is_old0=1 when matchingEntry has < 2 elements", () => {
      const resp: SmtProofResponse = {
        root: "0x1",
        entry: ["0x2"],
        matchingEntry: ["0x7"],
        siblings: [],
      };
      const out = convertSmtProofToCircuitInputs(resp);
      expect(out.smt_is_old0).toBe("1");
    });

    it("accepts a custom depth", () => {
      const resp: SmtProofResponse = {
        root: "0x1",
        entry: ["0x2"],
        siblings: [],
      };
      const out = convertSmtProofToCircuitInputs(resp, 8);
      expect(out.smt_siblings).toHaveLength(8);
    });

    it("throws on empty entry array", () => {
      const resp = { root: "0x1", entry: [], siblings: [] } as SmtProofResponse;
      expect(() => convertSmtProofToCircuitInputs(resp)).toThrow(/empty entry/);
    });

    it("throws when siblings is missing", () => {
      const resp = {
        root: "0x1",
        entry: ["0x2"],
      } as unknown as SmtProofResponse;
      expect(() => convertSmtProofToCircuitInputs(resp)).toThrow(/siblings/);
    });
  });

  describe("fetchSmtProof", () => {
    it("GETs /proof/{issuer}/{serialHex} and returns circuit inputs", async () => {
      const fetchSpy = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
        expect(String(url)).toBe(`${SMT}/proof/g2/0xdeadbeef`);
        expect(init?.method ?? "GET").toBe("GET");
        const body: SmtProofResponse = {
          root: "0x2a",
          entry: ["0x270f"],
          matchingEntry: ["0x7", "0xb"],
          siblings: ["0x64"],
        };
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }) as typeof fetch;
      globalThis.fetch = fetchSpy;

      const out = await fetchSmtProof({ serialHex: "0xdeadbeef" });
      expect(out.smt_root).toBe("42");
      expect(out.serial_number).toBe("9999");
      expect(out.smt_siblings).toHaveLength(SMT_DEPTH);
    });

    it("uses the configured issuer env var by default (g2)", async () => {
      globalThis.fetch = vi.fn(async (url: RequestInfo | URL) => {
        expect(String(url)).toContain("/proof/g2/");
        return new Response(
          JSON.stringify({ root: "0x1", entry: ["0x2"], siblings: [] }),
          { status: 200 },
        );
      }) as typeof fetch;
      await fetchSmtProof({ serialHex: "0x2" });
    });

    it("accepts an explicit issuer override (g3 for RSA-4096)", async () => {
      globalThis.fetch = vi.fn(async (url: RequestInfo | URL) => {
        expect(String(url)).toContain("/proof/g3/");
        return new Response(
          JSON.stringify({ root: "0x1", entry: ["0x2"], siblings: [] }),
          { status: 200 },
        );
      }) as typeof fetch;
      await fetchSmtProof({ issuer: "g3", serialHex: "0x2" });
    });

    it("URL-encodes path segments so odd issuer / serial strings don't break", async () => {
      globalThis.fetch = vi.fn(async (url: RequestInfo | URL) => {
        // A slash in the serial should be percent-encoded, not treated as a segment.
        expect(String(url)).toContain("/proof/g2/ab%2Fcd");
        return new Response(
          JSON.stringify({ root: "0x1", entry: ["0x2"], siblings: [] }),
          { status: 200 },
        );
      }) as typeof fetch;
      await fetchSmtProof({ serialHex: "ab/cd" });
    });

    it("throws on non-2xx response", async () => {
      globalThis.fetch = vi.fn(
        async () => new Response("", { status: 404, statusText: "Not Found" }),
      ) as typeof fetch;
      await expect(fetchSmtProof({ serialHex: "0x1" })).rejects.toThrow(/404/);
    });
  });
});
