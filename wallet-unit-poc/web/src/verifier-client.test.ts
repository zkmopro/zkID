import { describe, expect, it, vi } from "vitest";

import { setupFetchMock } from "./test-utils";
import { createChallenge, submitLinkVerify } from "./verifier-client";

const VERIFIER = "http://localhost:8080";

describe("verifier-client", () => {
  setupFetchMock({ VITE_VERIFIER_BASE_URL: VERIFIER });

  it("POSTs /challenge and returns the parsed body", async () => {
    const payload = {
      challenge_id: "abc",
      challenge_bytes: "AAAA",
      expires_at: "2026-04-20T12:00:00Z",
    };
    const fetchSpy = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      expect(String(url)).toMatch(/\/challenge$/);
      expect(init?.method).toBe("POST");
      return new Response(JSON.stringify(payload), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;
    globalThis.fetch = fetchSpy;

    await expect(createChallenge()).resolves.toEqual(payload);
  });

  it("throws on non-2xx /challenge response", async () => {
    globalThis.fetch = vi.fn(
      async () => new Response("", { status: 503, statusText: "Unavailable" }),
    ) as typeof fetch;
    await expect(createChallenge()).rejects.toThrow(/503/);
  });

  it("throws when /challenge response is missing challenge_id or challenge_bytes", async () => {
    globalThis.fetch = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ id: "abc", bytes: "AA", expires_at: "x" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    ) as typeof fetch;
    await expect(createChallenge()).rejects.toThrow(/unexpected response shape/);
  });

  it("base64-encodes proofs and POSTs to /link-verify", async () => {
    const certProof = new Uint8Array([1, 2, 3, 4]);
    const deviceProof = new Uint8Array([9, 9, 9, 9, 9]);
    const fetchSpy = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      expect(String(url)).toMatch(/\/link-verify$/);
      expect(init?.method).toBe("POST");
      const body = JSON.parse(String(init?.body));
      expect(body.cert_chain_type).toBe("rs2048");
      expect(body.challenge_id).toBe("ch-1");
      expect(body.nullifier).toBe("null-1");
      // Base64 of [1,2,3,4] = "AQIDBA=="; of [9,9,9,9,9] = "CQkJCQk="
      expect(body.cert_chain_proof).toBe("AQIDBA==");
      expect(body.device_sig_proof).toBe("CQkJCQk=");
      return new Response(
        JSON.stringify({
          verified: true,
          nullifier: "null-1",
          id_verified: true,
          persisted: true,
        }),
        { status: 200 },
      );
    }) as typeof fetch;
    globalThis.fetch = fetchSpy;

    const res = await submitLinkVerify({
      challengeId: "ch-1",
      certChainType: "rs2048",
      certChainProofBytes: certProof,
      deviceSigProofBytes: deviceProof,
      nullifier: "null-1",
    });
    expect(res).toEqual({
      verified: true,
      nullifier: "null-1",
      id_verified: true,
      persisted: true,
    });
  });

  it("refuses to submit a proof that exceeds the raw cap", async () => {
    // 701 KB — one byte over the 700 KB cap.
    const huge = new Uint8Array(700 * 1024 + 1);
    const small = new Uint8Array([1]);
    globalThis.fetch = vi.fn(async () => new Response("{}", { status: 200 })) as typeof fetch;
    await expect(
      submitLinkVerify({
        challengeId: "ch",
        certChainType: "rs2048",
        certChainProofBytes: huge,
        deviceSigProofBytes: small,
        nullifier: "n",
      }),
    ).rejects.toThrow(/raw cap/);
  });

  it("surfaces server error body on non-2xx /link-verify", async () => {
    globalThis.fetch = vi.fn(
      async () => new Response("invalid cert_chain_type", { status: 400 }),
    ) as typeof fetch;
    await expect(
      submitLinkVerify({
        challengeId: "ch",
        certChainType: "rs2048",
        certChainProofBytes: new Uint8Array([1]),
        deviceSigProofBytes: new Uint8Array([1]),
        nullifier: "n",
      }),
    ).rejects.toThrow(/invalid cert_chain_type/);
  });
});
