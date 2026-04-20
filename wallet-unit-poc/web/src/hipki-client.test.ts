import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";

import {
  fetchPkcs11Info,
  signTbs,
  type Pkcs11InfoResponse,
} from "./hipki-client";
import { setupFetchMock } from "./test-utils";

const HIPKI = "http://localhost:61161";
const TESTDATA = resolve(
  __dirname,
  "../../ecdsa-spartan2/tests/testdata",
);
const PKCS11_FIXTURE = readFileSync(
  resolve(TESTDATA, "pkcs11info_test.json"),
  "utf8",
);
const SIGN_FIXTURE = readFileSync(
  resolve(TESTDATA, "response_sign_test.json"),
  "utf8",
);

describe("hipki-client", () => {
  setupFetchMock({ VITE_HIPKI_BASE_URL: HIPKI });

  describe("fetchPkcs11Info", () => {
    it("GETs /pkcs11info?withcert=true and parses the response", async () => {
      const fetchSpy = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
        expect(String(url)).toBe(`${HIPKI}/pkcs11info?withcert=true`);
        expect(init?.method ?? "GET").toBe("GET");
        return new Response(PKCS11_FIXTURE, {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }) as typeof fetch;
      globalThis.fetch = fetchSpy;

      const resp = await fetchPkcs11Info();
      expect(resp.slots).toHaveLength(1);
      expect(resp.slots[0].token?.certs).toHaveLength(2);
      const ca = resp.slots[0].token!.certs.find((c) => c.label === "CA Cert");
      expect(ca?.subjectDN).toContain("Test Certificate Authority");
    });

    it("strips a trailing slash from baseUrl", async () => {
      const fetchSpy = vi.fn(async (url: RequestInfo | URL) => {
        expect(String(url)).toBe(`${HIPKI}/pkcs11info?withcert=true`);
        return new Response(PKCS11_FIXTURE, { status: 200 });
      }) as typeof fetch;
      globalThis.fetch = fetchSpy;
      await fetchPkcs11Info(`${HIPKI}/`);
    });

    it("throws on non-2xx response", async () => {
      globalThis.fetch = vi.fn(
        async () =>
          new Response("", { status: 502, statusText: "Bad Gateway" }),
      ) as typeof fetch;
      await expect(fetchPkcs11Info()).rejects.toThrow(/502/);
    });

    it("throws when response body has no slots array", async () => {
      globalThis.fetch = vi.fn(
        async () => new Response(JSON.stringify({ foo: "bar" }), { status: 200 }),
      ) as typeof fetch;
      await expect(fetchPkcs11Info()).rejects.toThrow(/slots array/);
    });

    it("accepts an explicit baseUrl override", async () => {
      const custom = "http://127.0.0.1:9999";
      const fetchSpy = vi.fn(async (url: RequestInfo | URL) => {
        expect(String(url)).toBe(`${custom}/pkcs11info?withcert=true`);
        return new Response(PKCS11_FIXTURE, { status: 200 });
      }) as typeof fetch;
      globalThis.fetch = fetchSpy;
      await fetchPkcs11Info(custom);
    });
  });

  describe("signTbs", () => {
    it("POSTs form-encoded tbsPackage with PKCS1 signatureType", async () => {
      const fetchSpy = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
        expect(String(url)).toBe(`${HIPKI}/sign`);
        expect(init?.method).toBe("POST");
        expect(new Headers(init?.headers).get("Content-Type")).toBe(
          "application/x-www-form-urlencoded",
        );
        const params = new URLSearchParams(String(init?.body));
        const pkg = JSON.parse(params.get("tbsPackage")!);
        expect(pkg).toEqual({
          tbs: "deadbeef",
          pin: "123456",
          hashAlgorithm: "SHA256",
          signatureType: "PKCS1",
        });
        return new Response(SIGN_FIXTURE, {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }) as typeof fetch;
      globalThis.fetch = fetchSpy;

      const resp = await signTbs({ tbs: "deadbeef", pin: "123456" });
      expect(resp.ret_code).toBe(0);
      expect(resp.last_error).toBe(0);
      expect(resp.cardSN).toBe("TEST000000000000");
      expect(typeof resp.signature).toBe("string");
      expect(typeof resp.certb64).toBe("string");
    });

    it("throws on non-2xx response without echoing the PIN", async () => {
      const pin = "999999";
      globalThis.fetch = vi.fn(
        async () => new Response("", { status: 401, statusText: "Unauthorized" }),
      ) as typeof fetch;
      let caught: Error | undefined;
      try {
        await signTbs({ tbs: "aa", pin });
      } catch (e) {
        caught = e as Error;
      }
      expect(caught).toBeDefined();
      expect(caught!.message).toMatch(/401/);
      expect(caught!.message).not.toContain(pin);
    });

    it("uses the supplied baseUrl when provided", async () => {
      const custom = "http://127.0.0.1:61162";
      const fetchSpy = vi.fn(async (url: RequestInfo | URL) => {
        expect(String(url)).toBe(`${custom}/sign`);
        return new Response(SIGN_FIXTURE, { status: 200 });
      }) as typeof fetch;
      globalThis.fetch = fetchSpy;
      await signTbs({ tbs: "aa", pin: "000000", baseUrl: custom });
    });
  });

  // Sanity-check that the fixture is structurally valid at import time —
  // catches checked-in fixture drift without waiting for a live-card test.
  it("pkcs11info fixture deserializes into the client's declared type", () => {
    const parsed = JSON.parse(PKCS11_FIXTURE) as Pkcs11InfoResponse;
    expect(parsed.slots[0].token?.certs.length).toBeGreaterThan(0);
  });
});
