import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  fetchPkcs11Info,
  probePkcs11Info,
  signTbs,
  type Pkcs11InfoResponse,
} from "./hipki-client";

import * as popup from "./hipki-popup";

const TESTDATA = resolve(
  __dirname,
  "../../ecdsa-spartan2/tests/testdata",
);
const PKCS11_FIXTURE_RAW = readFileSync(
  resolve(TESTDATA, "pkcs11info_test.json"),
  "utf8",
);
const SIGN_FIXTURE_RAW = readFileSync(
  resolve(TESTDATA, "response_sign_test.json"),
  "utf8",
);
const PKCS11_FIXTURE = JSON.parse(PKCS11_FIXTURE_RAW) as Record<string, unknown>;
const SIGN_FIXTURE = JSON.parse(SIGN_FIXTURE_RAW) as Record<string, unknown>;

describe("hipki-client", () => {
  beforeEach(() => {
    vi.spyOn(popup, "popupPkcs11Info").mockImplementation(async () =>
      PKCS11_FIXTURE,
    );
    vi.spyOn(popup, "popupSign").mockImplementation(async () => SIGN_FIXTURE);
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("fetchPkcs11Info", () => {
    it("delegates to popupPkcs11Info(true) and parses the response", async () => {
      const resp = await fetchPkcs11Info();
      expect(popup.popupPkcs11Info).toHaveBeenCalledWith(true, undefined);
      expect(resp.slots).toHaveLength(1);
      expect(resp.slots[0].token?.certs).toHaveLength(2);
      const ca = resp.slots[0].token!.certs.find((c) => c.label === "CA Cert");
      expect(ca?.subjectDN).toContain("Test Certificate Authority");
    });

    it("throws when response body has no slots array", async () => {
      vi.spyOn(popup, "popupPkcs11Info").mockResolvedValueOnce({
        foo: "bar",
      });
      await expect(fetchPkcs11Info()).rejects.toThrow(/slots array/);
    });
  });

  describe("probePkcs11Info", () => {
    it("delegates to popupPkcs11Info(false) for lightweight polling", async () => {
      const resp = await probePkcs11Info();
      expect(popup.popupPkcs11Info).toHaveBeenCalledWith(false, undefined);
      expect(Array.isArray(resp.slots)).toBe(true);
    });
  });

  describe("signTbs", () => {
    it("delegates to popupSign with tbs + pin and returns the response", async () => {
      const resp = await signTbs({ tbs: "deadbeef", pin: "123456" });
      expect(popup.popupSign).toHaveBeenCalledWith("deadbeef", "123456", undefined);
      expect(resp.ret_code).toBe(0);
      expect(resp.last_error).toBe(0);
      expect(resp.cardSN).toBe("TEST000000000000");
    });

    it("propagates popup errors without leaking the PIN", async () => {
      const pin = "999999";
      vi.spyOn(popup, "popupSign").mockRejectedValueOnce(
        new Error("HiPKI popup timeout (sign)"),
      );
      let caught: Error | undefined;
      try {
        await signTbs({ tbs: "aa", pin });
      } catch (e) {
        caught = e as Error;
      }
      expect(caught).toBeDefined();
      expect(caught!.message).toMatch(/timeout/);
      expect(caught!.message).not.toContain(pin);
    });
  });

  it("pkcs11info fixture deserializes into the client's declared type", () => {
    const parsed = PKCS11_FIXTURE as unknown as Pkcs11InfoResponse;
    expect(parsed.slots[0].token?.certs.length).toBeGreaterThan(0);
  });
});
