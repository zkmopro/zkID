import { describe, expect, it, vi } from "vitest";

import { probeHipki } from "./hipki-detector";
import { setupFetchMock } from "./test-utils";

const HIPKI = "http://localhost:61161";

describe("probeHipki", () => {
  setupFetchMock({ VITE_HIPKI_BASE_URL: HIPKI });

  it("returns `not_installed` when /pkcs11info is unreachable", async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    }) as typeof fetch;
    const probe = await probeHipki();
    expect(probe.status).toBe("not_installed");
  });

  it("returns `not_installed` on non-2xx response", async () => {
    globalThis.fetch = vi.fn(
      async () => new Response("", { status: 500 }),
    ) as typeof fetch;
    const probe = await probeHipki();
    expect(probe.status).toBe("not_installed");
  });

  it("returns `no_reader` when response has zero slots", async () => {
    globalThis.fetch = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ serverVersion: "1.0.11", slots: [] }),
          { status: 200 },
        ),
    ) as typeof fetch;
    const probe = await probeHipki();
    expect(probe.status).toBe("no_reader");
    if (probe.status === "no_reader") {
      expect(probe.serverVersion).toBe("1.0.11");
    }
  });

  it("returns `no_reader_or_card` when a slot exists but has no token", async () => {
    globalThis.fetch = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            serverVersion: "1.0.11",
            slots: [{ slotDescription: "Test Reader 0" }],
          }),
          { status: 200 },
        ),
    ) as typeof fetch;
    const probe = await probeHipki();
    expect(probe.status).toBe("no_reader_or_card");
    if (probe.status === "no_reader_or_card") {
      expect(probe.slots).toEqual(["Test Reader 0"]);
    }
  });

  it("returns `card_inserted` with serial + slot when token is present", async () => {
    globalThis.fetch = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            serverVersion: "1.0.11",
            slots: [
              {
                slotDescription: "Reader A",
                token: { serialNumber: "ABC123", certs: [] },
              },
            ],
          }),
          { status: 200 },
        ),
    ) as typeof fetch;
    const probe = await probeHipki();
    expect(probe.status).toBe("card_inserted");
    if (probe.status === "card_inserted") {
      expect(probe.cardSN).toBe("ABC123");
      expect(probe.slotDescription).toBe("Reader A");
    }
  });

  it("picks the slot with a token even if an earlier slot is empty", async () => {
    globalThis.fetch = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            slots: [
              { slotDescription: "Empty Reader" },
              {
                slotDescription: "Real Reader",
                token: { serialNumber: "SN42", certs: [] },
              },
            ],
          }),
          { status: 200 },
        ),
    ) as typeof fetch;
    const probe = await probeHipki();
    expect(probe.status).toBe("card_inserted");
    if (probe.status === "card_inserted") {
      expect(probe.cardSN).toBe("SN42");
      expect(probe.slotDescription).toBe("Real Reader");
    }
  });
});
