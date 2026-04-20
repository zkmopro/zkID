import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { probeHipki } from "./hipki-detector";
import * as popup from "./hipki-popup";

describe("probeHipki", () => {
  beforeEach(() => {
    // Each test stubs `popupPkcs11Info`; default mock prevents accidental
    // real popup-window creation in jsdom.
    vi.spyOn(popup, "popupPkcs11Info").mockResolvedValue({ slots: [] });
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns `not_installed` when the popup bridge throws", async () => {
    vi.spyOn(popup, "popupPkcs11Info").mockRejectedValue(
      new Error("HiPKI popup not open"),
    );
    const probe = await probeHipki();
    expect(probe.status).toBe("not_installed");
  });

  it("returns `no_reader` when response has zero slots", async () => {
    vi.spyOn(popup, "popupPkcs11Info").mockResolvedValue({
      serverVersion: "1.0.11",
      slots: [],
    });
    const probe = await probeHipki();
    expect(probe.status).toBe("no_reader");
    if (probe.status === "no_reader") {
      expect(probe.serverVersion).toBe("1.0.11");
    }
  });

  it("returns `no_reader_or_card` when a slot exists but has no token", async () => {
    vi.spyOn(popup, "popupPkcs11Info").mockResolvedValue({
      serverVersion: "1.0.11",
      slots: [{ slotDescription: "Test Reader 0" }],
    });
    const probe = await probeHipki();
    expect(probe.status).toBe("no_reader_or_card");
    if (probe.status === "no_reader_or_card") {
      expect(probe.slots).toEqual(["Test Reader 0"]);
    }
  });

  it("returns `card_inserted` with serial + slot when token is present", async () => {
    vi.spyOn(popup, "popupPkcs11Info").mockResolvedValue({
      serverVersion: "1.0.11",
      slots: [
        {
          slotDescription: "Reader A",
          token: { serialNumber: "ABC123", certs: [] },
        },
      ],
    });
    const probe = await probeHipki();
    expect(probe.status).toBe("card_inserted");
    if (probe.status === "card_inserted") {
      expect(probe.cardSN).toBe("ABC123");
      expect(probe.slotDescription).toBe("Reader A");
    }
  });

  it("picks the slot with a token even if an earlier slot is empty", async () => {
    vi.spyOn(popup, "popupPkcs11Info").mockResolvedValue({
      slots: [
        { slotDescription: "Empty Reader" },
        {
          slotDescription: "Real Reader",
          token: { serialNumber: "SN42", certs: [] },
        },
      ],
    });
    const probe = await probeHipki();
    expect(probe.status).toBe("card_inserted");
    if (probe.status === "card_inserted") {
      expect(probe.cardSN).toBe("SN42");
      expect(probe.slotDescription).toBe("Real Reader");
    }
  });
});
