// Polling HiPKI detector. Mirrors the HiPKI "IC card function check"
// reference page: every few seconds we POST /pkcs11info and distill the
// response into four actionable states so the UI can give precise feedback
// instead of a generic "HiPKI error".
//
//   not_installed — /pkcs11info doesn't respond (no LocalSignServer running).
//   no_reader     — server responds but has no slots.
//   no_card       — reader present, no slot has a `token` (card out).
//   card_inserted — at least one slot has a token with a serialNumber.
//
// Only `card_inserted` unblocks PIN entry.

import { probePkcs11Info, type Pkcs11InfoResponse } from "./hipki-client";

export type HipkiProbe =
  | { status: "not_installed"; message: string }
  | { status: "no_reader"; serverVersion?: string }
  | { status: "no_reader_or_card"; serverVersion?: string; slots: string[] }
  | { status: "card_inserted"; serverVersion?: string; cardSN: string; slotDescription?: string };

function interpret(resp: Pkcs11InfoResponse): HipkiProbe {
  const slots = resp.slots ?? [];
  if (slots.length === 0) {
    return { status: "no_reader", serverVersion: resp.serverVersion };
  }
  const withToken = slots.find((s) => s.token && s.token.serialNumber);
  if (!withToken) {
    return {
      status: "no_reader_or_card",
      serverVersion: resp.serverVersion,
      slots: slots
        .map((s) => s.slotDescription)
        .filter((d): d is string => typeof d === "string"),
    };
  }
  return {
    status: "card_inserted",
    serverVersion: resp.serverVersion,
    cardSN: withToken.token!.serialNumber!,
    slotDescription: withToken.slotDescription,
  };
}

/** One-shot probe. */
export async function probeHipki(): Promise<HipkiProbe> {
  try {
    const resp = await probePkcs11Info();
    return interpret(resp);
  } catch (err) {
    return {
      status: "not_installed",
      message: err instanceof Error ? err.message : String(err),
    };
  }
}

export interface HipkiPollerHandle {
  stop(): void;
}

/**
 * Poll `/pkcs11info` on a self-scheduling chain — the next probe is scheduled
 * only after the current one resolves, so a slow card reader cannot cause
 * overlapping requests to the LocalSignServer.
 *
 * Fires `onChange` only when the distilled probe key changes, so the UI
 * doesn't repaint on every tick.
 */
export function startHipkiPolling(
  onChange: (probe: HipkiProbe) => void,
  intervalMs = 2000,
): HipkiPollerHandle {
  let stopped = false;
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  let last: string | null = null;

  const runTick = async (): Promise<void> => {
    if (stopped) return;
    const probe = await probeHipki();
    if (stopped) return;
    const key = probeKey(probe);
    if (key !== last) {
      last = key;
      onChange(probe);
    }
  };

  const schedule = (): void => {
    if (stopped) return;
    timeoutId = setTimeout(() => {
      void runTick().finally(schedule);
    }, intervalMs);
  };

  void runTick().finally(schedule);
  return {
    stop() {
      stopped = true;
      if (timeoutId !== null) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
    },
  };
}

function probeKey(p: HipkiProbe): string {
  switch (p.status) {
    case "not_installed":
      return "not_installed";
    case "no_reader":
      return "no_reader";
    case "no_reader_or_card":
      return `no_card:${p.slots.join(",")}`;
    case "card_inserted":
      return `card:${p.cardSN}`;
  }
}
