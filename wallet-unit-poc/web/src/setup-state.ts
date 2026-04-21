// Setup-screen state. Lives outside the FSM phase union so it survives
// Retry — after proving, the user can re-prove without re-detecting the
// card or re-typing the PIN.
//
// HiPKI is a two-step click flow: `Detect readers` (CheckEnvir) lists
// slots; the user picks one and clicks `Read card` (GetUserCert scoped
// to that slot) to parse the cert and unlock PIN entry.

import { atom, computed, type ReadableAtom, type WritableAtom } from "nanostores";

import type { CardContext } from "./pipeline";
import type { Pin } from "./pin";

/** Snapshot of one slot the picker shows the user. */
export interface ReaderSlot {
  slotDescription: string;
  /** Card serial if a card is inserted, else undefined. */
  cardSN?: string;
}

export type HipkiState =
  | { status: "probing" }
  | { status: "detecting" }
  | { status: "not_installed"; message: string }
  | {
      status: "readers_listed";
      slots: ReaderSlot[];
      serverVersion?: string;
      /** Slot the user picked (defaults to the first slot with a card). */
      selectedSlot?: string;
    }
  | { status: "reading"; slotDescription: string }
  | {
      status: "card_ready";
      card: CardContext;
      cardSN: string;
      subjectDN?: string;
      serverVersion?: string;
    };

export type PinState =
  | { status: "pending" }
  | { status: "verifying"; cardSN: string }
  | {
      status: "locked";
      pin: Pin;
      cardSN: string;
      attemptsRemaining: number;
    }
  | {
      status: "error";
      message: string;
      attemptsRemaining: number;
    };

/** Worker warmup status. Drives the Assets panel and contributes to
 *  `$setupReady`. */
export type WarmupState =
  | { status: "idle" }
  | { status: "running"; sublabel: string; bytesDone?: number; bytesTotal?: number }
  | { status: "ready" }
  | { status: "error"; message: string };

export const $hipki: WritableAtom<HipkiState> = atom<HipkiState>({
  status: "probing",
});
export const $pin: WritableAtom<PinState> = atom<PinState>({
  status: "pending",
});
export const $warmup: WritableAtom<WarmupState> = atom<WarmupState>({
  status: "idle",
});

/** Derived: true when all three setup panels are green. Gates Continue. */
export const $setupReady: ReadableAtom<boolean> = computed(
  [$warmup, $hipki, $pin],
  (warmup, hipki, pin) =>
    warmup.status === "ready" &&
    hipki.status === "card_ready" &&
    pin.status === "locked",
);

/** Reset every setup atom. Called on FSM `reset` → landing. The `Pin`
 *  wrapper's own `consume()` is the authoritative single-use sink; the
 *  atom update drops the reference so nothing else can reach it. */
export function resetSetup(): void {
  $hipki.set({ status: "probing" });
  $pin.set({ status: "pending" });
  $warmup.set({ status: "idle" });
}

/** Single source of truth for "card is parsed and ready for PIN entry". */
export function isCardReady(): boolean {
  return $hipki.get().status === "card_ready";
}

/** Invalidate a verified PIN. Called whenever the card context changes
 *  (re-detect, re-read) so a `locked` PIN can't refer to a card the user
 *  no longer has selected. */
export function dropStalePin(): void {
  const pinNow = $pin.get();
  if (pinNow.status === "locked" || pinNow.status === "verifying") {
    $pin.set({ status: "pending" });
  }
}
