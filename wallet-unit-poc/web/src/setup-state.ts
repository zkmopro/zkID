// Setup-screen state. Lives outside the FSM store's phase union because
// these values survive Retry: after proving, we want to re-prove without
// re-detecting the card or re-typing the PIN.
//
// Two-step HiPKI flow (mirrors selfTest.htm):
//   1. user clicks "Detect readers" → popup runs `CheckEnvir` → we get
//      back a slot list with optional `token` per slot. UI flips to
//      `readers_listed` and renders a picker.
//   2. user picks a slot + clicks "Read card" → popup runs `GetUserCert`
//      scoped to that `slotDescription` → we parse the cert into a
//      CardContext. UI flips to `card_ready` which unlocks PIN entry.

import { atom, type WritableAtom } from "nanostores";

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

export const $hipki: WritableAtom<HipkiState> = atom<HipkiState>({
  status: "probing",
});
export const $pin: WritableAtom<PinState> = atom<PinState>({
  status: "pending",
});

/** Reset both atoms. Called on FSM `reset`. Does NOT clear the underlying
 *  `Pin` value since its own `consume()` is the authoritative sink. */
export function resetSetup(): void {
  $hipki.set({ status: "probing" });
  $pin.set({ status: "pending" });
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
