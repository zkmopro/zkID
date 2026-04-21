// Setup-screen state. Lives outside the FSM store's phase union because
// these values survive Retry: after proving, we want to re-prove without
// re-detecting the card or re-typing the PIN.
//
// `$hipki` is click-driven through the popupForm bridge. The popup is
// single-shot — each detect or sign opens its own popup that self-closes
// after one response. States:
//   - `probing`: initial, no detect attempted yet
//   - `detecting`: a detect popup is in flight
//   - `not_installed` / `no_reader` / `no_reader_or_card`: detect surfaced
//     a problem the user can act on (install HiPKI, plug in reader,
//     insert card)
//   - `card_inserted`: detect saw a card but enrichment is pending
//   - `card_ready`: cert parsed into a CardContext, PIN entry unlocked

import { atom, type WritableAtom } from "nanostores";

import type { CardContext } from "./pipeline";
import type { Pin } from "./pin";

export type HipkiState =
  | { status: "probing" }
  | { status: "detecting" }
  | { status: "not_installed"; message: string }
  | { status: "no_reader"; serverVersion?: string }
  | { status: "no_reader_or_card"; serverVersion?: string; slots: string[] }
  | {
      status: "card_inserted";
      cardSN: string;
      slotDescription?: string;
      serverVersion?: string;
    }
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
