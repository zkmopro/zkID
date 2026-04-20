// Setup-screen state (card + PIN). Lives outside the store's phase union
// because these values survive Retry: after proving, we'd want to re-prove
// without re-detecting the card or re-typing the PIN (the card locks after
// three wrong PIN attempts; making the user re-verify on every retry would
// risk burning attempts).
//
// Cleared on `reset` when the FSM returns to `landing` — see main.ts.

import { atom, type WritableAtom } from "nanostores";

import type { CardContext } from "./pipeline";
import type { Pin } from "./pin";

export type CardState =
  | { status: "pending" }
  | { status: "detecting" }
  | { status: "ok"; card: CardContext; subjectDN?: string; cardSN?: string }
  | { status: "error"; message: string };

export type PinState =
  | { status: "pending" }
  | { status: "verifying" }
  | { status: "locked"; pin: Pin; attemptsRemaining: number }
  | { status: "error"; message: string; attemptsRemaining: number };

export const $card: WritableAtom<CardState> = atom<CardState>({
  status: "pending",
});
export const $pin: WritableAtom<PinState> = atom<PinState>({
  status: "pending",
});

/** Reset both atoms. Called on FSM `reset`. Does NOT clear the underlying
 *  `Pin` value since its own `consume()` is the authoritative sink. */
export function resetSetup(): void {
  $card.set({ status: "pending" });
  $pin.set({ status: "pending" });
}
