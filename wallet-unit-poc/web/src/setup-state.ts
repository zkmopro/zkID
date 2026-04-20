// Setup-screen state (card probe + verified PIN). Lives outside the FSM
// store's phase union because these values survive Retry: after proving,
// we'd want to re-prove without re-tearing down the polling detector (the
// card and PIN stay valid as long as the card is still inserted).
//
// `$hipki` is driven by the polling detector in `hipki-detector.ts`. It
// distills /pkcs11info responses into four actionable states:
//   - `not_installed`: LocalSignServer unreachable
//   - `no_reader`: server responds but no slots
//   - `no_reader_or_card`: slot present but no token (card out)
//   - `card_inserted`: card present — enriched with the full `CardContext`
//     after a one-shot `fetchPkcs11Info(withcert=true)` pull
//
// `$pin` stays verified only while the cardSN that verified it is still
// inserted. If the user pulls the card, we drop the locked PIN.

import { atom, type WritableAtom } from "nanostores";

import type { HipkiProbe } from "./hipki-detector";
import type { CardContext } from "./pipeline";
import type { Pin } from "./pin";

export type HipkiState =
  | { status: "probing" }
  | HipkiProbe
  // `card_ready` is the post-detection state: we've fetched the full
  // pkcs11info + parsed the user cert into a CardContext. The setup flow
  // treats this as "ready for PIN" the same way it treated `card: ok` before.
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
