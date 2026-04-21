// Pre-fetched challenge atom.
//
// The challenge is fetched during Ready-screen mount so the Start-proving
// click reaches window.open (via signTbs) with user-activation still live.
// Fetching inside the click handler would await a network response first,
// consuming activation, and the HiPKI popup would be blocked by every
// modern browser (Chrome, Safari, Firefox all enforce this).
//
// Single-use: consumed by the proving run and dropped on phase exit so
// any retry re-enters Ready and fetches a fresh one.

import { atom, type WritableAtom } from "nanostores";

import type { Challenge } from "./verifier-client";

export type ChallengeState =
  | { status: "pending" }
  | { status: "fetching" }
  | { status: "ready"; challenge: Challenge }
  | { status: "error"; message: string };

export const $challenge: WritableAtom<ChallengeState> = atom<ChallengeState>({
  status: "pending",
});

export function clearChallenge(): void {
  $challenge.set({ status: "pending" });
}
