// App-level finite state machine.
//
// The router subscribes to `$state.phase` and mounts the matching screen.
// Per-step progress atoms still live in `ui.ts`; this store owns only the
// phase transitions that decide which screen is visible.

import { atom, type WritableAtom } from "nanostores";

export type AppState =
  | { phase: "landing" }
  | { phase: "setup" }
  | { phase: "proving" }
  | { phase: "result"; verified: boolean; durationMs: number }
  | { phase: "error"; where: string; message: string };

export type AppEvent =
  | { type: "start" }
  | { type: "continue" }
  | { type: "proving_done"; verified: boolean; durationMs: number }
  | { type: "pipeline_error"; where: string; message: string }
  | { type: "reset" };

/** Pure reducer. Invalid transitions return the current state unchanged. */
export function transition(state: AppState, event: AppEvent): AppState {
  switch (event.type) {
    case "start":
      return state.phase === "landing" ? { phase: "setup" } : state;
    case "continue":
      return state.phase === "setup" ? { phase: "proving" } : state;
    case "proving_done":
      return state.phase === "proving"
        ? {
            phase: "result",
            verified: event.verified,
            durationMs: event.durationMs,
          }
        : state;
    case "pipeline_error":
      // setup-origin errors (fixture load, HiPKI detect) surface through the
      // same terminal path as proving-origin errors; Phase 4 adds setup-phase
      // producers.
      return state.phase === "proving" || state.phase === "setup"
        ? { phase: "error", where: event.where, message: event.message }
        : state;
    case "reset":
      return { phase: "landing" };
  }
}

export type AppStateAtom = WritableAtom<AppState>;

export const $state: AppStateAtom = atom<AppState>({ phase: "landing" });

export function dispatch(event: AppEvent): void {
  $state.set(transition($state.get(), event));
}
