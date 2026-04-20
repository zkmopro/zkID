import { describe, expect, it } from "vitest";

import { transition, type AppEvent, type AppState } from "./store";

describe("transition", () => {
  it("landing + start → setup", () => {
    expect(transition({ phase: "landing" }, { type: "start" })).toEqual({
      phase: "setup",
    });
  });

  it("setup + continue → proving", () => {
    expect(transition({ phase: "setup" }, { type: "continue" })).toEqual({
      phase: "proving",
    });
  });

  it("proving + proving_done → result", () => {
    expect(
      transition(
        { phase: "proving" },
        { type: "proving_done", verified: true, durationMs: 1234 },
      ),
    ).toEqual({ phase: "result", verified: true, durationMs: 1234 });
  });

  it("proving + pipeline_error → error", () => {
    expect(
      transition(
        { phase: "proving" },
        { type: "pipeline_error", where: "witness", message: "boom" },
      ),
    ).toEqual({ phase: "error", where: "witness", message: "boom" });
  });

  it("setup + pipeline_error → error (fixture-load failures surface before proving starts)", () => {
    expect(
      transition(
        { phase: "setup" },
        { type: "pipeline_error", where: "fixtures", message: "404" },
      ),
    ).toEqual({ phase: "error", where: "fixtures", message: "404" });
  });

  it("any + reset → landing", () => {
    const states: AppState[] = [
      { phase: "setup" },
      { phase: "proving" },
      { phase: "result", verified: false, durationMs: 10 },
      { phase: "error", where: "x", message: "y" },
    ];
    for (const s of states) {
      expect(transition(s, { type: "reset" })).toEqual({ phase: "landing" });
    }
  });

  it("illegal transitions return current state unchanged", () => {
    const cases: Array<[AppState, AppEvent]> = [
      // `start` only valid from landing.
      [{ phase: "setup" }, { type: "start" }],
      [{ phase: "proving" }, { type: "start" }],
      // `continue` only valid from setup.
      [{ phase: "landing" }, { type: "continue" }],
      [{ phase: "proving" }, { type: "continue" }],
      // `proving_done` only valid from proving.
      [
        { phase: "landing" },
        { type: "proving_done", verified: true, durationMs: 1 },
      ],
      [
        { phase: "setup" },
        { type: "proving_done", verified: true, durationMs: 1 },
      ],
      // `pipeline_error` not valid from landing / result / error.
      [
        { phase: "landing" },
        { type: "pipeline_error", where: "x", message: "y" },
      ],
      [
        { phase: "result", verified: true, durationMs: 1 },
        { type: "pipeline_error", where: "x", message: "y" },
      ],
    ];
    for (const [state, event] of cases) {
      expect(transition(state, event)).toEqual(state);
    }
  });
});
