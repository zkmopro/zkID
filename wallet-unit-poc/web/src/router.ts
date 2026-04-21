import { mountLanding } from "./screens/landing";
import { mountProving } from "./screens/proving";
import { mountReady } from "./screens/ready";
import { mountResult } from "./screens/result";
import { mountReview } from "./screens/review";
import { mountSetup } from "./screens/setup";
import { mountSubmitting } from "./screens/submitting";
import { $state, type AppState } from "./store";

type Mount = (root: HTMLElement) => () => void;

function mountFor(state: AppState): Mount {
  switch (state.phase) {
    case "landing":
      return mountLanding;
    case "setup":
      return mountSetup;
    case "ready":
      return mountReady;
    case "proving":
      return mountProving;
    case "review":
      return mountReview;
    case "submitting":
      return mountSubmitting;
    case "result":
    case "error":
      return mountResult;
  }
}

export function mountRouter(root: HTMLElement): () => void {
  let currentPhase: AppState["phase"] | null = null;
  let disposeScreen: (() => void) | null = null;

  const render = (state: AppState): void => {
    // `result` and `error` share mountResult; it reads $state at mount
    // time, so remount on any phase change to refresh the banner payload.
    if (state.phase === currentPhase) return;
    disposeScreen?.();
    disposeScreen = mountFor(state)(root);
    currentPhase = state.phase;
  };

  render($state.get());
  const unsub = $state.listen(render);

  return () => {
    unsub();
    disposeScreen?.();
    disposeScreen = null;
    currentPhase = null;
  };
}
