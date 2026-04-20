import { mountLanding } from "./screens/landing";
import { mountProving } from "./screens/proving";
import { mountSetup } from "./screens/setup";
import { $state, type AppState } from "./store";

type Mount = (root: HTMLElement) => () => void;

// `result` and `error` share the proving screen: the result banner and Retry
// action live there, so collapsing them into one mount avoids a remount flash
// when the pipeline finishes.
function mountFor(state: AppState): Mount {
  switch (state.phase) {
    case "landing":
      return mountLanding;
    case "setup":
      return mountSetup;
    case "proving":
    case "result":
    case "error":
      return mountProving;
  }
}

export function mountRouter(root: HTMLElement): () => void {
  let currentPhase: AppState["phase"] | null = null;
  let disposeScreen: (() => void) | null = null;

  const render = (state: AppState): void => {
    const screenKey =
      state.phase === "result" || state.phase === "error"
        ? "proving"
        : state.phase;
    if (screenKey === currentPhase) return;
    disposeScreen?.();
    disposeScreen = mountFor(state)(root);
    currentPhase = screenKey;
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
