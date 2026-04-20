import { dispatch } from "../store";

export function mountLanding(root: HTMLElement): () => void {
  root.innerHTML = `
    <section class="screen screen-landing">
      <h1>zkID in-browser prover</h1>
      <p class="intro">
        Generate a zero-knowledge proof of your Taiwan Citizen Digital
        Certificate without revealing any personal data. Everything runs
        locally in your browser; verification happens on the server.
      </p>
      <button class="primary-button" data-testid="start-button" type="button">
        Start
      </button>
    </section>
  `;
  const button = root.querySelector<HTMLButtonElement>(
    '[data-testid="start-button"]',
  );
  const onClick = () => dispatch({ type: "start" });
  button?.addEventListener("click", onClick);
  return () => button?.removeEventListener("click", onClick);
}
