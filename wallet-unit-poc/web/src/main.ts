import {
  initWasm,
  loadCertificate,
  generateWitness,
  prove,
  verify,
  formatMs,
  formatBytes,
  type StepLog,
} from "./pipeline.js";
import "./style.css";

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

function setStepState(
  stepNum: number,
  state: "disabled" | "active" | "done" | "error"
) {
  const el = $(`step-${stepNum}`);
  el.classList.remove("disabled", "active", "done", "error");
  el.classList.add(state);
}

function enableButton(id: string) {
  ($(id) as HTMLButtonElement).disabled = false;
}

function disableButton(id: string) {
  ($(id) as HTMLButtonElement).disabled = true;
}

function setButtonRunning(id: string) {
  const btn = $(id) as HTMLButtonElement;
  btn.disabled = true;
  btn.classList.add("running");
}

function clearButtonRunning(id: string) {
  $(id).classList.remove("running");
}

function renderLogs(containerId: string, logs: StepLog[]) {
  $(containerId).innerHTML = logs
    .map(
      (log) => `
    <div class="log-line">
      <span class="log-label"><span class="log-check">&#10003;</span> ${log.label}</span>
      <span class="log-duration">${formatMs(log.durationMs)}</span>
    </div>`
    )
    .join("");
}

function renderProgress(containerId: string, message: string) {
  const container = $(containerId);
  const existing = container.querySelector(".log-line.in-progress");
  if (existing) existing.remove();
  container.innerHTML += `
    <div class="log-line in-progress">
      <span class="log-label"><span class="log-spinner spinner">&#9696;</span> ${message}</span>
      <span class="log-duration">...</span>
    </div>`;
}

function setStatus(
  stepNum: number,
  state: "running" | "done" | "error",
  text: string,
  timing?: string
) {
  $(`status-${stepNum}`).innerHTML = `
    <div class="status-bar ${state}">
      <span>${text}</span>
      ${timing ? `<span class="timing">${timing}</span>` : ""}
    </div>`;
}

function showResultBanner(valid: boolean, verifyMs: number, error?: string) {
  const banner = $("result-banner");
  banner.classList.remove("hidden", "success", "failure");
  banner.classList.add(valid ? "success" : "failure");

  $("result-icon").innerHTML = valid
    ? '<span style="color: var(--success)">&#10003;</span>'
    : '<span style="color: var(--error)">&#10007;</span>';

  $("result-title").textContent = valid ? "VERIFIED" : "VERIFICATION FAILED";

  let html = "";
  if (valid) {
    html += `<div class="result-row">
      <span class="result-label">Verified in:</span>
      <span class="result-value">${formatMs(verifyMs)}</span>
    </div>`;
  } else {
    html += `<div class="result-row">
      <span class="result-label">Error:</span>
      <span class="result-value">${error ?? "Unknown error"}</span>
    </div>`;
  }
  $("result-details").innerHTML = html;
}

async function init() {
  const overlay = document.createElement("div");
  overlay.className = "init-overlay";
  overlay.id = "init-overlay";
  overlay.innerHTML = `
    <div class="init-box">
      <h2>Initializing zkID RS256 Demo</h2>
      <p class="init-mode">Multi-threaded WASM (${navigator.hardwareConcurrency} cores)</p>
      <div class="init-status" id="init-status">Loading WASM module...</div>
      <div class="init-logs" id="init-logs"></div>
    </div>`;
  document.body.appendChild(overlay);

  try {
    const logs = await initWasm((msg) => {
      $("init-status").textContent = msg;
    });

    $("init-logs").innerHTML = logs
      .map((l) => `<div>&#10003; ${l.label} — ${formatMs(l.durationMs)}</div>`)
      .join("");

    $("init-status").textContent = "Ready!";
    await new Promise((r) => setTimeout(r, 600));
    overlay.classList.add("hidden");
    setTimeout(() => overlay.remove(), 300);

    setStepState(1, "active");
    enableButton("btn-load");
  } catch (err) {
    $("init-status").textContent = `Error: ${err}`;
    console.error("Init failed:", err);
  }
}

async function handleLoad() {
  setButtonRunning("btn-load");
  setStatus(1, "running", "Loading...");
  try {
    const result = await loadCertificate();
    renderLogs("details-1", result.logs);
    setStatus(1, "done", "Certificate loaded", formatMs(result.totalMs));
    setStepState(1, "done");
    disableButton("btn-load");
    clearButtonRunning("btn-load");
    setStepState(2, "active");
    enableButton("btn-witness");
  } catch (err) {
    setStatus(1, "error", `Error: ${err}`);
    setStepState(1, "error");
    clearButtonRunning("btn-load");
    enableButton("btn-load");
  }
}

async function handleWitness() {
  setButtonRunning("btn-witness");
  setStatus(2, "running", "Generating witness...");
  $("details-2").innerHTML = "";
  try {
    const result = await generateWitness((msg) => renderProgress("details-2", msg));
    renderLogs("details-2", result.logs);
    setStatus(2, "done", "Witness generated", formatMs(result.totalMs));
    setStepState(2, "done");
    disableButton("btn-witness");
    clearButtonRunning("btn-witness");
    setStepState(3, "active");
    enableButton("btn-prove");
  } catch (err) {
    setStatus(2, "error", `Error: ${err}`);
    setStepState(2, "error");
    clearButtonRunning("btn-witness");
    enableButton("btn-witness");
    console.error("Witness failed:", err);
  }
}

async function handleProve() {
  setButtonRunning("btn-prove");
  setStatus(3, "running", "Proving...");
  $("details-3").innerHTML = "";
  try {
    const result = await prove((msg) => renderProgress("details-3", msg));
    renderLogs("details-3", result.logs);
    setStatus(3, "done", "Proof generated", formatMs(result.totalMs));
    setStepState(3, "done");
    disableButton("btn-prove");
    clearButtonRunning("btn-prove");
    setStepState(4, "active");
    enableButton("btn-verify");
  } catch (err) {
    setStatus(3, "error", `Error: ${err}`);
    setStepState(3, "error");
    clearButtonRunning("btn-prove");
    enableButton("btn-prove");
    console.error("Prove failed:", err);
  }
}

async function handleVerify() {
  setButtonRunning("btn-verify");
  setStatus(4, "running", "Verifying...");
  $("details-4").innerHTML = "";
  try {
    const result = await verify((msg) => renderProgress("details-4", msg));
    renderLogs("details-4", result.logs);
    if (result.valid) {
      setStatus(4, "done", "Verification passed", formatMs(result.totalMs));
      setStepState(4, "done");
    } else {
      setStatus(4, "error", `Failed: ${result.error}`, formatMs(result.totalMs));
      setStepState(4, "error");
    }
    disableButton("btn-verify");
    clearButtonRunning("btn-verify");
    showResultBanner(result.valid, result.totalMs, result.error);
  } catch (err) {
    setStatus(4, "error", `Error: ${err}`);
    setStepState(4, "error");
    clearButtonRunning("btn-verify");
    enableButton("btn-verify");
    console.error("Verify failed:", err);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("btn-load").addEventListener("click", handleLoad);
  $("btn-witness").addEventListener("click", handleWitness);
  $("btn-prove").addEventListener("click", handleProve);
  $("btn-verify").addEventListener("click", handleVerify);
  init();
});
