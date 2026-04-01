// zkID Web Demo — RS256 Proof Pipeline
// Hybrid architecture: browser witness generation + server-side proving

// --- Configuration ---
const CONFIG = {
  // Path to the test certificate input JSON (bundled with the demo)
  testInputUrl: '/assets/rs256-input.json',
  // Path to the circom witness calculator WASM
  witnessWasmUrl: '/assets/rs256.wasm',
  // Proving server endpoint (ecdsa-spartan2 HTTP mode)
  proveServerUrl: 'http://localhost:8080/prove',
};

// --- Types ---
interface StepLog {
  step: number;
  label: string;
  durationMs: number;
}

type StepState = 'disabled' | 'active' | 'done' | 'error';

// --- State ---
let circuitInput: Record<string, unknown> | null = null;
let circuitInputJson: string | null = null;
let proofBytes: Uint8Array | null = null;
const logs: StepLog[] = [];

// --- UI Helpers ---
function setStepState(step: number, state: StepState, statusText?: string) {
  const el = document.getElementById(`step-${step}`);
  if (!el) return;
  el.setAttribute('data-state', state);
  const statusEl = el.querySelector('.step-status');
  if (statusEl && statusText) statusEl.textContent = statusText;

  // Enable/disable button
  const btn = el.querySelector('button');
  if (btn) btn.disabled = state === 'disabled';
}

function addLog(step: number, label: string, durationMs: number, error?: boolean) {
  logs.push({ step, label, durationMs });
  const logsEl = document.getElementById('logs');
  if (!logsEl) return;
  const mark = error ? '<span class="error-mark">✗</span>' : '<span class="checkmark">✓</span>';
  const timeStr = durationMs >= 1000
    ? `${(durationMs / 1000).toFixed(1)}s`
    : `${durationMs}ms`;
  logsEl.innerHTML += `<div class="log-entry">${mark} ${label} <span class="time">${timeStr}</span></div>`;
}

function showResult(success: boolean, details: string) {
  const el = document.getElementById('result-banner');
  if (!el) return;
  el.classList.remove('hidden', 'success', 'failure');
  el.classList.add(success ? 'success' : 'failure');
  el.innerHTML = details;
}

function hideOverlay() {
  const el = document.getElementById('overlay');
  if (el) el.classList.add('hidden');
}

// --- Step 1: Load Certificate ---
async function handleLoad() {
  const t0 = performance.now();
  try {
    const resp = await fetch(CONFIG.testInputUrl);
    if (!resp.ok) throw new Error(`Failed to fetch: ${resp.status}`);
    circuitInput = await resp.json();
    const ms = Math.round(performance.now() - t0);
    addLog(1, 'Certificate data loaded', ms);
    setStepState(1, 'done', `${ms}ms`);
    setStepState(2, 'active');
  } catch (e) {
    const ms = Math.round(performance.now() - t0);
    addLog(1, `Load failed: ${e}`, ms, true);
    setStepState(1, 'error', 'failed');
  }
}

// --- Step 2: Prepare Input ---
// Loads circom witness WASM and prepares circuit input for the proving server
async function handleWitness() {
  if (!circuitInput) return;
  const t0 = performance.now();
  try {
    // Load the circom witness calculator
    const wasmResp = await fetch(CONFIG.witnessWasmUrl);
    if (!wasmResp.ok) throw new Error(`Failed to fetch witness WASM: ${wasmResp.status}`);
    const wasmBuffer = await wasmResp.arrayBuffer();

    // Use the circom witness_calculator.js pattern
    // For now, we'll send the circuit input to the server for witness generation too
    // (Full browser witness gen requires porting witness_calculator.js)
    const loadMs = Math.round(performance.now() - t0);
    addLog(2, `Witness WASM loaded (${(wasmBuffer.byteLength / 1024 / 1024).toFixed(1)}MB)`, loadMs);

    // Store the serialized input for the proving step
    circuitInputJson = JSON.stringify(circuitInput);
    const totalMs = Math.round(performance.now() - t0);
    addLog(2, 'Circuit input prepared for proving server', totalMs);
    setStepState(2, 'done', `${totalMs}ms`);
    setStepState(3, 'active');
  } catch (e) {
    const ms = Math.round(performance.now() - t0);
    addLog(2, `Input preparation failed: ${e}`, ms, true);
    setStepState(2, 'error', 'failed');
  }
}

// --- Step 3: Generate Proof (Server) ---
async function handleProve() {
  if (!circuitInputJson) return;
  const t0 = performance.now();
  try {
    setStepState(3, 'active', 'proving...');
    const resp = await fetch(CONFIG.proveServerUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: circuitInputJson,
    });
    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`Proving server error (${resp.status}): ${errText}`);
    }
    const result = await resp.json();
    const proofB64 = result.proof;
    proofBytes = base64ToBytes(proofB64);
    const ms = Math.round(performance.now() - t0);
    addLog(3, `Proof generated (${(proofBytes.length / 1024).toFixed(1)}KB) in ${(result.timing_ms / 1000).toFixed(1)}s server-side`, ms);
    setStepState(3, 'done', `${ms}ms`);
    setStepState(4, 'done', 'ready');
    showProofOutput(proofB64);
  } catch (e) {
    const ms = Math.round(performance.now() - t0);
    addLog(3, `Proving failed: ${e}`, ms, true);
    setStepState(3, 'error', 'failed');
  }
}

// --- Step 4: Show proof for go-zkid-verifier ---
function showProofOutput(proofB64: string) {
  const proofOutput = document.getElementById('proof-output');
  const proofText = document.getElementById('proof-text') as HTMLTextAreaElement | null;
  if (proofOutput) proofOutput.classList.remove('hidden');
  if (proofText) proofText.value = proofB64;

  addLog(4, 'Proof ready — submit to go-zkid-verifier /verify endpoint', 0);
  showResult(true, `
    <strong>Proof Generated Successfully</strong><br/>
    Size: ${proofBytes ? (proofBytes.length / 1024).toFixed(1) : '?'}KB |
    Timing: ${formatTimingSummary()}<br/><br/>
    Submit the proof to
    <a href="https://github.com/zkmopro/go-zkid-verifier" target="_blank">go-zkid-verifier</a>
    for off-chain verification.
  `);
}

// --- Utilities ---
function base64ToBytes(b64: string): Uint8Array {
  const binString = atob(b64);
  return Uint8Array.from(binString, (c) => c.charCodeAt(0));
}

function formatTimingSummary(): string {
  return logs.map((l) => {
    const timeStr = l.durationMs >= 1000
      ? `${(l.durationMs / 1000).toFixed(1)}s`
      : `${l.durationMs}ms`;
    return `Step ${l.step}: ${timeStr}`;
  }).join(' | ');
}

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
  hideOverlay();

  document.getElementById('btn-load')?.addEventListener('click', handleLoad);
  document.getElementById('btn-witness')?.addEventListener('click', handleWitness);
  document.getElementById('btn-prove')?.addEventListener('click', handleProve);
  document.getElementById('btn-copy')?.addEventListener('click', () => {
    const proofText = document.getElementById('proof-text') as HTMLTextAreaElement | null;
    if (proofText) {
      navigator.clipboard.writeText(proofText.value);
      const btn = document.getElementById('btn-copy');
      if (btn) { btn.textContent = 'Copied!'; setTimeout(() => { btn.textContent = 'Copy to clipboard'; }, 2000); }
    }
  });
});
