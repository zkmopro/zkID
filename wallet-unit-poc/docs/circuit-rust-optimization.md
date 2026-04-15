# zkID Circuit & Rust Prover Optimization Plan

## Context

The monolithic circuit on `main` was too large for mobile app and web app to generate proofs (peak memory >4 GiB in the browser per [PR #20 OOM report](https://github.com/zkmopro/zkID/pull/20#issuecomment-4242511679)). `refactor/circuit-optimization` has already shipped the structural fixes:

- **PR #22** — removed JWT/ES256 remnants.
- **PR #24** — split the monolith into two linked circuits: `CertChainRSA256` (~2.51M constraints, rs2048) and `DeviceSigRSA256` (~968K constraints), bound by `pk_commit = ChunkedPoseidonP256(user_pk_limbs ‖ pk_blind)`.
- **PR #25** — Rust prover for the split (`cert-chain` + `device-sig` CLI, `generate-split-input`, `link-verify`, fixture generator).

Peak single-proof R1CS dropped 1.1G → 617M (~44%), but four opportunities remain on this branch:

1. **CI structure** — a single `mobile-tests.yaml` currently mixes circuit compile, Rust E2E, and (trivial) mobile API tests. The mobile crate references deleted `sha256rsa4096` feature and `Rs256FidoCircuit` → `cargo check` in mobile fails. As the workflow sits, it mingles three concerns; splitting it into `circom-tests.yaml` / `rust-tests.yaml` / `mobile-tests.yaml` lets circuit and Rust work land without being gated on (future) mobile adaptation.
2. **PR #23** (merged to `main` *after* we branched at `457e5eb`) added `reader.rs` with a memory-mapped R1CS loader and a 256 MB-stack witness thread that fixes a macOS SIGSEGV during `realloc()`. PR #25 regressed to the heap-loading path. We absorb PR #23 by rebasing `refactor/circuit-optimization` onto current `main` and resolving the expected conflicts in `sha256rsa_circuit.rs`/`prover.rs` to keep PR #23's reader + thread spawn while preserving PR #25's split-circuit rewrite.
3. **Circuit hot spots** measurable against the current R1CS: `VerifySubjectDN` and `VerifySerialNumber` each run an O(N×M) IsEqual-sum selector — together ~290K constraints. zk-email's `array.circom` (already imported via `rs256.circom`) ships `SelectSubArray`/`VarShiftLeft` with **O(log₂(N)·N)** cost — a ~95 % reduction for this pattern. `maxMessageLength=1536` is also over-provisioned: the largest observed MOICA cert is 893 bytes; tightening to 1024 keeps 14 % headroom and drops 8 SHA-256 blocks plus shrinks every per-cert-byte scan.
4. **Prover hot spots** verified by reading the code: `load_r1cs` is called twice per prove run (setup phase + prove phase, at `sha256rsa_circuit.rs:847` and `:856`), but more importantly `SatisfyingAssignment::enforce` in Spartan2 is a **no-op** — so the prove-phase R1CS load and 2.5 M-constraint iteration are pure waste; `cached_witness` clones a full `Vec<Scalar>` on every access (`:814`); `save_keys` / `save_proof` / `save_instance` / `save_witness` serialize to an intermediate `Vec<u8>` before `write_all`; the release profile is `debug = true` only — no `lto`/`codegen-units`; `link-verify` does a non-constant-time field compare at `main.rs:244`.

**Out of scope**: SMT depth reduction (decision: keep depth 128 to match 128-bit serial number key space). Mobile crate migration (currently broken — separate follow-up plan). SDK WASM rewrite (orphaned `PrepareCircuit`/`ShowCircuit` — separate follow-up plan). Spartan2 engine swap, Nova folding, proof aggregation. Parallel `prove-split` (risks OOM on constrained devices). Criterion benchmark harness (existing `benchmark` subcommand is sufficient).

## Workflow & Governance

**One PR per phase** (except Phase 0, which is a local commit — see exception below). Each code-touching phase listed below ships as its own pull request. No stacked commits on a long-lived branch. This keeps reviews small, each gate decisive, and bisection easy if a regression slips through.

**Manual review gate between PRs.** After a phase PR is opened, execution stops and waits for manual check (code review, CI results, any local test run desired). Only after a "continue" signal does the next phase begin. No autonomous chaining of phases.

**Integration target: `refactor/circuit-optimization`.** Phase 1 (CI refactor) branches off and targets it. Phase 2 rebases the branch itself onto `main` (force-pushed). Phases 3.x and 4.x branch off `refactor/circuit-optimization` and target it. Once all phases are merged into `refactor/circuit-optimization`, a single final PR lifts the whole branch onto `main`. Branch naming follows the CLAUDE.md convention `<type>/<descriptor>` in kebab-case — see "PR & Branch Map" below for the exact names.

**Exception — Phase 0 is a local commit only, no PR.** The docs checked in by Phase 0 exist to stabilize the plan artifact on the branch itself; they travel with the Phase 1 PR for review context.

**Agent team drives each phase.** The main session orchestrates; per-phase specialists do the focused work:
- **`feature-dev:code-architect`** — produces a concrete, file-level implementation blueprint given this plan's phase description. Reads the current files, flags any mismatch between plan and reality, and returns the step-by-step code-level design.
- **Executor (main session)** — writes code per the architect's blueprint. Uses Edit/Write/Bash directly for small and medium phases. For large phases, may delegate to `feature-dev:feature-dev` or `general-purpose`.
- **`pr-review-toolkit:code-reviewer`** — reviews the diff before the PR is opened; confirms adherence to project conventions, catches silent failures and convention drift.
- **`pr-review-toolkit:code-simplifier`** — simplifies the resulting diff (drops dead scaffolding, unnecessary abstraction, over-commented sections) while preserving behavior. Runs after reviewer.

Per-phase execution loop: `architect → executor → reviewer → simplifier → verify (tests + E2E) → commit → push → open PR → WAIT for manual check → next phase`.

## Targets

| Layer | Metric | Today | After plan |
|---|---|---|---|
| cert_chain_rs2048 | R1CS constraints | 2,512,448 | ~2.0 – 2.2 M (expect 12–20 % reduction) |
| cert_chain_rs4096 | R1CS constraints | 2,703,872 | ~2.2 – 2.4 M |
| device_sig_rs2048 | R1CS constraints | 968,442 | unchanged (DeviceSig has no DN/serial scans) |
| ecdsa-spartan2 | cert-chain prove peak RSS | ~400 MB | ~200 MB (mmap + no witness clone + no R1CS during prove) |
| ecdsa-spartan2 | macOS witness SIGSEGV | crashes on rs4096 | fixed via 256 MB thread (ported from PR #23) |
| CI | per-area workflow | single mixed `mobile-tests.yaml` | split into `circom-tests` / `rust-tests` / `mobile-tests` |

Parallel prove and criterion benchmark harness are **deliberately out of scope** — parallel prove risks OOM on constrained devices (mobile is the main consumer once migration happens), and benchmark harness adds process weight for a workload that the existing `benchmark` subcommand already covers adequately. Measurements per phase captured via that subcommand plus `/usr/bin/time -l`.

## Phase Structure

Four tracks, nine phases (Phase 0 local-only; eight PRs). Each PR is independently mergeable, testable, and separated by a manual review gate.

### Phase 0 — publish this plan to project docs (local commit, no PR)

Before any code changes, commit the plan itself to the repo so reviewers can read it in context and future sessions can reference it without the `~/.claude/plans/` state. **This is a local commit on `refactor/circuit-optimization` — not a separate PR.** The docs travel into later phase PRs for review context.

**Files**
- `wallet-unit-poc/docs/circuit-rust-optimization.md` (new, copy of this plan verbatim). If `docs/` does not exist, create it with a minimal `README.md` pointing to this plan.

**Agent workflow**: trivial enough to skip architect; main session writes the file, reviewer does a quick pass for clarity, commit.

**Tests**: none (docs-only).

**Commit**: `docs: add circuit and Rust prover optimization plan`

### Phase 1 — CI workflow refactor

Split the current `mobile-tests.yaml` into three focused workflows aligned with crate boundaries. The mobile workflow stays but is marked to not block circuit/Rust landings — the mobile crate itself is broken (deleted `sha256rsa4096` feature, `Rs256FidoCircuit`), and fixing it is a separate follow-up plan. This refactor **does not touch** the mobile crate code; it only separates CI so the mobile's broken state doesn't gate circuit/Rust PRs.

**Files (new)**
- `.github/workflows/circom-tests.yaml` — triggers on `wallet-unit-poc/circom/**` and self-changes. Jobs: `compile-circuits` (Linux: rs2048, rs4096, device_sig), `compile-circuits-macos`, `circuit-tests` (mocha via `yarn test`). Artifacts: R1CS + C++ witness files, uploaded for rust-tests to consume (or recompiled there — see "Design decisions" below).
- `.github/workflows/rust-tests.yaml` — triggers on `wallet-unit-poc/ecdsa-spartan2/**`, `wallet-unit-poc/circom/circuits/**`, and self-changes. Jobs: `compile-circuits` (re-run for independence), `rust-tests` (unit + E2E split flow for rs2048 and rs4096 + link-verify), `release-artifacts` (upload keys + R1CS to GitHub Release on main branch only).

**Files (modified / replaced)**
- `.github/workflows/mobile-tests.yaml` — narrowed to only the mobile crate. Triggers on `wallet-unit-poc/mobile/**` and self-changes. Jobs: the trivial `cargo test --release --no-default-features --lib` that already runs today. Marked `continue-on-error: true` (or the whole workflow flagged non-blocking) since the crate is broken; fix-up is out of scope.

**Design decisions**
- **Artifact sharing between workflows**: cross-workflow artifact passing via `actions/download-artifact` requires GitHub API calls and adds coupling. For independence, `rust-tests.yaml` compiles circuits itself (~small duplication vs. `circom-tests.yaml`). Accept the duplication; it keeps each workflow self-contained and easy to re-run from the UI.
- **Triggers**: each workflow triggers on changes in its own domain. A PR that touches `ecdsa-spartan2/` only runs `rust-tests`; a PR that touches `circom/` runs `circom-tests` and `rust-tests` (since Rust consumes compiled circuits); mobile changes only run `mobile-tests`.
- **Mobile workflow non-blocking**: set `continue-on-error: true` on the Rust test step, or mark the whole workflow as a non-required check on branch protection. This decision is the user's (branch protection is a repo-admin concern); the plan notes it but doesn't encode a specific branch protection change.

**Tests**
- `workflow_dispatch` run of each new workflow on the branch before PR is opened. Confirm: `circom-tests` green, `rust-tests` green, `mobile-tests` exit code doesn't block.
- A throwaway commit touching only `wallet-unit-poc/ecdsa-spartan2/README.md` (a doc in the crate) should trigger `rust-tests` but not `circom-tests` or `mobile-tests` — verifies path filters.

**Docs**
- `CLAUDE.md` — rewrite the "CI Workflows" section to reflect the three-workflow split and their responsibilities.
- Add a brief `.github/workflows/README.md` (or section at the top of each workflow) describing what it covers and when it runs.

**Agent workflow**: architect reads the current `mobile-tests.yaml` and drafts the three new files; executor creates them; reviewer verifies path filters, job dependencies, and matrix strategies are correct; simplifier removes any duplication between workflow headers.

**Commit**: `ci: split mobile-tests.yaml into circom-tests, rust-tests, mobile-tests`

### Phase 2 — rebase onto main (brings in PR #23 via conflict resolution)

One PR that absorbs PR #23. Because PR #23 was merged to `main` after `refactor/circuit-optimization` branched, a proper rebase integrates those changes; conflicts with PR #25's sha256rsa_circuit.rs/prover.rs rewrite are resolved to keep PR #23's **new file `reader.rs`** and its **witnesscalc thread spawn** pattern, while dropping PR #23's `drop()` calls in prover.rs (PR #25's Spartan2 integration supersedes them).

**Action plan**
1. `git fetch origin main && git rebase origin/main` on `refactor/circuit-optimization` locally (or in a worktree).
2. Expected conflict files: `ecdsa-spartan2/src/circuits/sha256rsa_circuit.rs`, `ecdsa-spartan2/src/prover.rs`, possibly `Cargo.toml`, `Cargo.lock`.
3. Conflict resolution recipe:
   - **`reader.rs`**: take PR #23's version verbatim (no conflict — new file).
   - **`sha256rsa_circuit.rs`**: start from PR #25's rewrite, then reapply PR #23's two changes on top:
     (a) replace `use circom_scotia::{reader::load_r1cs, synthesize}` (line 10) with `use circom_scotia::synthesize; use crate::reader::load_r1cs_mmap;`; at the two call sites (lines 847 and 856) call `load_r1cs_mmap(&r1cs_path)` instead of `load_r1cs(&r1cs_path)`.
     (b) wrap `T::generate_witness_bytes(&json_string)` at line 798 in `std::thread::Builder::new().stack_size(256 << 20).spawn(...)`.
   - **`prover.rs`**: take PR #25's rewrite as-is; do **not** port PR #23's `drop()` calls (they target a prove path that no longer exists in PR #25's Spartan2-integrated flow).
   - **`Cargo.toml`**: keep `memmap2 = "0.9.8"` (already present); add `anyhow = "1"` only if `reader.rs` needs it.
   - **`lib.rs`**: add `pub mod reader;`.
4. `cargo test --release`, run the full E2E flow for both rs2048 and rs4096 (see Verification Plan).
5. `git push --force-with-lease origin refactor/circuit-optimization` (force-push is unavoidable after rebase; `--with-lease` protects against clobbering unseen remote work). **This is the only phase that force-pushes the branch; subsequent phases are clean fast-forwards.**

**Tests**
- `cargo test --release` (existing `fixture_consistency`, `split_input_generation` pass).
- `cargo run --release --features cert_chain_rs4096 -- cert-chain setup` and `cert-chain prove` complete without OOM and without SIGSEGV on macOS.
- New `rust-tests.yaml` (from Phase 1) green on the rebased branch.

**Docs**
- `wallet-unit-poc/ecdsa-spartan2/README.md` — add a "Performance" section noting the mmap R1CS loader and the 256 MB witnesscalc thread.

**Agent workflow**: architect reviews the actual rebase conflicts (they may differ from expectation), suggests the resolution; executor applies; reviewer checks the final diff against main vs pre-rebase; simplifier cleans up any stray artifacts from the merge.

**Commit** (after rebase): the rebase itself preserves PR #22, #24, #25 commit history. No new commit needed — the push *is* the PR. The PR description summarizes what was taken from PR #23 and what was dropped.

### Phase 3 — Track 1: circom constraint reduction

Cleanest ordering: tighten params first (bounded-impact, mostly config), then redesign selectors so the benefit compounds. Each phase is a re-setup point (keys/R1CS regenerated in CI).

#### 3.1 Tighten `maxMessageLength` 1536 → 1024 for cert_chain

Cuts SHA-256 from 24 → 16 blocks and shrinks every downstream byte scan. Keeps `maxSubjectDNLength = 128` so `subject_dn_hash = PoseidonBytes(128)` output stays bit-identical. Keeps `maxSerialNumberLength = 20`.

**Files**
- `wallet-unit-poc/circom/circuits.json` — change cert_chain_rs2048 params to `[1024, 121, 17, 2048, 17, 2048, 128, 128, 20]`, cert_chain_rs4096 to `[1024, 121, 34, 4096, 17, 2048, 128, 128, 20]`. Leave `device_sig_rs2048` at `[1536, …]` — device-sig `tbs` sizing is a broader roadmap concern tracked elsewhere.
- `wallet-unit-poc/circom/circuits/main/cert_chain_rs2048.circom` and `cert_chain_rs4096.circom` are auto-generated by circomkit — `yarn compile:all` regenerates them from `circuits.json`.
- `wallet-unit-poc/circom/inputs/cert_chain_rs2048/input.json`, `.../cert_chain_rs4096/input.json` — re-pad `user_cert_zero_padded`, `issuer_tbs` from 1536 → 1024 entries. **Preserve `default_tbs` value; change the fixture padding, not the payload.**
- `wallet-unit-poc/circom/tests/circuits/cert_chain_rs2048.test.ts`, `cert_chain_rs4096.test.ts`, `pk_commit_linking.test.ts` — update the `params` literal.
- `wallet-unit-poc/ecdsa-spartan2/src/circuits/split_circuits.rs` — update `MAX_MESSAGE_LENGTH` constant (currently 1536) to 1024.
- `wallet-unit-poc/ecdsa-spartan2/src/circuits/sha256rsa_circuit.rs` — any `1536` literal tied to cert_chain JSON array sizing drops to 1024; device-sig paths untouched.
- Regenerate fixtures: `cargo run --example generate_fixtures` (ChaCha-seeded; deterministic — seeds and `DEFAULT_TBS` stay).

**Tests**
- `yarn compile:cert_chain_rs2048 && yarn compile:cert_chain_rs4096` succeed; `snarkjs r1cs info build/cert_chain_rs2048/cert_chain_rs2048.r1cs` shows reduced count.
- `NODE_OPTIONS=--max-old-space-size=16384 yarn test`.
- `cargo test --release` + E2E: `generate-split-input` → `cert-chain setup/prove/verify` → `device-sig setup/prove/verify` → `link-verify`.

**Docs**
- `wallet-unit-poc/circom/README.md` — document the observed cert sizes and the 1024-byte budget.
- `CLAUDE.md` — no change (build commands unaffected).

**Commit**: `perf(circom): tighten cert_chain maxMessageLength to 1024`

#### 3.2 Redesign `VerifySubjectDN` + `VerifySerialNumber` via `SelectSubArray`

zk-email's `array.circom:VarShiftLeft(maxArrayLen, maxOutArrayLen)` is a log-depth butterfly shift: O(log₂(maxArrayLen)·maxArrayLen). For (1024, 128) that's ~10 K constraints vs the current ~196 K IsEqual-sum (after Phase 3.1's param tightening). `SelectSubArray` wraps `VarShiftLeft` with a `GreaterThan`-based zero-mask beyond `length`. Since the prover already supplies `subject_dn[maxSubjectDNLength]` as an input and enforces zero-padding for `i ≥ length`, the new circuit does: `extracted = SelectSubArray(cert, subject_dn_offset, subject_dn_length)`, then `extracted[i] === subject_dn[i]` for all `i < maxSubjectDNLength`. Same pattern for `VerifySerialNumber`: replace the O(maxSerialNumberLength × maxMessageLength) inner scans (cert byte extraction + tag/length selectors) with `SelectSubArray`-based extraction.

`PoseidonBytes(subject_dn)` (cert_chain.circom:105) is unchanged — public `subject_dn_hash` output is bit-identical.

**Files**
- `wallet-unit-poc/circom/circuits/utils/utils.circom` — rewrite `VerifySubjectDN` (lines 31–67) and `VerifySerialNumber` (lines 71–203) using `SelectSubArray` / `VarShiftLeft`. Replace the tag/length-byte extraction in `VerifySerialNumber` with `ItemAtIndex(maxArrayLen)` calls (also in `array.circom`) at `offset-2` and `offset-1`. The big-endian integer reconstruction table (`pow256`) stays; its dimension is `maxSerialNumberLength × (maxSerialNumberLength+1)` (~400 IsEquals for `maxSerialNumberLength=20`) — small, keep as-is.
- `wallet-unit-poc/circom/circuits/cert_chain.circom` — no signature change; the new template calls keep the same inputs.

**Tests**
- Add or extend `wallet-unit-poc/circom/tests/circuits/utils.test.ts` (create if missing) with focused coverage: `subject_dn_offset` at beginning / middle / end of cert; mismatch rejection; zero-length subject DN; over-long subject DN rejected.
- `yarn test` passes including existing `pk_commit_linking.test.ts`.
- E2E (Rust prover) unchanged.

**Docs**
- Header comment on each template stating which zk-email primitive it uses and why (intent + warnings only).
- `wallet-unit-poc/circom/README.md` — update the "Utilities" section to note dependency on `@zk-email/circuits/utils/array.circom`.

**Commit**: `perf(circom): rewrite VerifySubjectDN and VerifySerialNumber with SelectSubArray`

#### 3.3 Constraint-count regression guard

After the circuit reductions land, lock the savings in with a test that fails if a future change pushes constraint counts past a threshold.

**Files** (new)
- `wallet-unit-poc/circom/tests/circuits/constraint_count.test.ts` — compile each top-level circuit via circomkit's `WitnessTester`, read constraint count, assert `≤ THRESHOLD + 5 %`. Thresholds set from the final counts after Phase 3.2 lands.
- `wallet-unit-poc/circom/package.json` — add `"test:constraints": "NODE_OPTIONS=--max-old-space-size=16384 npx mocha tests/circuits/constraint_count.test.ts"`.

**Tests**
- Self-test: running against the current branch should pass. Regression is detected by introducing a deliberate constraint-bloating change and verifying the test fails.

**Docs**
- `wallet-unit-poc/circom/README.md` — document the regression guard and how to update thresholds when intentionally increasing constraint count.
- `.github/workflows/circom-tests.yaml` (from Phase 1) — add a step to run `yarn test:constraints` in the `circuit-tests` job.
- `CLAUDE.md` — add the new script to the "Circom Circuits" build commands list.

**Commit**: `test(circom): lock constraint counts with regression guard`

### Phase 4 — Track 2: remaining prover optimizations

Lands after Phase 3 so ad-hoc benchmark numbers reflect the combined effect. Each phase is independent unless noted.

#### 4.1 Skip R1CS load during prove (use proving key shape instead)

**Key observation**: `SatisfyingAssignment::enforce` in Spartan2 (`src/bellpepper/solver.rs:70–78`) is a **no-op**:
```rust
fn enforce<...>(&mut self, _: A, _a: LA, _b: LB, _c: LC) {
    // Do nothing: we don't care about linear-combination evaluations in this context.
}
```
`circom_scotia::synthesize` (`src/lib.rs`) only touches R1CS for three things: (a) `num_inputs` count for `alloc_input` loop, (b) `num_aux` count for `alloc` loop, (c) `constraints` iteration feeding `cs.enforce` — which is pure waste during prove because enforce is a no-op, yet it still iterates all ~2.5 M constraints and allocates `LinearCombination`s for each.

So during prove we need **zero** R1CS data: `num_inputs = T::NUM_PUBLIC + 1` (the `+1` accounts for the constant-1 at wire 0); `num_aux = witness.len() - num_inputs`. The proving key's `pk.S` (already loaded, referenced at `prover.rs:106`) carries the constraint shape for Spartan's own use. The circuit's `synthesize` no longer needs to construct it.

**Design**
- Setup phase (`ShapeCS`): keep `load_r1cs_mmap` + `circom_scotia::synthesize(cs, r1cs, None)` — Spartan2 needs full constraint shape here. This runs once per setup, not per prove.
- Prove phase (`SatisfyingAssignment`): replace with a minimal walk that calls `cs.alloc_input` for indices `1..num_inputs` and `cs.alloc` for indices `0..num_aux`, sourcing values from the cached witness. No R1CS load, no constraint iteration.

**Files**
- `wallet-unit-poc/ecdsa-spartan2/src/circuits/sha256rsa_circuit.rs` — split `synthesize` into `synthesize_shape` (setup) and `synthesize_assignment` (prove). The prove path drops `load_r1cs_mmap`, drops `circom_scotia::synthesize`, and loops directly on witness indices. Add a debug assertion: during setup, record `(num_inputs, num_aux)` seen from R1CS in a `OnceLock`, and during prove verify `witness.len() == num_inputs + num_aux` — catches NUM_PUBLIC mismatches.
- No change to `Cargo.toml` — no new deps.

**Tests**
- `cargo test --release` — existing `fixture_consistency` and E2E flow must pass. Add a focused unit test that runs setup + prove + verify on a trivial fixture and asserts the proof verifies (round-trip is the backstop).
- Ad-hoc benchmark of `cert-chain prove`: expect **100–300 MB** peak RSS reduction (no R1CS in memory during prove) and **significant** prove-time reduction (no 2.5 M-iteration constraint loop). Capture `setup_ms`, `prove_ms`, peak RSS in the PR description.

**Docs**
- Inline comment on the prove-phase branch citing `SatisfyingAssignment::enforce` no-op behavior and why the R1CS can be skipped — critical for future maintainers to not "add back" the R1CS load thinking it's missing.
- `wallet-unit-poc/ecdsa-spartan2/README.md` — document under "Performance" that prove-path memory footprint excludes R1CS.

**Risks**
- If a future Spartan2 version makes `SatisfyingAssignment::enforce` non-trivial, the shortcut breaks. Mitigation: debug assertion on witness-length invariant; CI end-to-end prove+verify catches any divergence; add a `tests/spartan_solver_contract.rs` test that calls the solver's `enforce` with a poison LC and asserts it's accepted (contract test).
- If `NUM_PUBLIC` is ever mis-stated for a circuit, the new path mis-counts inputs vs aux. Mitigation: the debug assertion captures the R1CS-derived counts at setup time and compares against `T::NUM_PUBLIC` — mismatch fails loudly.

**Commit**: `perf(ecdsa-spartan2): skip R1CS during prove — SatisfyingAssignment::enforce is no-op`

#### 4.2 Eliminate the witness clone

`get_or_generate_witness` (line 810) returns `witness.clone()` on every call — a full `Vec<Scalar>` copy (~50–100 MB for cert_chain). Wrap in `Arc<Vec<Scalar>>` so the cache returns a cheap `Arc::clone`. At the call site, `circom_scotia::synthesize` takes `Option<Vec<Scalar>>`; use `Arc::try_unwrap` (single-owner fast path, falls back to clone for the rare shared case).

**Files**
- `wallet-unit-poc/ecdsa-spartan2/src/circuits/sha256rsa_circuit.rs` — change `cached_witness` type to `Arc<Mutex<Option<Arc<Vec<Scalar>>>>>`; update `get_or_generate_witness`, `public_values`, and `warm_witness_cache`.

**Tests**
- `cargo test --release`. Measure peak RSS on `cert-chain prove` via `/usr/bin/time -l`; expect 50–100 MB reduction.

**Docs**
- Intent comment on the `Arc` wrapping.

**Commit**: `perf(ecdsa-spartan2): share witness via Arc instead of cloning`

#### 4.3 Release profile + streaming serialization + constant-time pk_commit

Three small, independent changes bundled because they touch different files and each is trivial.

**Files**
- `wallet-unit-poc/ecdsa-spartan2/Cargo.toml` — extend `[profile.release]` with `opt-level = 3`, `lto = "thin"`, `codegen-units = 1`. Keep `debug = true` (profiling symbols). Add `subtle = "2"` to `[dependencies]`.
- `wallet-unit-poc/ecdsa-spartan2/src/setup.rs` — replace the `bincode::serialize(x)? + write_all(&bytes)` pattern in `save_keys` (lines 37–45), `save_proof` (125–127), `save_instance` (140–142), `save_witness` (155–157), `save_shared_blinds` (107–109) with `bincode::serialize_into(BufWriter::new(file), x)?`. Add `use std::io::BufWriter;`.
- `wallet-unit-poc/ecdsa-spartan2/src/main.rs:244` — replace `pk_commit_a == pk_commit_b` with `subtle::ConstantTimeEq::ct_eq(pk_commit_a.to_repr().as_ref(), pk_commit_b.to_repr().as_ref()).unwrap_u8() == 1`. Keep the existing debug log unchanged.

**Tests**
- `cargo test --release`. Confirm saved-file sha256 matches before/after for `save_keys` output (bincode is deterministic).
- `cargo run --release -- link-verify` still passes on matching / rejects on mismatching pk_commit.

**Docs**
- `wallet-unit-poc/ecdsa-spartan2/README.md` — note the release-profile tuning and ct-compare in a "Security and performance" section.

**Commit**: `perf(ecdsa-spartan2): release profile, streaming serialize, constant-time pk_commit`

## PR & Branch Map

Phase 0 lands as a local commit on `refactor/circuit-optimization` (no PR). Phase 1 branches off and targets `refactor/circuit-optimization`. Phase 2 is a force-pushed rebase of `refactor/circuit-optimization` onto the latest `main`. Phases 3.x and 4.x branch off `refactor/circuit-optimization` and target it. The final lift of the whole branch onto `main` is a separate, out-of-scope PR opened once all phases are merged.

| Phase | Branch | PR title |
|---|---|---|
| 0 | (local commit on `refactor/circuit-optimization`) | — no PR |
| 1 | `ci/split-workflows` | `ci: split mobile-tests.yaml into circom-tests, rust-tests, mobile-tests` |
| 2 | `refactor/circuit-optimization` (rebased) | `refactor: rebase onto main; absorb PR#23 reader.rs + witnesscalc thread` |
| 3.1 | `perf/circom-tighten-cert-chain-maxmsg` | `perf(circom): tighten cert_chain maxMessageLength to 1024` |
| 3.2 | `perf/circom-selectsubarray-rewrite` | `perf(circom): rewrite VerifySubjectDN and VerifySerialNumber with SelectSubArray` |
| 3.3 | `test/circom-constraint-regression-guard` | `test(circom): lock constraint counts with regression guard` |
| 4.1 | `perf/ecdsa-spartan2-skip-r1cs-prove` | `perf(ecdsa-spartan2): skip R1CS during prove — SatisfyingAssignment::enforce is no-op` |
| 4.2 | `perf/ecdsa-spartan2-arc-witness` | `perf(ecdsa-spartan2): share witness via Arc instead of cloning` |
| 4.3 | `perf/ecdsa-spartan2-release-profile` | `perf(ecdsa-spartan2): release profile, streaming serialize, constant-time pk_commit` |

## Dependency Graph

```
  Phase 0 (local docs) ──── committed on refactor/circuit-optimization; no PR
         │
         ▼
  Phase 1 (CI refactor) ─── establishes clean per-area workflows before any code change
         │
         ▼
  Phase 2 (rebase onto main; absorbs PR#23)
         │
         ├───────────────────────┐
         ▼                       ▼
  Phase 3 (circom)         Phase 4 (remaining prover)
  3.1 maxMsg 1024          4.1 skip R1CS during prove ◄── uses Phase 2's mmap loader for setup
  3.2 SelectSubArray       4.2 Arc witness ◄──────── independent
  3.3 constraint guard     4.3 profile/serialize/ct ◄── independent
```

Within Phase 3, phases are serial (3.1 → 3.2 → 3.3). Within Phase 4, 4.1/4.2/4.3 are independent but gated by the manual review between PRs. Phases 3 and 4 don't overlap in files, so they could theoretically interleave — but because of the **manual gate between every PR**, the actual cadence is "one phase in flight at a time". Suggested execution order: Phase 0 → 1 → 2 → 3.1 → 3.2 → 3.3 → 4.1 → 4.2 → 4.3.

## Verification Plan

Run after every phase. E2E is the gold standard.

1. **Constraint counts** (circom): `yarn compile:all` then `snarkjs r1cs info build/<name>/<name>.r1cs`. Record counts per circuit in the commit message.
2. **Witness tests** (circom): `NODE_OPTIONS=--max-old-space-size=16384 yarn test` — all suites pass, including `pk_commit_linking.test.ts`.
3. **Rust unit tests**: `cargo test --release`, `cargo test --release --features cert_chain_rs2048`, `cargo test --release --features cert_chain_rs4096`, `cargo test --release --features device_sig_rs2048`. All pass, `fixture_consistency` verifies signatures over the preserved `DEFAULT_TBS`.
4. **End-to-end split flow** (rs2048, then rs4096):
   ```
   cargo run --release -- generate-split-input [--cert-chain-4096]
   cargo run --release --features cert_chain_rs2048 -- cert-chain setup
   cargo run --release --features cert_chain_rs2048 -- cert-chain prove   --input circom/inputs/cert_chain_rs2048/input.json
   cargo run --release --features cert_chain_rs2048 -- cert-chain verify
   cargo run --release --features device_sig_rs2048 -- device-sig setup
   cargo run --release --features device_sig_rs2048 -- device-sig prove   --input circom/inputs/device_sig_rs2048/input.json
   cargo run --release --features device_sig_rs2048 -- device-sig verify
   cargo run --release -- link-verify
   ```
5. **CI**: after Phase 1 lands, `circom-tests.yaml` covers steps 1–2 and `rust-tests.yaml` covers steps 3–4. Phase 3.3 wires the `yarn test:constraints` regression guard into `circom-tests.yaml`.
6. **Ad-hoc benchmarks per phase**: run the existing `benchmark` subcommand before and after each code-touching phase; capture `setup_ms`, `prove_ms`, `verify_ms`, and peak RSS (via `/usr/bin/time -l` on macOS). Record in the PR description — no dedicated benchmark harness is added.
7. **macOS SIGSEGV check** (Phase 2): on macOS, run `cargo run --release --features cert_chain_rs4096 -- cert-chain prove` — confirm no crash. No automated macOS CI exists; spot-check locally.

## Risks and Tradeoffs

| Risk | Phase | Mitigation |
|---|---|---|
| CI refactor drops a job needed for downstream branch protection | 1 | Before opening the PR, cross-check every job in the old `mobile-tests.yaml` against the three new workflows; a quick diff of `jobs:` keys confirms coverage. Branch protection changes (required-checks list) are user-driven and tracked separately. |
| Mobile workflow kept broken confuses future contributors | 1 | `mobile-tests.yaml` gets a README-style header comment explaining "this workflow currently covers only the legacy mobile crate; full migration is in the follow-up plan at `docs/...`". |
| Phase 2 force-push on `refactor/circuit-optimization` could clobber unseen remote work | 2 | Use `git push --force-with-lease` (not `--force`); confirm no new commits landed on the remote since last fetch. |
| Unknown MOICA cert >1024 bytes crashes witness gen | 3.1 | Bundled fixture is 893 bytes; MOICA v3 spec caps TBS at ~600. 14 % margin. If a real card exceeds, bump to 1280 and regenerate. |
| `SelectSubArray` bug or semantic mismatch | 3.2 | Directly tested against the existing IsEqual-based impl (run both in a test harness on identical inputs, assert witness-equivalent). `pk_commit_linking` end-to-end is the backstop. |
| Future Spartan2 version makes `SatisfyingAssignment::enforce` non-trivial, breaking the R1CS skip | 4.1 | Debug assertion on witness-length invariant + contract test against solver's `enforce` semantics; E2E prove+verify in CI catches any divergence immediately. |
| Release profile `lto = "thin"` slows compile | 4.3 | Acceptable on CI; dev builds use `[profile.dev]` unaffected. |

## Follow-up Work (Explicitly Out of Scope)

These are called out so reviewers know they've been considered and deferred:

- **Mobile crate migration** — `wallet-unit-poc/mobile/Cargo.toml` references the deleted `sha256rsa4096` feature and `Rs256FidoCircuit`; `cargo check` fails. Needs `CertChainRsa4096Circuit` + `DeviceSigRsa2048` API migration, async wrapper for Flutter/uniffi FFI. Blocks true mobile proving. Phase 1 isolates mobile's CI so it doesn't gate circuit/Rust landings; the actual crate fix is deferred to a follow-up plan.
- **SDK WASM rewrite** — `wallet-unit-poc/openac-sdk/wasm/src/lib.rs` references nonexistent `PrepareCircuit` / `ShowCircuit`. Needs a rewrite to the split circuits with a multi-threaded WASM harness (SharedArrayBuffer + `wasm-bindgen-rayon`), else the browser OOM from PR #20 isn't actually fixed end-to-end.
- **SMT depth reduction** — retained at 128 per the key-space decision.
- **device_sig `maxMessageLength` tightening** — broader roadmap item; deferred until HiPKI payload bounds are finalized.

## Critical Files

Circuit:
- `wallet-unit-poc/circom/circuits.json`
- `wallet-unit-poc/circom/circuits/utils/utils.circom` (VerifySubjectDN, VerifySerialNumber)
- `wallet-unit-poc/circom/circuits/cert_chain.circom`
- `wallet-unit-poc/circom/node_modules/@zk-email/circuits/utils/array.circom` (SelectSubArray, VarShiftLeft — already imported via `rs256.circom`)
- `wallet-unit-poc/circom/inputs/cert_chain_rs{2048,4096}/input.json`
- `wallet-unit-poc/circom/tests/circuits/` (all)

Rust:
- `wallet-unit-poc/ecdsa-spartan2/src/circuits/sha256rsa_circuit.rs` (lines 76, 798, 814, 847, 856)
- `wallet-unit-poc/ecdsa-spartan2/src/main.rs:244` (pk_commit compare)
- `wallet-unit-poc/ecdsa-spartan2/src/setup.rs` (serialize patterns)
- `wallet-unit-poc/ecdsa-spartan2/src/prover.rs` (prove_circuit_with_pk)
- `wallet-unit-poc/ecdsa-spartan2/src/circuits/split_circuits.rs` (MAX_MESSAGE_LENGTH)
- `wallet-unit-poc/ecdsa-spartan2/Cargo.toml` (profile, deps)
- `wallet-unit-poc/ecdsa-spartan2/src/lib.rs` (module exports)
- `wallet-unit-poc/ecdsa-spartan2/src/reader.rs` (new, via Phase 2 rebase)
- `wallet-unit-poc/ecdsa-spartan2/examples/generate_fixtures.rs` (regeneration)

CI / Docs:
- `.github/workflows/circom-tests.yaml` (new, Phase 1)
- `.github/workflows/rust-tests.yaml` (new, Phase 1)
- `.github/workflows/mobile-tests.yaml` (narrowed, Phase 1)
- `CLAUDE.md` (CI section + new commands per phase)
- `wallet-unit-poc/circom/README.md`, `wallet-unit-poc/ecdsa-spartan2/README.md` (updated per phase)
- `wallet-unit-poc/docs/circuit-rust-optimization.md` (new, Phase 0 — this file)
