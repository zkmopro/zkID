# TODOS

## Update design doc with corrected artifact sizes and hybrid architecture

**Status:** Pending
**Priority:** Low
**Added:** 2026-04-01

The design doc at `~/.gstack/projects/zkmopro-zkID/moventsai-main-design-20260401-110353.md` has incorrect artifact sizes that were corrected during eng review:

| Artifact | Design Doc | Actual |
|----------|-----------|--------|
| Proving key | 260MB | 744MB |
| Verifying key | not mentioned | 744MB |
| R1CS | not mentioned | 636MB |
| Witness | 32MB | 128MB |
| circom WASM calc | not mentioned | 11MB |

Architecture also changed: browser-side Spartan2 proving is infeasible (rayon blocker + 1.5GB+ static data). Revised to hybrid approach (browser witnesses, server proves) with parallel workstream to fork Spartan2 and gate rayon for future browser proving.

**Depends on:** Nothing. Can be done anytime.
