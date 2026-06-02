# Ghidra RE Skill Learnings

Append-only log of non-obvious discoveries from Ghidra reverse engineering sessions.

## 2026-06-02: v5.12.0 headless quirks + cross-binary offset porting
- **Context**: RE of 32-bit Windows DLLs on the v5.12.0 headless server.
- **Learning**: (1) `search_strings` returns nothing without `encoding:"ascii"`.
  (2) v5.x headless auto-analysis can NPE (`GhidraScriptUtil.bundleHost null`) and roll
  back function_count, but partial analysis persists and is usable. (3) `reanalyze`
  "Auto-analysis failed" == analysis already in progress. (4) `load_program` times out
  at 30s but continues server-side. Full list in [reference/gotchas.md](reference/gotchas.md).
- **Rule**: Always pass `encoding:"ascii"` to `search_strings`; poll `analysis_status`
  after `load_program`; check the server log for the bundleHost NPE before assuming OOM.
- **Bonus**: Porting struct offsets between two builds of one codebase — anchor ONE
  global via a unique nearby string, then apply the known internal struct deltas and
  verify each lands sanely. Survives base shifts.

## 2026-06-02: RE the EXACT binary the live target maps
- **Context**: Live `/proc/<pid>/mem` work against a Windows DLL; offsets read all-zero
  even though the process was clearly running.
- **Learning**: I'd RE'd a local copy of the DLL, but the process mapped a different
  build of the same-named DLL (different size/md5) → offsets invalid.
- **Rule**: Before trusting offsets against a live process, `md5sum`/size-compare the
  analyzed file vs the one in `/proc/<pid>/maps`. RE the exact mapped binary (or pin the
  target's version). All-zero reads at a good base ⇒ wrong binary or pre-init, not
  necessarily wrong math. Full list in [reference/gotchas.md](reference/gotchas.md).
