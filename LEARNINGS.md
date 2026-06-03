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

## 2026-06-03: catch-all vtable trap silently corrupts the stack for arg-taking slots
- **Context**: Headless game-client RE — a clean `htmlctl.dll` stub (factory + vtable of
  traps). Most servers fine; `<server-ip>` (HTML MOTD) crashed at spawn with a call
  through garbage (`0x0D439C61` / `EIP=0`), far from the real cause.
- **Learning**: The generic catch-all `vtbl_trap(void *self)` returns 0 with `ret 0` (cleans 0
  bytes) — correct only for 0-arg methods. A trapped method WITH stack args leaks those bytes;
  one leak survives, but a path that re-fires a trapped 2-arg slot across reconnect cycles
  accumulates leaks → stack corruption → call-through-garbage crash. The crash EIP is the
  garbage target, not the caller.
- **Rule**: A stub vtable trap can't self-correct its `ret N`. Find the call site via the
  trap's `__builtin_return_address(0)` log (or a ptrace SIGSEGV tracer for the return addr on
  the stack), `objdump` the caller, count pushes before `call [reg+N]` → implement that slot
  with the correct `ret N` (body may still `return 0`; it's the cleanup that matters). Do NOT
  fix by returning a non-NULL object unless the consumer needs one — that just moves the crash
  to the methods it then calls on that object. Also: winedbg JIT (`AeDebug Auto=1`) can't be
  used on engines that throw benign first-chance SEH during init (it breaks boot); and the
  Ghidra MCP headless server cannot `import_file`/list project files (GUI-only) — use objdump
  for binaries not already open. See reference/dynamic-analysis.md §2.

## 2026-06-03: load_program works headless (partial analysis); runtime-first crash RE
- **Context**: RE of a large (~1.5 MB) 32-bit Windows engine DLL on v5.12.0 headless to diagnose
  an intermittent loader/relocation crash and to locate a file-hash routine for patching.
- **Learning**: (1) **`load_program(file=…)` IS an MCP tool now** (earlier notes said the MCP
  "cannot import" — that was `import_file`/project ops). It loads the PE fast but with only
  ~exports analyzed (a 1.5 MB DLL → ~300 funcs), so a target address has NO function:
  `decompile_function` says "No function found". Fix: `create_function(addr)` then
  `decompile_function` — do NOT `run_analysis` (hangs minutes). `get_function_callers`/xrefs return
  nothing on a load_program'd program (no xref pass); `save_program`/`list_project_files` are
  GUI-only → annotations are session-only. (2) An intermittent page-commit boot crash was diagnosed
  **without Ghidra**: `/proc/maps` showed several DLLs relocated off their preferred base, and the
  PE `DllCharacteristics` showed some had `DYNAMICBASE`; the fault is concurrency-amplified (clean
  solo, frequent under N concurrent processes). The fix was a PE rewrite (rebase), not Ghidra.
- **Rule**: For "what does function X at addr A do", reach for `load_program` + `create_function(A)`
  + `decompile_function(A)` — fast, no project, no full-analysis hang. Use `import_file` only when
  you genuinely need whole-program xrefs. For loader/relocation crashes (faults in the OS/loader,
  not the target's code), the decisive evidence is RUNTIME (`/proc/maps` load addr vs PE ImageBase,
  `DllCharacteristics` DYNAMICBASE) — Ghidra static analysis won't surface a loader fault. See
  reference/dynamic-analysis.md §3 and headless-operations.md.
