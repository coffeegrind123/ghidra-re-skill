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

## 2026-06-04: gdb first-chance SIGSEGV beats winedbg for HANDLED Wine crashes; an "exoneration" bisect is only valid if it TOGGLES the suspect
- **Context**: A multi-instance sweep of a 32-bit Wine game client showed "0/N playable, all
  crashed after connect." Suspicion fell on that session's own engine patches (a multi-DLL rebase +
  a code-cave hooked into a hash routine). Goal: confirm/deny the regression and find the crash.
- **Learning**: (1) **The change WAS the cause — and an earlier bisect wrongly "exonerated" it
  because it never actually toggled the suspect.** That bisect declared the crash "pre-existing":
  the rebase was reverted, but the cave was assumed *inert* on the failing targets (reasoning "those
  servers don't exercise the hooked path") instead of being un-hooked and re-tested. It does exercise
  it. Re-running with the hook ON vs OFF (the real toggle) crashed 6/6 vs 0/6 — squarely the cave.
  Root cause: a **one-hex-digit typo in the cave's jmp rel32** (target off by 0x100000) sent the hook
  into the middle of a live function with no prologue → stack smash. Because the cave *body* never
  executed, every "variant" of the body crashed identically, which had looked like "the body is
  innocent / it's pre-existing." **Two lessons: (a) a bisect that ASSUMES a change is inert hasn't
  tested it — only an actual ON/OFF toggle of that exact change exonerates it; (b) an identical crash
  across edits to a region can mean that region never runs (a mis-aimed hook/jump), not that the
  region is correct.** Also real and useful: a single hand-picked "works" target masks population-wide
  breakage — sweep across known-good AND known-bad targets. (2) **winedbg cannot catch a first-chance
  exception the guest HANDLES.** When the engine's
  `SetUnhandledExceptionFilter`/`__try` catches the AV and exits cleanly, `winedbg --auto` (2nd-chance
  only) and interactive winedbg (passes 1st-chance silently) both see nothing — the process just
  "terminates." **gdb attached to the Wine process catches the host SIGSEGV first-chance** (Wine
  raises SIGSEGV before building the guest exception): `gdb -p <pid> --batch -x script` with
  `catch signal SIGSEGV` + `commands … x/80xw $esp … continue … end`. (3) **Don't NOP the guest's
  `SetUnhandledExceptionFilter` to force the AV unhandled** — in MSVCRT-static binaries those call
  sites are CRT internals (install + restore); NOPping them corrupts CRT EH and breaks boot.
  (4) **`eip` inside the thread STACK range = a stack-smash** (control ran into stack data); the
  write-to-NULL it dies on is incidental. Read the call chain from `x/80xw $esp`, but only words in a
  module's **.text** range are return addresses — a word in `.rdata`/IAT is data (disassembles to
  garbage like repeating `d0 01`). The real ret, disassembled just-before, reveals the `call [reg+N]`
  vtable dispatch that made the frame. (5) The post-crash `code=40010006` "Missing shutdown
  function …" storm is the engine's normal `Sys_Shutdown` audit (runs on ANY quit), NOT the crash —
  the lone `code=c0000005` above it is the fault.
- **Rule**: To clear a suspected change, TOGGLE it (apply ⇄ revert the exact bytes/patch) and
  re-test — never argue it's inert from "that path isn't exercised." Sweep across known-good AND
  known-bad targets so one hand-picked target doesn't mask population-wide breakage. When edits to a
  code region all crash identically, suspect the region never executes (a mis-aimed hook/jmp rel32)
  before concluding the region is correct — verify the hook lands where you think by disassembling
  its jump target. To get a backtrace for a Wine crash the guest catches, attach **gdb** (or a ctypes
  ptrace tracer) and catch SIGSEGV first-chance — not winedbg. See reference/dynamic-analysis.md §2.
