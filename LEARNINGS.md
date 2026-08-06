# Ghidra RE Skill Learnings — STAGING, not a destination

Scratch buffer for non-obvious discoveries from RE sessions. **A learning that sits here is
not doing any work** — nothing reads this file during a session.

**The job is to APPLY it into the skill, then delete it from here:**

| Kind of learning | Where it belongs |
|---|---|
| A rule to follow every session | `SKILL.md` → General Rules |
| "X looks like Y but is actually Z" | `SKILL.md` → Critical Pitfalls |
| A symptom you can observe | `SKILL.md` → Error Handling table (symptom / diagnosis / fix) |
| Depth on loading, addressing, searching | `reference/headless-operations.md` |
| A tool misbehaving | `reference/gotchas.md` |
| Workflow depth | the matching `reference/*.md` |

Entries below are **unapplied backlog**. Fold them in and remove them. Do not let this file
grow — length here is a measure of neglect, not of knowledge.

⚠ Anything in `SKILL.md` that says "see LEARNINGS" is itself a bug: the knowledge should be
inline where it is needed, not a pointer into staging.

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

## 2026-06-04 (#2): "process gone" ≠ "crashed" — triage clean-exit vs fault BEFORE you RE, and sniff cmd_text for the trigger
- **Context**: A multi-worker Wine game-client sweep reported many "crashed after connect (state 4)".
  An external watcher only knew the process had vanished from `/proc/<pid>/mem` (a short read = the
  mapping went away). The prior assumption was CPU-starvation memory faults under concurrency.
- **Learning**: (1) **A vanished `/proc/<pid>/mem` mapping has TWO causes that look identical from
  outside: a real fault (SIGSEGV→guest AV) and a CONTROLLED exit (`Sys_Quit`/`Host_Shutdown`).** Decide
  which BEFORE spending any RE — a clean exit has no crash to find. The discriminator is the guest's
  own stderr (`WINEDEBUG=+seh` to surface it): a fault shows a lone **`code=c0000005`** ("Unhandled
  exception"); a controlled exit shows **only** the `code=40010006` (`DBG_PRINTEXCEPTION_C` =
  OutputDebugString) **`Sys_Shutdown` audit storm** ("Missing shutdown function for …") and, if it
  wasn't even a `Sys_Error`, **no `Sys_Error`/`FATAL`/`Host_Error` string anywhere** in the window. The
  earlier entry noted "the lone c0000005 above the storm is the fault" — the complement is just as
  important: **storm with NO c0000005 ⇒ no crash; it quit on purpose.** (`dllMaps` empty at capture
  confirms full teardown.) This reframed a whole class of "concurrency crashes" as benign clean exits.
- **Corollary technique — find what TRIGGERS a clean guest exit by sniffing the command buffer.** A
  server's `svc_stufftext` (and any console-driven quit) lands in the engine's `cmd_text` sizebuf as
  plain command strings, executed within a frame or two. **Sub-frame poll `cmd_text` (data ptr +
  cursize) faster than the frame rate** (~15ms vs a 33ms frame at fps_max 30; positioned `pread` so it
  doesn't race the main reader) and dedup the lines that aren't yours. Here it caught the real
  stufftext (`retry`/`unpause`/`hideconsole`/`m_pitch`) and **exonerated** the "server forces
  `quit`/`record`" theory (no such command) — proving the exit was engine-internal at spawn, not
  server-driven. A suggestive shutdown artifact (an unclosed `demoheader.dmf`) was a red herring;
  the buffer sniff is what settled it.
- **Rule**: When something reports a process "crashed" but you only have "the mapping is gone," FIRST
  classify crash-vs-clean-exit from guest stderr (`+seh`: `c0000005` = fault; bare `40010006`
  `Sys_Shutdown` storm = controlled exit) — don't RE a non-crash. To attribute a clean *guest-driven*
  exit, sub-frame-sniff the engine command buffer for the triggering command before assuming a static
  cause; rule the server in/out by what it actually sends, not by a plausible artifact. See
  reference/dynamic-analysis.md §2–3.

## 2026-06-04 (#3): map the engine's quit machinery ONCE; don't attribute a static path to a phenomenon you haven't reproduced
- **Context**: Chasing "headless game client cleanly exits ~4-10s into a connect" (GoldSrc sw.dll). Goal: find WHERE/WHY the engine quits during spawn.
- **Learning**: (1) **Build the quit-map by working the teardown backward to its UNIQUE trigger, not forward from the spawn path.** A clean *full* shutdown = a specific teardown signature (here the "Missing shutdown function" memory-pool audit storm) that only runs on one engine run-state value. Find the global that holds run-state (xref the state machine / Host_Frame), find every WRITER of the quit value, and eliminate: most writers are init/command-handlers/other-state; usually exactly ONE in-frame code path sets the full-quit value. Here: full-quit run-state 3 ⇐ Host_Quit_f ⇐ the single in-frame `host_killtime` auto-quit at the tail of the host frame. Every other in-frame setter wrote the *restart/menu* value (2), and the key-handler sites are dead headless. This is a 30-minute map that turns any future "client vanished cleanly" into a 30-second triage.
- **Learning**: (2) **A static "this is the only code path that could do X" is necessary but NOT sufficient to claim it caused an observed X — confirm the inputs are actually present at runtime.** I correctly proved host_killtime→Host_Quit_f is the unique full-quit path, then over-reached and called the server malicious. Live `/proc/<pid>/mem` reads (host_killtime.value, run-state, sv.time) showed host_killtime stayed 0, run-state stayed "active", sv.time stayed 0 (so the compare can't even trip without a negative value). A user's retail-client cross-check (joins fine) was the tell the static path wasn't the cause. **META-CORRECTION (same session): I then concluded "doesn't reproduce at all" — WRONG AGAIN, because I'd tested only SERIALLY (one client). Running 4 clients in parallel reproduced it instantly — the failure mode was CPU contention, invisible to a single-client repro.** So the bug was real and reproducible, just only in the multi-worker regime. Lesson compounds: sample across the ACTUAL operating regime (here: concurrency) before declaring "reproduces" OR "doesn't" — a convenient single-instance repro is not the regime the bug lives in. Final classification came from a full-log `c0000005` scan (the 160-line tail is useless under +seh — each engine print balloons to ~5 trace lines, pushing any fault out of the window): all ~15 contention exits were CLEAN (no AV) — orderly engine shutdowns, not memory faults.
- **Learning**: (3) **A clean orderly-shutdown signature in the log does NOT by itself prove a voluntary quit** — a top-level SEH/`__except` handler can catch a real AV and *then* run the orderly teardown (same storm). Always look for a `c0000005`/"Unhandled exception" in a `+seh` Wine log before concluding "it quit on purpose"; absence in a truncated 160-line tail is not absence.
- **Learning**: (4) The `cl_filterstuffcmd` blocklist is the engine's OWN enumeration of "commands too dangerous to accept from a server" — anything locally-dangerous that's NOT on it (e.g. `host_killtime`) is latent client-attack surface worth cataloguing even when no server currently abuses it.
- **Rule**: For "process vanished" on a headless target, instrument the live state globals (read them every <frame via /proc/mem) BEFORE theorizing a static cause; let the runtime values pick among the candidate paths the static map produced. Map once, measure, then attribute — never attribute from the map alone.
- **Tooling note**: GhidraMCPHeadlessServer (com.xebyte) cannot `import_file` ("requires GUI mode"); import via `analyzeHeadless <projdir> <name> -import <bin> -overwrite` on the CLI, then point the server at it with `open_project`+`load_program_from_project`. Put the project OUTSIDE any Docker bind-mount (the 9p divergence ate the prior `research/cs16-re`).

## 2026-07-16: `current_program` is a STALE NAME — /load_program does not switch to it, and it survives close
- **Context**: Diffing two CSNZ `hw.dll` builds (Steam vs a third-party private server). Both files are literally named `hw.dll`.
- **Learning**: (1) **`/load_program` (and the `load_program` tool) does NOT make the loaded program current.** The server keeps a separate `current_program` *name*, and every tool that omits `program=` resolves against it. After loading a second binary, `list_open_programs` showed the new program with `is_current: false` while `current_program` still named the old one — so `list_strings`/`get_xrefs_to`/`decompile_function` all silently kept answering **from the previous binary**. The results look perfectly plausible (same addresses, same xrefs) because they ARE real — just from the wrong file. Nothing errors.
- **Learning**: (2) **`get_current_program_info` returns CACHED data for a program that no longer exists.** After `/close_program name=hw.dll` succeeded and only `hw_csns.dll` remained open, `get_current_program_info` still reported `name: hw.dll`, the closed binary's `executable_path`, and its `function_count`/`memory_size`. It is NOT a source of truth. `list_open_programs` is — and its `count`/`is_current`/`current_program` fields disagreeing with each other is the tell.
- **Learning**: (3) **Two binaries with the same basename collide.** Loading the second returned `{"success": true}`, but only one program ever existed (a second `/close_program name=hw.dll` said "Program not found"). Same-name loads are silently lossy — copy to distinct filenames (`hw_steam.dll`, `hw_csns.dll`) before loading.
- **Learning**: (4) On this v4.0.0-headless server `run_analysis` is a **no-op** on a `/load_program`'d program: returned `duration_ms: 1, new_functions: 0` against a 271-function minimal load. A previously-analyzed program returning ~89k functions in ~300ms is likewise reporting a *cached* count, not a fresh pass. So `run_analysis` "succeeding" instantly proves nothing.
- **Learning**: (5) The minimal-load workaround from `reference/headless-operations.md` works fine without any analysis: `search_byte_patterns(<ascii hex of the string>)` -> VA, then `search_byte_patterns(<VA as little-endian>)` -> the `PUSH <straddr>` site, then `read_memory` around it and decode by hand. Recovered a full id->name table this way in 4 calls, no analysis, no hang risk.
- **Rule**: In ANY multi-binary session: (a) copy inputs to **distinct basenames** first; (b) after loading, call **`switch_program(name)`** — loading alone does not switch; (c) verify with **`list_open_programs`** (`is_current: true` on the one you want), NEVER `get_current_program_info`, which lies about closed programs; (d) prefer passing **`program=` explicitly** on every call so `current_program` can't matter. If two queries against "different" binaries return byte-identical addresses, assume you are reading one binary until `list_open_programs` proves otherwise.
