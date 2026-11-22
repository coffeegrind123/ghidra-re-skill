# Ghidra RE Skill Learnings: STAGING, not a destination

Scratch buffer for non-obvious discoveries from RE sessions. A learning that sits here does no
work: nothing reads this file during a session.

**Apply it into the skill, then delete it from here:**

| Kind of learning | Where it belongs |
|---|---|
| A rule for every session | `SKILL.md` -> General Rules |
| "X looks like Y but is actually Z" | `SKILL.md` -> Critical Pitfalls |
| An observable symptom | `SKILL.md` -> Error Handling table |
| Loading, addressing, searching | `reference/headless-operations.md` |
| A tool misbehaving | `reference/gotchas.md` |
| Workflow depth | the matching `reference/*.md` |

Anything in `SKILL.md` that says "see LEARNINGS" is a bug: inline the knowledge where it is
needed.

## 2026-11-23: skill moved to ghidra-mcp-next

- **Context**: The skill was rewritten for the ghidra-mcp-next server (headless, pyghidra,
  transaction-based). Everything about the previous server (its versions, bridge, HTTP
  endpoints, tool groups, current-program switching, Java inline scripts, server-side
  Hungarian prefixing) was removed, along with the entries here that described it.
- **Measured on Ghidra 12.0.3**:
  - `open_database` returns at once with a database id; `wait_for_analysis` must come first.
    Several databases can be open; each call names one. No current program.
  - `batch`: up to 100 ops in one transaction; any failure rolls back all and names
    `op_index`; success is one undo step `MCP: <label>`; `$N.path` / `${N.path}` references;
    `if_revision` -> `TargetChanged`; `operation_id` -> `replayed: true`; `dry_run` rolls back.
    Lifecycle tools, undo/redo, `run_auto_analysis`, `reanalyze_range`, `set_image_base` and
    `run_ghidra_script` are refused inside a batch (`InvalidOp`).
  - `execute`: CPython 3 via pyghidra with `program`, `flat`, `monitor`, `toAddr`,
    `decompile`, `tools.<name>`; one transaction; `read_only=true` always rolls back; timeout
    checked between Python lines; stdout 64 KiB, result 256 KiB.
  - `run_ghidra_script` runs existing Java/Python GhidraScripts in one transaction, no time
    limit.
  - Plate comments survive `set_function_prototype` (the old "prototype wipes plate comments"
    ordering rule does not apply).
  - The prototype parser knows Ghidra builtins but not `uint8_t`/`size_t` without a type
    archive: `int f(uint8_t *buf, size_t len)` -> C ParseException; `int f(byte *buf, uint len)`
    works.
  - No server-side Hungarian prefixing; the agent applies prefixes everywhere.
  - Ghidra Server programs are read-only until `checkout_file`; `save_database` fails with
    `ReadOnly` before that.
  - `run_auto_analysis` really analyzes and reports `functions_before/after` and `seconds`.
  - `score_documentation` ranks functions worst-first by missing name, prototype, plate
    comment, parameters and (optionally) locals.
- **Rule**: Applied throughout `SKILL.md` and `reference/`. Delete this entry once a session
  has confirmed the skill works end to end on the new server.

## 2026-06-02: reverse the EXACT binary the live target maps

- **Learning**: Offsets from a local copy of a DLL read all-zero against a running process
  because the process mapped a different build of the same-named DLL (different size and md5).
- **Rule**: Before trusting offsets against a live process, compare `md5sum`/size of the
  analyzed file with the one in `/proc/<pid>/maps`. All-zero reads at a good base mean wrong
  binary or pre-init, not necessarily wrong math. Applied in `reference/gotchas.md`.
- **Bonus**: Porting struct offsets between two builds of one codebase: anchor one global via
  a unique nearby string, apply the known internal struct deltas, verify each lands sanely.

## 2026-06-03: a catch-all vtable trap corrupts the stack for slots that take arguments

- **Learning**: A stub DLL's generic `vtbl_trap(void *self)` returns with `ret 0`, correct only
  for 0-argument methods. A trapped method with stack arguments leaks those bytes each call; a
  path that re-fires it accumulates leaks until a call through garbage crashes far from the
  cause. The crash EIP is the garbage target, not the caller.
- **Rule**: Find the call site from the trap's `__builtin_return_address(0)` log, disassemble
  the caller, count the pushes before `call [reg+N]`, and implement that slot with the right
  `ret N`. Do not return a non-NULL object unless the consumer needs one. winedbg JIT
  (`AeDebug Auto=1`) breaks applications that raise benign first-chance SEH during init.
  Applied in `reference/dynamic-analysis.md` §3.

## 2026-06-03: loader and relocation crashes are runtime evidence, not static

- **Learning**: An intermittent page-commit crash at startup was diagnosed without Ghidra:
  `/proc/<pid>/maps` showed several DLLs relocated off their preferred base, and their PE
  `DllCharacteristics` had `DYNAMICBASE`. It was concurrency-amplified (clean alone, frequent
  under N parallel processes). The fix was a PE rebase.
- **Rule**: For faults in the OS loader rather than the target's code, compare runtime load
  addresses with PE `ImageBase` first. Applied in `reference/dynamic-analysis.md` §3.

## 2026-06-04: a bisect only exonerates a change if it TOGGLES it; gdb catches handled Wine crashes

- **Learning**: A bisect declared a crash "pre-existing" after reverting one patch but assuming
  a second (a hooked code cave) was inert. Toggling the hook on and off gave 6/6 crashes vs
  0/6. Cause: a one-digit typo in the cave's `jmp rel32` sent control into the middle of a live
  function. Every edit to the cave body crashed identically because the body never ran.
- **Learning**: winedbg cannot catch a first-chance exception the guest handles. gdb attached
  to the Wine process catches the host SIGSEGV first (`catch signal SIGSEGV` + `x/80xw $esp`).
  EIP inside the thread stack range means a stack smash. Only stack words inside a module's
  `.text` are return addresses.
- **Rule**: To clear a suspect change, toggle exactly that change and re-test. Sweep known-good
  and known-bad targets. When all edits to a region crash the same way, check the region runs
  at all (disassemble the hook's jump target). Applied in `reference/dynamic-analysis.md` §2.

## 2026-06-04: "process gone" is not "crashed"; classify before reversing

- **Learning**: A vanished `/proc/<pid>/mem` mapping has two causes that look the same from
  outside: a fault and a controlled exit. With `WINEDEBUG=+seh`, a fault shows a lone
  `code=c0000005`; a controlled exit shows only the `code=40010006` shutdown-audit storm and no
  fatal-error string. A top-level exception handler can catch a real fault and then run the
  orderly shutdown, so scan the whole log for `c0000005`, not a truncated tail.
- **Learning**: To find what triggers a clean guest-driven exit, poll the application's command
  buffer (data pointer + current size) faster than its frame rate through `/proc/<pid>/mem`
  and log commands that are not yours. This ruled the remote server in or out by what it
  actually sent.
- **Learning**: A static proof that "only path P can cause X" does not show P caused an observed
  X. Live reads of the globals P depends on showed it never fired. The failure reproduced only
  with several instances in parallel (CPU contention), not with one.
- **Rule**: Classify crash vs clean exit first. Instrument live state before attributing a
  static cause. Reproduce in the real operating regime (concurrency included) before saying
  "reproduces" or "does not". Applied in `reference/dynamic-analysis.md` §2-4.
