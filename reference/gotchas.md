# Gotchas

Non-obvious failure modes: Ghidra behaviour, this server's transaction model, and RE practice.
Read this when a tool behaves unexpectedly. Promote durable rules into SKILL.md.

## Transactions, batch and execute

- **One failing op discards the whole batch.** That is the point, but it means a single
  phantom variable or stale name costs every other edit in the batch. The error carries
  `op_index`, `tool` and `error_type`: fix that op and resend. `dry_run=true` checks a plan
  without keeping anything.
- **A renamed symbol's old name is gone inside the same batch.** `FUN_00401000` used as an
  address after `rename_function` fails with `NotFound`. Use `"$N.address"` from the rename.
- **`$N` must point backwards.** A reference to the current or a later op fails with
  `InvalidReference`. A whole-string `"$N.path"` keeps the JSON type (int stays int);
  `"${N.path}"` inside a longer string becomes text.
- **Refused inside batch (`InvalidOp`)**: `open_database`, `close_database`,
  `save_database`, `wait_for_analysis`, `undo`, `redo`, `run_auto_analysis`,
  `reanalyze_range`, `set_image_base`, `run_ghidra_script`, `list_targets`, and the meta
  tools. Most of these are also missing from `tools.<name>` inside `execute` (AttributeError).
  Call them on their own.
- **`revision` moves on every transaction, including rolled-back ones.** Take the revision
  from your latest result (success or error), not from an earlier read, before passing
  `if_revision`.
- **`operation_id` replays only successful writes.** A retry with the same id after a failure
  runs again. Results of the last 256 successful writes are kept per worker.
- **`execute` timeout is checked between Python lines.** One long Java call (a decompile of a
  huge function, a big memory scan) can overrun `timeout_s`. Break long work into Python-level
  loops.
- **`execute` returns `str()` of Java objects.** Build plain dicts, lists, ints and strings
  yourself. Java `byte` values are signed in Python: `b & 0xFF`.
- **`execute` output caps**: stdout 64 KiB, result 256 KiB (`truncated` says so). Return
  counts and the first N items, not everything.
- **`run_ghidra_script` has no time limit.** A running Java script cannot be interrupted; an
  endless loop blocks that database until the server restarts.
- **Nothing is on disk until `save_database`.** Batches, execute and scripts change the open
  program only. `close_database` saves by default.

## Types and prototypes

- **`uint8_t`, `size_t` and SDK typedefs fail to parse** unless a type archive defines them:
  `int f(uint8_t *buf, size_t len)` raises a C ParseException; `int f(byte *buf, uint len)`
  works. Use Ghidra builtins.
- **Plate comments survive `set_function_prototype`** on this server (measured). Older notes
  that a prototype change wipes plate comments do not apply here.
- **Re-read locals after a prototype change.** It re-runs the decompiler; take local names
  from a fresh `list_decompiler_variables`, not from one read before the change.
- **The decompiler's display type can differ from the stored type.** Trust
  `list_decompiler_variables`, and set types explicitly.
- **`apply_type_at_address` needs the exact, case-sensitive type name**; `set_type` accepts C
  spellings (`char *`, `unsigned short`) and matches names case-insensitively.

## Strings and xrefs

- **Strings and xrefs exist only after the analyzers that create them ran.** On a program
  opened without auto-analysis, `list_strings` and `get_xrefs_to` can be nearly empty. Run
  `run_auto_analysis`, or search raw bytes (`search_bytes` with the string's ASCII hex).
- **Test a negative with a positive control.** Before concluding "this string is never used",
  run the same search for a string you know is used.
- **`get_xrefs_to` reaching its `limit`** (default 100) is a signal: a global with 100+
  references is a central state or config variable.

## Addresses and porting between builds

- **Ghidra addresses include the image base.** Read `image_base` from `get_database_info`;
  RVA = Ghidra address - image base, live address = runtime base + RVA. PE EXEs commonly base
  at `0x400000` and DLLs at `0x10000000`, but read the actual value: a relocated module loads
  at a different runtime base than its preferred one.
- **Porting offsets between two builds of one codebase**: anchor ONE global in the new build
  via a unique nearby string (find the string, follow its xref to the function that uses the
  global), then apply the known internal struct deltas from the reference build and check each
  derived address lands on a sane global. Deltas survive global-base shifts only if the struct
  layout is unchanged; after a major version bump, re-verify each field.

## Live-memory RE: match the exact binary the target maps

- **Reverse the exact binary the live process maps, not a same-named local copy.** Offsets
  from one build are garbage against another. Compare `md5sum` and size of the analyzed file
  against the one in `/proc/<pid>/maps` (or pull the mapped file out and analyze that). For a
  stable harness, pin the target's version and reverse that build once.
- **All-zero reads at a plausible base do not prove a wrong offset.** It usually means the
  wrong binary or a global not yet initialized. If several independent globals also read 0
  while the process clearly runs, suspect a build mismatch before your offset math.

## Wine crash-triage misreads

- **"Process terminated cleanly" does not mean no crash.** If a Wine guest installs a top-level
  handler (`SetUnhandledExceptionFilter` / a `__try` around the frame loop) that catches an
  access violation and exits through its own shutdown, the exit looks orderly and
  `winedbg --auto` / interactive winedbg break on nothing (they act only on unhandled or pass
  first-chance silently). Catch it with gdb attached and `catch signal SIGSEGV`: the host
  SIGSEGV fires before the guest handler. See [dynamic-analysis.md](dynamic-analysis.md) §2.
- **The post-crash "Missing shutdown function for X : Y" / "File ... never closed" storm is a
  red herring.** Those are `code=40010006` (`OutputDebugString`) lines from the application's
  normal shutdown audit, which runs on any quit. Grep for the single `code=c0000005` above
  them. A storm with no `c0000005` means a controlled exit, not a crash.
- **Do not NOP a guest's `SetUnhandledExceptionFilter` call to force the crash unhandled.** In
  an MSVCRT-static binary those call sites are CRT internals (install, then restore), and
  NOPping them breaks CRT exception setup and boot. Use a host-level SIGSEGV catcher.
