# Headless Operations Reference

ghidra-mcp-next runs Ghidra headless through pyghidra. One worker process serves each open
database.

## Opening programs

| Source | Call |
|---|---|
| A binary | `open_database(file_path="/path/to/binary", run_auto_analysis=true)` |
| A program in an existing project | `list_project_files(project="/path/to/proj.gpr")`, then `open_database(file_path="/path/to/proj.gpr", program="/folder/prog")` |
| A Ghidra Server program | `open_database(file_path="ghidra://host[:port]/repo/folder/prog")` |

- `open_database` returns at once with `{status: "opening", database, ...}`. Call
  `wait_for_analysis(database=...)` before any other tool; others are refused until it is
  ready. `wait_for_analysis(databases=[...])` returns when ONE of several is ready.
- A binary is imported into `<its dir>/ghidra_projects/`, which must be writable. Re-opening
  an open program returns its existing id. `database_id="srv"` picks the id yourself.
- `run_auto_analysis=true` for a fresh import. An already analyzed project program does not
  need it.
- `force_new=true` is destructive: it deletes the existing project and all annotations, then
  re-imports.
- Wrong processor (raw firmware, unusual formats): `list_targets`, then re-open with
  `language="ARM:LE:32:v8"` and `compiler_spec="default"` (values from `list_targets`).
- Several databases can be open at once. Every tool call names its `database`; there is no
  current program. `list_databases` recovers ids. `GHIDRA_MCP_MAX_WORKERS` may cap how many
  are open.

After `wait_for_analysis`: `get_database_info` for `processor`, `bitness`, `image_base`,
`function_count`, `min_address`/`max_address`.

## Analysis time and coverage

- Full auto-analysis of a large binary takes minutes; `wait_for_analysis` blocks until done.
  Decompiler-based analyzers can stall on pathological functions.
- `run_auto_analysis` re-runs full analysis on an open program and waits. It really analyzes:
  it returns `functions_before`, `functions_after` and `seconds`. It blocks the database
  meanwhile. It is refused inside `batch`.
- `reanalyze_range(start_address, end_address)` disassembles a range and then runs the
  auto-analysis pass over the program. Use it after patching or creating code in one place.
- When you need only a few functions in a big binary, skip whole-program analysis: open
  without `run_auto_analysis`, then `create_function(address)` + `decompile_function` for the
  addresses you need. Xrefs and strings stay sparse in that state.
- **"Analysis finished" does not mean the functions you need exist.** On a large 32-bit PIC
  `.so`, full analysis was measured at 3,752 functions for 7.5 MB of `.text`, leaving
  confirmed call sites with no enclosing function and `get_xrefs_to` empty (Ghidra does not
  resolve GOT-relative data refs on i386 PIC). Then stop coaxing function discovery: decode
  the raw bytes in `execute`, which needs no functions.

## Saving

Nothing reaches disk until `save_database(database, comment)`. `close_database` saves unless
`save=false`. Large programs can take minutes to save. A Ghidra Server program must be checked
out first, or the save fails with `ReadOnly`.

## Ghidra Server

- Programs opened from `ghidra://` are read-only until `checkout_file(exclusive=false)`.
- `get_version_state`: `checked_out`, `can_save`, `version`, `latest_version`.
- `checkin_file(comment, keep_checked_out=true)` saves and publishes a version.
- `get_version_history`, `list_checkouts`.
- `undo_checkout` discards the checkout and every change since it, saved or not.
- Credentials only from the server's environment: `GHIDRA_MCP_SERVER_USER`,
  `GHIDRA_MCP_SERVER_PASSWORD`. They are never tool arguments.
- `list_repositories`, `create_repository` and `list_repository_files` need no open database;
  each starts a short-lived JVM, so expect several seconds.
- `add_to_repository` shares the open local program (saved first, annotations included) as
  version 1; open the returned `url` to work on the shared copy.
- Checkout, checkin, `undo_checkout` and `add_to_repository` are refused inside `batch`.

## Scripts

- `execute(database, code, read_only=true)` for reads; without `read_only` for edits. Python
  3 through pyghidra with `program`, `flat`, `monitor`, `toAddr`, `decompile`, `tools`.
  `timeout_s` up to 600, checked between Python lines.
- `run_ghidra_script(script, args)` for existing Java or Python GhidraScripts, by name
  (`list_ghidra_scripts` searches `GHIDRA_MCP_SCRIPT_DIRS`, `~/ghidra_scripts`, then Ghidra's
  bundled script dirs) or absolute path. Java scripts need a JDK; Ghidra compiles them on first
  use. One transaction, rolled back if the script throws. No time limit.
- CLI fallback when no server is available: `analyzeHeadless <projdir> <name> -import <bin>
  -postScript <Script>` runs the same GhidraScripts. Put the project outside any directory
  shared through a container bind mount.

## Initial recon pattern

1. `list_exports`: exported functions, ordinals.
2. `list_imports(module_filter=...)`: libraries, APIs (runtime-resolved APIs are absent).
3. `list_strings(filter_pattern=...)`: IPs, paths, format strings, errors, API names.
4. `find_code_by_string(pattern=...)`: from a string to the code that uses it.

## Finding code

- `search_bytes(pattern="...")`: references to addresses or byte sequences (exact bytes, no
  wildcards; `limit` defaults to 20).
- `search_text(pattern=...)`: regex over every instruction's text.
- `get_xrefs_to`: references to an address (only where analysis created them).
- `get_address_info`: what is at an address, its name, xref counts, containing function.
- `get_xrefs_to` stopping at its `limit` (default 100) is itself a signal: a global with 100+
  references is a central state or config variable.

## Address bases: add the image base to anything from binutils

A shared object's own vaddrs start at 0; Ghidra loads it at an image base (commonly
`0x00010000`). Every address from `nm` / `readelf` / `objdump` must have that base added
before it means anything to Ghidra. Measured on a real `.so`: symbol addresses from `nm` were
all exactly `+0x10000` in Ghidra.

The failure is silent: `get_function` finds no function, which reads as "analysis missed it"
rather than "you are 64 KB low".

- Read `image_base` from `get_database_info` first.
- Confirm the delta on two known symbols before trusting a sweep.
- Addresses that came from Ghidra (`search_bytes`, `list_functions`) are already in Ghidra
  space: do not rebase them.
- RVA = Ghidra address - image base; live address = runtime base + RVA.

## Data pattern searching

When `get_xrefs_to` returns nothing (common for data in unanalyzed regions):
1. Take the target address, e.g. `0x0044ebac`.
2. Little-endian bytes: `ac eb 44 00`.
3. `search_bytes(pattern="ac eb 44 00")`.
4. Each hit is code using that address as an immediate.

A string with no xrefs: `search_bytes` with the string's ASCII hex gives its address; then
`search_bytes` with that address little-endian gives the `PUSH <addr>` site; then
`decode_instructions` around it. No analysis needed.

### This does not work on 32-bit PIC shared objects

Position-independent code reaches data with `lea reg,[GOTreg + disp32]`. Searching the
absolute address returns nothing, which looks the same as "never referenced".

```python
disp = (target_addr - got_base) & 0xFFFFFFFF   # search these 4 bytes, little-endian
```

- Get candidate bases from `list_memory_blocks`: try both `.got` and `.got.plt`. One gives
  exactly one hit in `.text`, the other none. (Measured: the linker used `.got`.)
- The GOT register is whatever GCC picked for that function, not necessarily `ebx`
  (observed: `esi`). Do not filter on the register.
- Test the method with a string you know is used before concluding anything.

## Dynamic imports

APIs loaded at runtime (`GetProcAddress`, `dlsym`): the API names appear in `list_strings`
but not in `list_imports`. `find_code_by_string(pattern="^sendto$")` finds the loading code;
without defined strings, use the byte-search chain above.

## Unanalyzed code

Auto-analysis may miss functions (common in Delphi/BCB binaries):
1. `read_bytes(address, size=64)` to see raw bytes.
2. Look for prologues: `55 8B EC` (push ebp; mov ebp, esp).
3. `create_function(address)` at the prologue (in a batch for several).
4. `decompile_function` to check.

For a systematic sweep, see [orphaned-code-discovery.md](orphaned-code-discovery.md).

## Server configuration (for whoever runs the server)

| Variable | Meaning |
|---|---|
| `GHIDRA_INSTALL_DIR` | Ghidra installation (auto-detected if unset) |
| `GHIDRA_MCP_SCRIPT_DIRS` | Extra GhidraScript dirs, `:`-separated |
| `GHIDRA_MCP_DISABLE_EXECUTE=1` | Removes `execute` |
| `GHIDRA_MCP_DISABLE_BATCH=1` | Removes `batch` |
| `GHIDRA_MCP_MAX_WORKERS` | Most databases open at once |
| `GHIDRA_MCP_SERVER_USER` / `GHIDRA_MCP_SERVER_PASSWORD` | Ghidra Server credentials |

Requirements: Ghidra 12.0 or newer, JDK 21 (a JDK, to compile Java GhidraScripts).
