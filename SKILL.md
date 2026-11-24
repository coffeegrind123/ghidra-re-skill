---
name: ghidra-re
description: Reverse engineer, decompile, and analyze NATIVE binaries with the ghidra-mcp-next headless Ghidra MCP server (22 listed tools, ~120 more via search_tools, atomic batch edits, and Python execute against the Ghidra API). Covers function documentation, data type investigation, orphaned code discovery, call graph analysis, struct creation, variable renaming, binary reconnaissance, malware analysis, and Ghidra Server checkout/checkin. Use when the user mentions Ghidra, decompilation, disassembly, binary analysis, DLL/EXE/ELF investigation, function renaming, malware analysis, or references function addresses like 0x401000. Do NOT use for source-level debugging, dynamic analysis, non-Ghidra RE tools, or MANAGED .NET assemblies (use ILSpy/ilspycmd for those, see rule 0).
allowed-tools: mcp__ghidra__* Bash(curl:*)
when_to_use: "Use when the user wants to reverse engineer or analyze a binary with Ghidra. Examples: 'analyze this binary', 'decompile this function', 'what does this DLL do', 'document all functions', 'find hidden functions', 'create a struct', 'trace the call graph', 'check for malware', 'rename this function at 0x401000'."
argument-hint: "[function address, binary path, or task description]"
metadata:
  author: coffeegrind123
  version: "2.0"
---

# Ghidra MCP Reverse Engineering

Server: ghidra-mcp-next (headless, pyghidra). Tools appear as `mcp__ghidra__<name>`.

## General Rules

0. **Triage first: is it native?** Run `file` on the target before opening it. Ghidra is for
   native code (PE/ELF/Mach-O machine code). A managed .NET assembly (`file` says
   "Mono/.Net assembly") decompiles far better with ILSpy / `ilspycmd`, which rebuilds
   near-original C#. Ghidra's CIL output is poor and slow. A .NET single-file app ships a small
   native apphost `.exe` (a generic launcher, not worth reversing) next to the managed `.dll`:
   reverse the `.dll` with ILSpy.

   ```sh
   curl -fsSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 8.0 --install-dir ~/.dotnet --no-path
   ~/.dotnet/dotnet tool install -g ilspycmd --version 9.1.0.7988
   # every run (the tool targets net6, the runtime is net8):
   export DOTNET_ROOT=$HOME/.dotnet PATH=$HOME/.dotnet:$HOME/.dotnet/tools:$PATH DOTNET_ROLL_FORWARD=LatestMajor
   ilspycmd foo.dll -o .        # -> foo.decompiled.cs
   ```
   Pin `9.1.0.7988`: unpinned and `10.1.x` fail with "DotnetToolSettings.xml not found";
   `8.2.x` crashes on net10 metadata. Use single-file output; project mode `-p` throws on newer
   TargetFramework metadata. To pull an embedded manifest resource without running the
   assembly, a short C# tool over `PEReader` + `MetadataReader.ManifestResources` dumps it.

0b. **Do you need Ghidra at all?** For a known function in a non-stripped binary, binutils
   answer in seconds with no import and no analysis wait:
   ```sh
   file  <bin>                                   # arch, stripped?, PIE/.so?
   nm -D --defined-only <bin> | grep -i <name>   # exported symbol -> address
   nm -D -u <bin> | grep -iE 'brk|mmap|malloc'   # imports = behaviour hints
   readelf -V <bin> | grep -oE 'GLIBC_2\.[0-9]+' # minimum glibc it needs
   objdump -d --start-address=0xA --stop-address=0xB -M intel <bin>
   ```
   Use Ghidra for decompilation, whole-program xrefs, type recovery, call graphs, saved
   annotations, or a stripped binary. `readelf -V | grep GLIBC_` answers "why won't this run
   here". Binutils are missing on many slim images; there every command prints nothing and
   `grep -c` prints `0`. Confirm the tool exists before trusting a negative.

1. **Lifecycle.** `open_database(file_path=...)` returns at once with a `database` id. Call
   `wait_for_analysis(database=...)` before anything else; other tools are refused while it
   opens. Every other tool takes `database`. Several databases can be open at once; each is
   addressed only by its id. There is no "current program".

2. **Change loop.** Read (decompile, list variables, xrefs) -> plan every edit -> ONE `batch`
   per coherent change, with a `label` -> re-read to check -> `save_database`. Do not send
   edits one call at a time. A batch is atomic: if any op fails, nothing changes.

3. **Save discipline.** Nothing reaches disk until `save_database(database, comment)`.
   `close_database` saves by default. Save after each finished function or batch group.

4. **Phantom variables.** `extraout_*` and `in_*` variables with `undefined` types are
   decompiler artifacts from register splitting. Renaming or retyping them fails, and one
   failing op rolls back the whole batch. Leave them out of batches and note them in the plate
   comment's Special Cases.

5. **Hungarian notation** for variables, globals, and struct fields. The server does not add
   prefixes; you apply them everywhere. Set the type first; the prefix must match the real
   Ghidra type, not the decompiler's display type. Table:
   [reference/hungarian-notation.md](reference/hungarian-notation.md).

6. **Name collisions.** Before renaming, check the name is free:
   `list_functions(filter_pattern="^Name$")`, and `list_names(filter_pattern="^g_name$")` for
   globals. Parallel agents can pick the same name.

7. **Thunk dual-documentation.** If a function is a single JMP (`get_function` shows
   `is_thunk`), document BOTH the thunk and the body it jumps to (`get_xrefs_from` on the JMP).
   Otherwise the body stays `FUN_*` with no comments.

8. **Context budget.** Listings are paginated (`items`, `total`, `offset`, `limit`,
   `has_more`). Always pass `limit`. `decompile_functions` costs seconds per function; filter
   it with `filter_pattern`. `execute` caps stdout at 64 KiB and the result at 256 KiB: return
   summaries, not dumps.

9. **Type normalization.** Use lowercase Ghidra builtins (`uint`, `ushort`, `byte`, `char`,
   `int`, pointer forms) not Windows SDK types (`DWORD`, `USHORT`, `BYTE`). The prototype
   parser knows the builtins but not `uint8_t` or `size_t` unless a type archive defines them:
   `int f(uint8_t *buf, size_t len)` fails with a C ParseException; `int f(byte *buf, uint len)`
   works.

10. **Autonomy.** Run the workflows without asking for confirmation at each step. Ask only when
    the binary's purpose or a function's behaviour is genuinely ambiguous.

11. **Parallel writers and retries.** When subagents edit the same database, pass
    `if_revision` (the `revision` from your last result) on writes that depend on what you
    read. If another write landed, the call fails with `TargetChanged` and changes nothing:
    re-read and retry. Pass `operation_id` on any write you might resend (timeouts, retries):
    a repeat returns the stored result with `replayed: true` instead of applying twice.
    Every `batch`, `execute`, `undo` and save result, and every batch/execute error, carries
    the current `revision`.

12. **Finding tools.** 22 tools are listed. The rest (~120) are found with
    `search_tools(pattern="struct|enum")` and run through `call(tool, arguments, database)`,
    as `batch` ops, or as `tools.<name>(...)` inside `execute`. `get_schema(tools=[...])` gives
    parameters. The resource `ghidra://api/tools.pyi` is the full typed API. Never guess a tool
    or parameter name: look it up. This skill names hidden tools directly (`score_documentation`,
    `set_comment`, ...); call them through `call`, `batch` or `execute`, not as `mcp__ghidra__*`.

## batch and execute

**`batch(database, ops=[{tool, params}], label, if_revision, operation_id, dry_run)`**
- Up to 100 ops in ONE transaction. Any failure rolls back everything; the error names
  `op_index`, `tool`, `error_type` and the current `revision`.
- Success is one undo step named `MCP: <label>`. `undo` reverts it and reports the name.
- `"$N.path"` is replaced by that value from op N's result, keeping its type (`"$0.address"`,
  `"$2.items.0.name"`). `"${N.path}"` interpolates inside a longer string. `$$` escapes `$`.
- `dry_run=true` runs every op, returns the results, then rolls back. Use it to validate a
  risky plan.
- Refused inside a batch (`InvalidOp`): lifecycle tools, `undo`/`redo`, `run_auto_analysis`,
  `reanalyze_range`, `set_image_base`, `run_ghidra_script`. Call those on their own.

Example: document one function. After `rename_function`, the name `FUN_00401000` is gone, so
later ops use the entry address it returned (`$1.address`).

```json
batch(database="fw_bin", label="doc ParsePacketHeader",
      if_revision=1284, operation_id="doc-401000-a", ops=[
  {"tool": "parse_type_declaration", "params": {"declaration":
     "struct PacketHeader { ushort wType; ushort wLength; uint dwSequence; byte *pPayload; };"}},
  {"tool": "rename_function", "params": {"address": "FUN_00401000", "new_name": "ParsePacketHeader"}},
  {"tool": "set_function_prototype", "params": {"address": "$1.address", "type_string":
     "int ParsePacketHeader(${0.type_name} *pHeader, byte *pBuffer, uint dwLength)"}},
  {"tool": "set_type", "params": {"address": "0x40a010", "type_string": "uint"}},
  {"tool": "rename_symbol", "params": {"address": "0x40a010", "new_name": "g_dwPacketCount"}},
  {"tool": "rename_decompiler_variable", "params": {"function_address": "$1.address",
     "old_name": "local_10", "new_name": "dwOffset"}},
  {"tool": "set_comment", "params": {"address": "$1.address", "comment_type": "plate",
     "comment": "Validates a packet header and copies its payload.\n\nAlgorithm:\n1. ..."}}])
```

**`execute(database, code, read_only, label, timeout_s, if_revision, operation_id)`**
- CPython 3 through pyghidra (not Jython, not Java). The code is a function body: `return`
  or a final bare expression gives the result. Java objects are converted with `str()`.
- Globals: `program` / `currentProgram`, `flat` (FlatProgramAPI), `monitor`, `toAddr`,
  `decompile(func_or_addr) -> str`, `tools.<name>(**params) -> dict` (every tool), `print`
  (captured), and imports from the `ghidra` and `java` packages.
- One transaction: an exception or timeout rolls everything back. `read_only=true` always
  rolls back. A successful write is one undo step.
- `timeout_s` (1-600, default 30) is checked between Python lines; one long Java call can
  overrun it.
- Use it for loops, computed edits, and reads no single tool covers. Disabled when the server
  runs with `GHIDRA_MCP_DISABLE_EXECUTE=1`.

Example: every unnamed function reachable from one function, leaves first (no single tool
walks the graph transitively and filters by name):

```python
fm = program.getFunctionManager()
root = fm.getFunctionContaining(toAddr("0x401000"))
seen, todo, out = set(), [(root, 0)], []
while todo:
    f, depth = todo.pop()
    key = str(f.getEntryPoint())
    if key in seen or depth > 4:
        continue
    seen.add(key)
    if f.getName().startswith("FUN_"):
        out.append({"address": key, "depth": depth,
                    "size": int(f.getBody().getNumAddresses()),
                    "callers": f.getCallingFunctions(monitor).size()})
    for callee in f.getCalledFunctions(monitor):
        if callee.isThunk():
            callee = callee.getThunkedFunction(True)
        if callee is not None and not callee.isExternal():
            todo.append((callee, depth + 1))
return sorted(out, key=lambda r: (-r["depth"], r["size"]))
```
Run it with `read_only=true`. Java `byte` values arrive signed in Python: mask with `& 0xFF`.

**`run_ghidra_script(script, args)`** runs an existing Java or Python GhidraScript by name
(from `GHIDRA_MCP_SCRIPT_DIRS`, `~/ghidra_scripts`, Ghidra's bundled dirs; see
`list_ghidra_scripts`) or by absolute path. One transaction, rolled back if it throws. It has
no time limit: a script that loops forever blocks that database. For new logic use `execute`.

## Decision Tree

Every path: `open_database` -> `wait_for_analysis` -> work -> `save_database`.

```
"Analyze this" / "What does it do?" -> not open: Phase 0; open: Phase 1; one function: Phase 2
"Document functions" / "Clean up"   -> one: Phase 2; many or "all": Phase 3
"What is this struct?"              -> Phase 4      "Find hidden functions" -> Phase 5
"Who calls this?" / "Call graph"    -> Phase 6      "Malware" / "IOCs"      -> Phase 7
```

## Phase 0: Open

| Source | `open_database` arguments |
|---|---|
| A binary | `file_path="/path/to/binary", run_auto_analysis=true` (imports into `<dir>/ghidra_projects/`, which must be writable) |
| A program in an existing project | `file_path="/path/to/proj.gpr", program="/folder/prog"`; `list_project_files(project=...)` lists programs without opening anything |
| A Ghidra Server program | `file_path="ghidra://host[:port]/repo/folder/prog"`; read-only until `checkout_file` (see Ghidra Server) |

Then `wait_for_analysis(database=...)`, then `get_database_info` (processor, bitness,
`image_base`, `function_count`). If auto-detection picked the wrong processor (raw firmware),
re-open with `language=` and `compiler_spec=` from `list_targets`. Analysis of a large binary
takes minutes. Details: [reference/headless-operations.md](reference/headless-operations.md).

## Phase 1: Recon

1. `get_database_info`: format, processor, image base, counts.
2. `list_exports`, `list_imports(module_filter=...)`: API surface and dependencies.
3. `list_strings(filter_pattern=...)`: URLs, paths, errors, format strings, API names.
   `find_code_by_string(pattern=...)` goes from a string to the code using it.
4. `list_entry_points`, `list_memory_blocks`: entry and memory layout.
5. `list_functions(limit=50)` and `score_documentation(limit=20)` for an overview.
6. Optional: `apply_function_id` to name library code from FID databases.

Report: binary type, likely purpose, key exports, interesting strings, next steps.

## Phase 2: Single Function Documentation

Full protocol: [reference/function-documentation.md](reference/function-documentation.md).

1. **Read**: `decompile_function`, `list_decompiler_variables`, `get_function`,
   `get_xrefs_from`. Classify (thunk, leaf, worker, init, handler, public API).
2. **Plan**: name (PascalCase, verb first, collision-checked), prototype, globals, struct use,
   local names, comments.
3. **Batch A, identity**: types (`parse_type_declaration`), `rename_function`,
   `set_function_prototype`, globals (`set_type` then `rename_symbol`).
4. **Re-read** `list_decompiler_variables`: a prototype change re-runs the decompiler, so
   take local names from this fresh list, not from the one you read before.
5. **Batch B, body**: remaining `rename_decompiler_variable` / `retype_decompiler_variable`,
   plate comment (`set_comment` with `comment_type="plate"`), PRE and EOL comments.
6. **Verify**: `decompile_function` again; check the plate summary matches the name.

Small functions fit in one batch. Plate comments survive `set_function_prototype` on this
server; still set names and types first so the comments describe the final names.

## Phase 3: Batch Documentation

Dispatch details: [reference/function-documentation.md](reference/function-documentation.md).

- **Targets**: `score_documentation(max_score=60, limit=20)` ranks functions worst-first by
  what is missing (name, prototype, plate comment, parameters, and locals with
  `include_locals=true`). Alternatives: the execute walk above (leaves first),
  `list_functions(filter_pattern="^FUN_")`, or address neighbours of a documented function.
- **Order**: callees before callers, so callers decompile with good names.
- **Subagents**: give each the `database` id and its addresses. Requests to one database run
  one at a time in its worker, so more than about 3 agents per database mostly wait. Writers
  use `if_revision` and `operation_id` (rule 11).
- **Models**: Sonnet by default; Opus for 40+ line functions, public API entry points, or a
  retry after a poor first pass.

## Phase 4: Data Type Investigation

Full workflow: [reference/data-type-investigation.md](reference/data-type-investigation.md).

1. Find parameters typed `int *`, `void *`, `undefined4`, used with offsets.
2. Collect offset accesses from the function and its callers (`get_xrefs_to`, then
   `decompile_function` each; `decompile_functions(filter_pattern=...)` for a named group).
3. `list_structures(filter_pattern=...)` / `get_structure` for an existing match.
4. Create in one batch: `parse_type_declaration` with the whole struct, or `create_structure`
   + `add_struct_member` ops. Name by identity (`Connection`, not `InitializedConnection`).
5. Apply in the same batch: `set_function_prototype` or `retype_decompiler_variable` with
   `Name *` in every function that uses it.
6. Re-decompile and confirm the fields resolve.

## Phase 5: Orphaned Code Discovery

Scanner and classification: [reference/orphaned-code-discovery.md](reference/orphaned-code-discovery.md).

Run the scanner with `execute(read_only=true)`: pass 1 finds disassembled instructions in no
function (HIGH), pass 2 prologue byte patterns (`55 8B EC`, `8B FF 55 8B EC`, ...), pass 3
non-padding runs ending in RET (LOW). Process types in the order B, C, D, F, A, E, G. Create
approved candidates in batches of 5-10: `create_function`, then `set_comment` with a triage
plate using `"$N.address"`. Spot-check with `decompile_function`. Re-run the scanner: new gaps
appear as boundaries move.

## Phase 6: Call Graph

`get_call_graph(address, depth=1..3)` for the caller/callee tree; `get_xrefs_to` /
`get_xrefs_from` for single references (data, strings, vtables); `find_decompiled_calls` for
call sites in pseudocode; `get_basic_blocks` / `get_cfg_edges` for control flow inside a
function; `execute` for transitive walks (example above).

## Phase 7: Security Analysis

- `list_imports(module_filter=...)` and `search_text(pattern="CALL.*(VirtualAlloc|CreateRemoteThread|WriteProcessMemory)")`
  for injection, persistence, network and crypto APIs.
- `list_strings` / `find_code_by_string` for URLs, IPs, registry keys, paths, mutex names;
  `search_bytes` for crypto constants and known signatures.
- Strings that name APIs but are absent from imports mean runtime resolution
  (`GetProcAddress`, `dlsym`): follow them with `find_code_by_string`.
- Anti-analysis: `search_text` for `rdtsc`, `cpuid`, `int3`, and `IsDebuggerPresent`
  references; `get_analysis_problems` for bad disassembly in packed regions.
- Decompile and document every flagged function (Phase 2).

## Across Builds

Several databases can be open at once. To carry work from a documented build to a new one:

- `match_functions(source_database, target_database, algorithm=...)` pairs functions; one
  pair per function on both sides, never many-to-one. Measured on two library version pairs
  with debug-symbol truth (functions of 10+ instructions, precision / recall):

  | algorithm | precision | recall | notes |
  |---|---|---|---|
  | `fid_specific` (default) | 1.00 | 0.03-0.15 | unique hashes only |
  | `fuzzy` | 0.99-1.00 | 0.22-0.27 | adds similarity matches; review `score` |
  | `vt` | 1.00 | 0.46-0.53 | Version Tracking: identical code and same-name pairs as seeds, then matches through matched callers, callees and data |
  | `bsim` | 0.99 | 0.83-0.90 | same seeds, then BSim decompiler similarity (confidence >= 10); slow, decompiles both programs; review the pairs |

  `vt` and `bsim` open a Version Tracking session on the target, which clears the target's
  undo history (Ghidra joins the two undo stacks).
- `propagate_documentation(...)` takes the same algorithms and copies names, prototypes,
  plate and line comments, labels, locals and the data types they use; one undo step;
  `dry_run=true` previews. Comments and labels copy only between bodies of identical layout.
- Ghidra's own Version Tracking, for review and its markup rules:
  `version_track(source_database, target_database, session_name)` correlates and returns the
  best one-to-one matches; then on the target: `version_track_matches(session_name)`,
  `apply_version_tracking(session_name, pairs=[{source, destination}], fields=[...])`
  (accepts and copies markup; a pair VT never found becomes a manual match), and
  `version_track_correlate(session_name, ["combined_reference"])` to find changed functions
  next to accepted ones; repeat. Reference correlators find nothing until matches are
  accepted. `auto_version_track` does it all with Ghidra's defaults, accepting and applying on
  its own judgement. Each apply is one undo step that reverts the markup AND the match
  statuses. VT reads the source's SAVED state (`save_source=true` saves it first). Sessions
  are not saved: they end with `close_version_track` or when the target closes.
- What changed: `diff_programs` ranks changed functions (code, callees, size); `diff_strings`
  lists strings added or removed; `diff_functions_across(level="decompiled")` diffs one pair as
  C with load addresses normalised, `level="instructions"` by instruction. A real code change
  can leave the decompiled C identical (e.g. a patched dead branch): check instructions too.

## Ghidra Server

A `ghidra://` program is read-only until `checkout_file(exclusive=false)`; before that
`save_database` fails with `ReadOnly`. `get_version_state` shows checkout, `can_save` and newer
versions. `checkin_file(comment, keep_checked_out=true)` publishes a version.
`get_version_history` and `list_checkouts` show history and holders. `undo_checkout` is
destructive: it drops saved-but-not-checked-in work. Credentials come only from the server's
environment (`GHIDRA_MCP_SERVER_USER` / `GHIDRA_MCP_SERVER_PASSWORD`), never tool arguments.
Ghidra 12.2+ clients reject a server's self-issued TLS certificate: the server needs
`GHIDRA_MCP_SERVER_CACERTS` (the certificate to trust), or `GHIDRA_MCP_SERVER_TRUST_LOOPBACK=1`
for a server on 127.0.0.1 where every local account is trusted.

Repositories (hidden tools: reach them with `call`; no database needed, several seconds each
because they start a JVM): `list_repositories(server="host[:port]")`,
`create_repository(server, name)`, `list_repository_files(repository="ghidra://host/repo")`
to find program paths. To share a binary you analyzed locally: open it, then
`add_to_repository(repository="ghidra://host/repo/folder", comment=...)`. It saves, copies the
program with its annotations as version 1 and returns its `url`. The open database stays the
local copy, so open the returned `url` to keep working on the shared one.

## Error Handling

Errors are tool errors whose JSON carries `error_type`.

| Symptom | Diagnosis | Fix |
|---|---|---|
| `NoDatabase` / `NotReady` | Nothing open, or still opening | `open_database`, then `wait_for_analysis` |
| `InvalidArguments` / `InvalidArgument` / `UnknownTool` | Wrong name or value | `search_tools` / `get_schema(tools=[...])`, fix, resend |
| Batch fails with `op_index` | That op failed; nothing changed | Fix that op (often a phantom variable or a stale name), resend the batch |
| `InvalidReference` in a batch | `$N` points at a later op or a missing path | Reference only earlier ops; check the result field name |
| `InvalidOp` in a batch | Lifecycle, undo, analysis or script tool in a batch | Call it on its own |
| `TargetChanged` | Program changed since your `if_revision` | Re-read, re-plan, retry with the new revision |
| `TimeoutError` from execute | Ran past `timeout_s`; rolled back | Raise `timeout_s` (max 600) or split the work |
| `ScriptError` / `SyntaxError` | Python or GhidraScript error; rolled back | Error carries the line and stdout so far |
| `ReadOnly` on save | Server program not checked out | `checkout_file` |
| `DecompilationFailed` | Decompiler gave up (`timeout_s`, default 60) | Raise `timeout_s`, or read `disassemble_function`; check bounds with `list_function_ranges` |
| `EditDisplaced` from `edit_decompiler_variables` | A wider type would overlap (and Ghidra would silently delete) a neighbouring variable | Retype the neighbour first, or pass `allow_displace=true` deliberately |
| `UnsavedSource` from `version_track` | VT reads the source's saved state | `save_database` on the source, or `save_source=true` |
| A `NotFound` lists close names | A typo or a renamed symbol | Pick from the suggestions in the error |
| `NotFound` renaming a variable | Name changed after a prototype edit, or a phantom | `list_decompiler_variables` again; skip phantoms |
| `create_function` fails at a candidate | Shared epilogue or inside another body | Skip; the code belongs to a neighbour |
| `get_function` finds nothing at an `nm` address | `.so`/PIE image base not added | Add `image_base` from `get_database_info`; verify on two known symbols |
| `search_bytes` for a string's address finds nothing, but it is used | 32-bit PIC reaches data GOT-relative | Search `disp = target - got_base`, trying `.got` and `.got.plt` |
| Analysis done but a call site has no function | Auto-analysis under-covers large PIC `.so` | `create_function` at the site, or decode raw bytes in `execute` |

## Critical Pitfalls

- Do NOT put a phantom variable or a guessed name in a batch: one failing op discards the
  whole batch. Use `dry_run=true` when unsure.
- Do NOT reuse a pre-rename symbol name (`FUN_...`, `DAT_...`) later in the same batch; use
  the address from the rename's result (`"$N.address"`).
- Do NOT forget `save_database`: batches and execute change only the open program.
- Do NOT trust decompiler display types for storage: check `list_decompiler_variables` and set
  types explicitly.
- Do NOT create functions in switch/jump tables: check `get_xrefs_to` and `get_switch_info`.
- Do NOT run a long loop through `run_ghidra_script`: a Java script is only stopped at its
  `timeout_s` and checks for cancellation only where it calls the monitor. Use `execute` with
  `timeout_s` for loops.
- Analysis-created names (`FUN_`, `DAT_`, `LAB_`) are default names: any rename replaces them.
  `rename_symbol` renames or creates the label at an address, globals included.

## Self-Refinement Protocol

When a session teaches something non-obvious (a decompiler quirk, a binary pattern, a tool
behaviour), put it where it will be read: a per-session rule into General Rules, "X looks like
Y but is Z" into Critical Pitfalls, a symptom into Error Handling, loading/addressing/search
depth into `reference/headless-operations.md`, a misbehaving tool into `reference/gotchas.md`,
workflow depth into the matching `reference/*.md`. `LEARNINGS.md` is only a staging buffer;
nothing reads it during a session. Never write "see LEARNINGS" here; inline the knowledge.

## Reference Files

- [reference/tool-categories.md](reference/tool-categories.md): task -> tool name map
- [reference/function-documentation.md](reference/function-documentation.md): documentation protocol, batch dispatch
- [reference/data-type-investigation.md](reference/data-type-investigation.md): structs from usage patterns
- [reference/orphaned-code-discovery.md](reference/orphaned-code-discovery.md): gap scanner, types A-G
- [reference/hungarian-notation.md](reference/hungarian-notation.md): type-to-prefix table
- [reference/headless-operations.md](reference/headless-operations.md): opening, analysis, addressing, byte search
- [reference/gotchas.md](reference/gotchas.md): non-obvious failure modes and fixes
- [reference/dynamic-analysis.md](reference/dynamic-analysis.md): confirming offsets and behaviour at runtime (Wine, `/proc/<pid>/mem`, stub DLLs, tcpdump, PE rebasing)
