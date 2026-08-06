---
name: ghidra-re
description: Reverse engineer, decompile, and analyze NATIVE binaries using 222 Ghidra MCP tools. Covers function documentation, data type investigation, orphaned code discovery, call graph analysis, struct creation, variable renaming, binary reconnaissance, and malware analysis. Use when the user mentions Ghidra, decompilation, disassembly, binary analysis, DLL/EXE investigation, function renaming, malware analysis, or references function addresses like 0x401000. Do NOT use for source-level debugging, dynamic analysis, non-Ghidra RE tools, or MANAGED .NET assemblies (use ILSpy/ilspycmd for those — see rule 0).
allowed-tools: mcp__ghidra__* Bash(curl:*)
when_to_use: "Use when the user wants to reverse engineer or analyze a binary with Ghidra. Examples: 'analyze this binary', 'decompile this function', 'what does this DLL do', 'document all functions', 'find hidden functions', 'create a struct', 'trace the call graph', 'check for malware', 'rename this function at 0x401000'."
argument-hint: "[function address, binary path, or task description]"
metadata:
  author: coffeegrind123
  version: "1.2"
---

# Ghidra MCP Reverse Engineering

## General Rules

0. **Triage first — is it even native?** Run `file` on the target before loading it into Ghidra. Ghidra is for **native** code (PE/ELF/Mach-O machine code). A **managed .NET assembly** (`file` reports "Mono/.Net assembly", or it references `Microsoft.CodeAnalysis`/`System.*`) decompiles far better with **ILSpy / `ilspycmd`**, which reconstructs near-original C#; Ghidra's CIL output is poor and slow. Heads-up: a .NET single-file app ships a tiny **native apphost `.exe`** (a generic launcher — not worth REing) next to the real managed `.dll` — RE the `.dll` with ILSpy. Only stay in Ghidra when the binary is genuinely native.

   **ILSpy install (no dotnet/ilspycmd preinstalled here):**
   ```sh
   curl -fsSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 8.0 --install-dir ~/.dotnet --no-path
   ~/.dotnet/dotnet tool install -g ilspycmd --version 9.1.0.7988
   # EVERY run (tool targets net6, runtime is net8):
   export DOTNET_ROOT=$HOME/.dotnet PATH=$HOME/.dotnet:$HOME/.dotnet/tools:$PATH DOTNET_ROLL_FORWARD=LatestMajor
   ilspycmd foo.dll -o .        # -> foo.decompiled.cs
   ```
   ⚠ **Pin `9.1.0.7988`.** Unpinned/`10.1.x` fail with "DotnetToolSettings.xml not found";
   `8.2.x` crashes on net10 metadata via `System.Version.ToString(fieldCount)`.
   ⚠ Use single-file output — project mode `-p` throws on newer TargetFramework metadata.
   To extract an **embedded manifest resource** without running the assembly, a ~30-line C#
   tool over `PEReader` + `MetadataReader.ManifestResources` (read
   `CorHeader.ResourcesDirectory`, then the per-resource length-prefixed blob) dumps it.

0b. **Triage second — do you even need Ghidra?** For a **known function in a non-stripped
binary**, host binutils answer in seconds with no project, no import, no analysis wait and
no image-base arithmetic to get wrong:

```sh
file  <bin>                                   # arch, stripped?, PIE/.so?
nm -D --defined-only <bin> | grep -i <name>   # exported symbol -> address
nm -D -u <bin> | grep -iE 'brk|mmap|malloc'   # imports = behaviour hints
readelf -V <bin> | grep -oE 'GLIBC_2\.[0-9]+' # minimum glibc it requires
objdump -d --start-address=0xA --stop-address=0xB -M intel <bin>
```

Escalate to Ghidra for what binutils cannot do: decompilation to C, whole-program xrefs,
type/struct recovery, call graphs, persistent annotation, or a **stripped** binary with no
symbol to anchor on.
⚠ `readelf -V | grep GLIBC_` is the one-command answer to "why won't this run here" — check
it before blaming the environment. A binary **you** compiled may require a *newer* glibc
than the base image you were about to pin to.
⚠ Binutils are absent on many prod hosts and in `node:*-slim`, where every invocation
returns empty and `grep -c` over it prints `0` — which reads as "feature missing". Confirm
the tool exists before trusting a negative (see rule 14).

1. **Pre-flight**: Always confirm the bridge is attached before any session work — `list_instances` (shows the connected instance, its project and open programs), then `check_tools` for the specific tools you are about to use. ⚠ **`check_connection` is NOT an MCP tool in v6.0.0** — it exists only as an HTTP health probe (`curl http://127.0.0.1:8089/check_connection`). Calling it as a tool fails with "unknown tool", which reads like a broken bridge when the bridge is fine.

2. **Save discipline**: `save_program` after every batch of mutations (every 5-10 changes). The headless server has no auto-save — a crash loses all unsaved work.

3. **Ordering law**: `set_function_prototype` WIPES existing plate comments — this is a Ghidra behavior, not a bug. Complete ALL naming, prototype, and type changes BEFORE setting plate comments and inline comments. Violating this order means re-doing all comment work. Note: in v5.0.0 the server now validates plate comment quality, but the wipe-on-prototype behavior remains.

4. **Phantom variables**: `extraout_*`, `in_*` variables with `undefined` types are decompiler artifacts from register splitting. They cannot be renamed or retyped. Note in plate comment Special Cases and skip.

5. **Hungarian notation**: All variable and global renames use Hungarian prefixes. Types must be set BEFORE renaming — the prefix must match the actual Ghidra type, not the decompiler's display type. Struct field names are NOW SERVER-ENFORCED via auto-prefixing on `create_struct`, `add_struct_field`, and `modify_struct_field` — do not manually add Hungarian prefixes to struct fields. Variable renames still require manual prefixes but the server validates them. Read [reference/hungarian-notation.md](reference/hungarian-notation.md) when you need the type-to-prefix table.

6. **Name collision checking**: Always `search_functions_enhanced` with the chosen name before `rename_function`. Parallel subagents can independently pick the same name, causing silent overwrites.

7. **Thunk dual-documentation**: If a function is a single JMP (thunk/forwarding stub), document BOTH the thunk AND the implementation body it jumps to. Documenting only the thunk leaves the body named `FUN_*` with no comments.

8. **Context budget**: `batch_decompile` and `list_functions` can return huge payloads that blow the context window. Always use offset/limit parameters.

9. **Type normalization**: Use lowercase Ghidra builtins (uint, ushort, byte) not Windows SDK types (DWORD, USHORT, BYTE). Ghidra's type resolver prioritizes builtins — using SDK types causes inconsistent resolution.

10. **Autonomy**: Execute RE workflows without asking for confirmation at each step. Ask only when the binary's purpose or a function's behavior is genuinely ambiguous.

11. **Atomic variable operations**: `set_variables` is the preferred tool for atomic type+rename operations. It eliminates SSA churn from separate type-set and rename calls, reducing decompiler re-analysis cycles.

12. **Multi-binary discipline — loading is NOT switching**: `load_program`/`import_file` do NOT make the new binary current. The server keeps a separate `current_program` **name**, and every tool omitting `program=` resolves against it — so after loading a second binary your queries keep answering **from the first one, silently and plausibly**. Also: two files with the same basename collide (the second load reports success but does not exist). Always: copy inputs to **distinct basenames** -> load -> **`switch_program(name)`** -> verify with **`list_open_programs`** that `is_current: true`. Pass `program=` explicitly on every call in a multi-binary session. **Never trust `get_current_program_info`** — see rule 13.

13. **`get_current_program_info` lies about closed programs**: it returns CACHED data (name, `executable_path`, `function_count`) for a program that has already been closed. `list_open_programs` is the only source of truth; the tell is its `count`/`is_current`/`current_program` fields disagreeing with each other, or `current_program` naming a program absent from `programs[]`. **Red flag**: if queries against two "different" binaries return byte-identical addresses, you are reading one binary — verify before believing any of it.

## Breaking Changes (current: v6.0.0)

GhidraMCP v5+ uses a bridge with dynamic tool discovery instead of the v4 hardcoded handlers. Key changes:

- **Tool count**: the v6.0.0 release ships **272 tools** across GUI and headless. A **headless** server registers **~214** of them plus **8 static bridge tools** — about **222 exposed**, measured against Ghidra 12.0.3. The live `/mcp/schema` is the authoritative list — categorized docs are a guide, not exhaustive.
- **The bridge is a wheel, not a script**: v6.0.0 ships `ghidra_mcp_bridge-6.0.0-py3-none-any.whl` with a `bridge-mcp-ghidra` console script. A stray `bridge_mcp_ghidra.py` on disk will shadow it — if tool names look like an older release, check for that file first.
- **`check_connection` is no longer an MCP tool** (see rule 1). Use `list_instances` / `check_tools`.
- **`store_function_knowledge` is not registered** on a stock v6 headless server — it belonged to the psycopg2-gated knowledge DB. Do not build a workflow around it without confirming via `check_tools`.
- **Absent from the v6 headless surface** (verified against a live `/mcp/schema`, Ghidra 12.0.3). Some are GUI-only, some are gone; either way `check_tools` returns `not_found` here:
  `check_connection`, `batch_rename_variables`, `batch_set_variable_types`, `consolidate_duplicate_types`, `search_memory_strings`, `run_script`, `project_info`, `export_system_knowledge`, `store_function_knowledge`, and the GUI navigation tools (`launch_codebrowser`, `goto_address`, `get_current_selection`, `get_current_address`, `get_current_function`).
  ⚠ When one of these fails, it is a **missing tool**, not a broken bridge or a failed analysis — the two look identical from the error alone. `search_tools` confirms what actually exists before you build a workflow on a remembered name.
- **`batch_rename_variables` renamed to `rename_variables`**: The old name no longer exists. Use `rename_variables` for all variable rename operations.
- **`set_variables` is new**: Atomic type+rename in one call. Preferred over separate `batch_set_variable_types` + `rename_variables` to avoid SSA churn.
- **`batch_set_comments` arrays now optional**: `decompiler_comments` and `disassembly_comments` arrays are optional — you can pass only `plate_comment` if that's all you need.
- **`analyze_function_completeness` removed from documentation workflow**: Scoring is now external in v5. Do not call it inside the function documentation protocol.
- **Struct field Hungarian prefixes are server-enforced**: `create_struct`, `add_struct_field`, and `modify_struct_field` auto-prefix field names. Do not manually add prefixes.
- **Static bridge tools (v6.0.0, all 8)**: `list_instances`, `connect_instance`, `list_tool_groups`, `load_tool_group`, `unload_tool_group`, `search_tools`, `check_tools`, `import_file`. These are always available even before an instance is attached.
- **`check_tools` returns `not_loaded`**: If a tool group isn't loaded, use `connect_instance` or `load_tool_group` to activate it.
- **`search_tools` searches the whole catalog**, including groups that are not loaded — use it to find the right tool without loading everything first.
- **Security (v6.0.0)**: the HTTP servers reject cross-origin requests and non-loopback `Host` headers with **403** unless `GHIDRA_MCP_AUTH_TOKEN` is set. The MCP bridge is exempt (loopback `Host`, no `Origin`), so a normal setup needs no token — but a 403 from a browser or a remote client is this guard, not a broken server.

### Coming in v7.0.0 (unreleased — do not write call sites against it yet)

A hard break with no compatibility aliases: **272 → 251 tools**, and **every tool returns JSON**.
`set_plate_comment` / `set_decompiler_comment` / `set_disassembly_comment` collapse into
`set_comment(address, comment, type=...)`; each `batch_*` tool merges into its singular form with a
bulk argument (`batch_decompile` → `decompile_function(functions="a,b,c")`);
`set_local_variable_type` / `set_parameter_type` → `set_variable_type`; `rename_data` /
`rename_label` / `rename_or_label` → `rename_symbol(..., kind=...)`. Tools that answered in prose
return records, so detect errors by an `error` key rather than by pattern-matching English.

## Lifecycle

```
list_instances -> [load binary or verify current program] -> get_current_program_info
  -> [workflow: recon | function_doc | batch_doc | data_types | orphaned_code | call_graph | security]
  -> save_program -> [repeat or close_project]
```

## Decision Tree

```
What does the user want?
+-- "Analyze this binary" / "What does this do?"
|   +-- Binary not loaded -> Phase 0 (Load Binary)
|   +-- Binary loaded, no prior work -> Phase 1 (Initial Recon)
|   +-- Specific function mentioned -> Phase 2 (Single Function Doc)
|
+-- "Document functions" / "Clean up this binary"
|   +-- Single function -> Phase 2
|   +-- Multiple / "all" / "batch" -> Phase 3 (Batch Documentation)
|
+-- "What is this struct?" / "Create a type" / "This param is a pointer to..."
|   +-- Phase 4 (Data Type Investigation)
|
+-- "Find hidden functions" / "Orphaned code" / "Missed functions"
|   +-- Phase 5 (Orphaned Code Discovery)
|
+-- "Who calls this?" / "Call graph" / "Trace execution"
|   +-- Phase 6 (Call Graph Analysis)
|
+-- "Check for malware" / "IOCs" / "Anti-analysis"
    +-- Phase 7 (Security Analysis)
```

## Phase 0: Load Binary

Use `import_file` to load a binary. It runs Ghidra's headless analyzer automatically:

```
import_file(file_path="/absolute/path/to/binary", auto_analyze=true)
```

After loading:
1. `get_current_program_info` — verify architecture, compiler, format

Read [reference/headless-operations.md](reference/headless-operations.md) if loading binaries or troubleshooting headless server issues.

## Phase 1: Initial Recon

1. `get_current_program_info` — architecture, compiler, format, image base
2. `list_exports` — public API surface, ordinals
3. `list_imports` — dependencies, runtime features, API usage
4. `list_strings` with `filter` param — URLs, paths, error messages, format strings, API names
5. `get_entry_points` — execution entry
6. `list_segments` — memory layout (.text, .data, .rdata, etc.)
7. `get_function_count` + `list_functions` (first 50, sorted by size) — overview
8. `search_byte_patterns` for specific signatures if relevant

Present summary: binary type, likely purpose, key exports, interesting strings, suggested next steps.

## Phase 2: Single Function Documentation (V6)

For the complete step-by-step protocol, read [reference/function-documentation.md](reference/function-documentation.md).

Summary of the V6 workflow:
1. **Initialize**: `decompile_function` + `get_function_variables` — understand current state
2. **Rename**: `rename_function_by_address` with PascalCase verb-first name (check collision first)
3. **Prototype**: `set_function_prototype` — correct types, calling convention (BEFORE comments)
4. **Variables**: `set_variables` for atomic type+rename (eliminates SSA churn vs separate calls)
5. **Structures**: `create_struct` + `add_struct_field` if offset access patterns found
6. **Globals**: `rename_global_variable` with g_ prefix for DAT_*/s_* references
7. **Comments**: `batch_set_comments` — plate + optional PRE + EOL (AFTER all naming/type changes). Verify consistency between function name and plate comment.

## Phase 3: Batch Documentation

For dispatch patterns and failure modes, read the batch section in [reference/function-documentation.md](reference/function-documentation.md).

- **Pre-flight**: `list_instances` + `check_tools` before dispatching any subagents
- **Concurrency**: Max 3 parallel subagents (MCP serializes at HTTP layer)
- **Model selection**: Sonnet default (90%+ quality at 5x lower cost). Opus only for 40+ line functions, scores below 85%, or public API entry points
- **Target selection**: By completeness score (worst first), call graph (leaves first), undocumented (`FUN_*`/`Ordinal_*`), or neighborhood (address-adjacent)
- **Dependency order**: Document callees before callers for better context propagation

## Phase 4: Data Type Investigation

For the complete 7-phase workflow, read [reference/data-type-investigation.md](reference/data-type-investigation.md).

1. **Identify**: Find parameters with generic pointer types (int*, void*, uint*)
2. **Analyze**: Examine offset access patterns in decompiled code and disassembly
3. **Cross-reference**: `get_function_callers` -> `batch_decompile` callers -> merge field offset maps
4. **Search**: `search_data_types` for existing matching structures
5. **Create**: `create_struct` + `add_struct_field` with identity-based naming (UnitAny, not InitializedUnit)
6. **Apply**: `set_parameter_type` or `set_variables` across all functions
7. **Verify**: Re-decompile to confirm fields resolve correctly

## Phase 5: Orphaned Code Discovery

For the scanner script, classification types, and processing order, read [reference/orphaned-code-discovery.md](reference/orphaned-code-discovery.md).

Three-pass scanner finds valid instructions between known functions:
- **Pass 1**: Already-disassembled instructions not in any function (HIGH confidence)
- **Pass 2**: Raw byte prologue patterns — `55 8B EC` (PUSH_EBP+FRAME), SUB_ESP, PUSH_ESI/EDI (VARIABLE)
- **Pass 3**: Fallback — non-padding bytes with RET (LOW confidence)

Classification types A-G. Processing order: B (disassembled), C (standard prologue), D (callee-save), F (getter/wrapper), A (thunk), E (atypical), G (unknown).

For each: `create_function` -> `decompile_function` (sanity check) -> `set_plate_comment` with triage metadata. Full V6 documentation is a separate task.

## Phase 6: Call Graph Analysis

- `get_function_callers` / `get_function_callees` — immediate neighbors
- `get_full_call_graph` or `analyze_call_graph` — deeper traversal
- `get_xrefs_to` / `get_xrefs_from` — data references (strings, globals, vtables)
- `get_bulk_xrefs` — batch cross-reference collection
- `diff_functions` — compare two functions side by side

## Phase 7: Security Analysis

- `detect_malware_behaviors` — behavioral pattern categories
- `find_anti_analysis_techniques` — packing, anti-debug, VM detection
- `extract_iocs_with_context` — strings, IPs, domains, file paths, registry keys
- `analyze_api_call_chains` — threat-relevant API call patterns
- Follow up with targeted decompilation of flagged functions

## Error Handling

| Symptom | Diagnosis | Fix |
|---------|-----------|-----|
| "No program open" | Binary not loaded | Phase 0: load via curl or `open_program` |
| "Connection refused" | MCP server down | Restart bridge: `bash /opt/ghidra-mcp/run-mcp.sh` |
| Plate comment disappeared | Set prototype after comment | Re-apply comments — ordering law violated |
| `extraout_*` / `in_*` variables | Decompiler artifacts | Skip in rename/type ops, note in plate comment |
| Variable rename fails silently | Register-only storage | `force_decompile` then retry, or use PRE_COMMENT |
| Name collision on rename | Duplicate name exists | `search_functions_enhanced` first, differentiate name |
| Struct field shows `undefined4` | Storage vs display mismatch | Normal — call `set_local_variable_type` explicitly |
| `batch_decompile` timeout | Too many functions | Use smaller batches (10-20), not all at once |
| Thunk shows no body docs | JMP-only function documented | Document both thunk AND target body function |
| `create_function` overlap error | Shared epilogue or existing body | Skip — code belongs to adjacent function |
| "No HighVariable found" | Stack arrays, decompiler composites | Skip on first failure, note in plate comment |
| Score < 50% | Severe documentation gaps | Flag for manual review, do not re-dispatch |
| `set_local_variable_type` rejects no-op | Type must actually change | Verify current type differs from target before calling |
| `add_struct_field` replaceAtOffset | Overlays undefined bytes | Only works on undefined/padding bytes — remove existing field first if occupied |
| `check_tools` returns `not_loaded` | Tool group not active | Use `connect_instance` or `load_tool_group` to activate |
| Queries on a newly-loaded binary return the OLD binary's data | Loading does not switch; `current_program` still names the previous program | `switch_program(name)`, verify `is_current: true` via `list_open_programs`, or pass `program=` explicitly |
| Two "different" binaries give identical addresses/xrefs | You are reading one binary | `list_open_programs` — do not trust `get_current_program_info` |
| `get_current_program_info` shows a closed/wrong program | It returns cached data for a dead program | Use `list_open_programs` as source of truth |
| Second load of a same-named file "succeeds" but isn't there | Basename collision — silently lossy | Copy to distinct basenames (`hw_steam.dll`, `hw_csns.dll`) and reload |
| `run_analysis` returns in ~1ms with `new_functions: 0` | No-op on a `load_program`'d program (v4 headless); a huge count returned instantly is a CACHED count | Don't assume it analyzed. Use the byte-pattern workaround (see Pitfalls) or `analyzeHeadless` on the CLI |
| `get_function_by_address` says "No function found" at an address `nm` gave you | `.so`/PIE image base not added | Add `image_base` from `list_open_programs` (commonly `0x10000`); verify on two known symbols |
| `search_byte_patterns` for a string's absolute address returns nothing, but the string IS used | 32-bit PIC — data is reached GOT-relative, never by absolute address | Search `disp = (target - got_base)` instead; try `.got` AND `.got.plt` |
| `search_memory_strings` returns 0 even for a string you grepped out of the file | No strings defined — `load_program` does minimal analysis. On v6 headless the tool is absent entirely, which looks the same from the caller | Use `search_byte_patterns` with ASCII hex; always run a known-present control first |
| `analyzeHeadless` reports "Analysis succeeded" but your call site has no enclosing function | Auto-analysis under-covers large PIC `.so` (e.g. 3.7k functions for 7.5 MB `.text`) | Do not equate "succeeded" with "the functions you need exist". Script the decode over raw bytes (`run_script_inline`) instead of relying on function discovery |

## Critical Pitfalls

- Do NOT assume a loaded binary is the current one — loading does not switch. `switch_program` + verify via `list_open_programs`, or pass `program=` explicitly. Wrong-binary answers do not error; they look correct
- Do NOT load two files with the same basename — the second silently does not exist. Copy to distinct names first
- Do NOT trust `get_current_program_info` — it returns cached data for closed programs. `list_open_programs` is the source of truth
- Do NOT conclude `run_analysis` analyzed anything because it "succeeded" — ~1ms/`new_functions: 0` is a no-op, and an instant ~89k count is cached. When analysis is unavailable, skip it: `search_byte_patterns(<ascii hex of a string>)` -> VA, then `search_byte_patterns(<VA little-endian>)` -> the `PUSH <addr>` site, then `read_memory` and decode by hand. No analysis, no hang risk
- **On a `.so`/PIE, ADD THE IMAGE BASE to every address from `nm`/`readelf`/`objdump`.** A shared object's own vaddrs start at 0; Ghidra loads it at an image base (commonly `0x10000`). `get_function_by_address` then answers "No function found", which reads as *analysis missed it* rather than *you are 64 KB low*. Read `image_base` from `list_open_programs` FIRST, confirm the delta on two known symbols, and do NOT rebase addresses that came FROM Ghidra
- **On a 32-bit PIC `.so`, absolute-address byte search finds NOTHING.** Code references data as `lea reg,[GOTreg + disp32]`, so searching a string's little-endian absolute address returns no hits — indistinguishable from "this string is never used". Compute `disp = (target - got_base) & 0xFFFFFFFF` and search those 4 bytes. Try BOTH `.got` and `.got.plt` as the base (one yields exactly one hit in `.text`, the other none), and do not assume the GOT register is `ebx` — GCC picks per function
- Do NOT use GUI tools in headless mode — `launch_codebrowser`, `goto_address`, `get_current_selection` will fail or return meaningless results
- Always use `import_file` to load binaries — it runs `analyzeHeadless` directly
- Do NOT set comments before prototype — `set_function_prototype` WIPES plate comments. Always: types -> names -> prototype -> comments
- Do NOT retry phantom variables (`extraout_*`, `in_*`) — they are decompiler artifacts, not fixable
- Do NOT trust decompiler display types for storage — `get_function_variables` may show `int` display but `undefined4` storage. Always check and explicitly set types
- Do NOT assume register-only variables survive prototype changes — verify with `get_function_variables` after `set_function_prototype`
- Do NOT document only the thunk (JMP stub) — the implementation body function also needs renaming, prototype, and comments
- Do NOT dump all functions without limit — `list_functions` and `batch_decompile` without offset/limit will blow context budget
- Do NOT use uppercase Windows types (DWORD, BYTE, USHORT) in type-setting operations — always normalize to lowercase builtins (uint, byte, ushort)
- Do NOT skip `search_functions_enhanced` before renaming — name collisions across parallel subagents cause silent overwrites
- Do NOT create functions at switch/case table data — verify with `get_xrefs_to` that the address isn't a jump table entry
- Do NOT use `force_decompile` for final verification — scoring is external in v5
- Do NOT use `batch_rename_variables` — it was renamed to `rename_variables` in v5.0.0
- Do NOT call `analyze_function_completeness` inside the documentation workflow — scoring is external in v5, not part of the per-function protocol
- Do NOT manually add Hungarian prefixes to struct field names — the server auto-prefixes them on `create_struct`, `add_struct_field`, and `modify_struct_field`

## Self-Refinement Protocol

After completing a Ghidra RE task, if you discovered something non-obvious (a decompiler
quirk, a binary-specific pattern, a tool behavior), **apply it to the skill itself** —
`LEARNINGS.md` is a staging buffer, not the destination. Nothing reads `LEARNINGS.md`
during a session, so a learning parked there does no work.

Put it where it will actually be read:

| Kind of learning | Destination |
|---|---|
| A rule to follow every session | General Rules (above) |
| "X looks like Y but is actually Z" | Critical Pitfalls |
| A symptom you can observe | Error Handling table (symptom / diagnosis / fix) |
| Depth on loading, addressing, searching | `reference/headless-operations.md` |
| A tool misbehaving | `reference/gotchas.md` |
| Workflow depth | the matching `reference/*.md` |

Use `LEARNINGS.md` only to park something you cannot place yet — then fold it in and
delete the entry. A growing `LEARNINGS.md` means the skill is not being maintained.
Never write "see LEARNINGS" into `SKILL.md`: inline the knowledge where it is needed.

## Reference Files

Load these as needed during your workflow:

- [reference/tool-categories.md](reference/tool-categories.md) — When you need to find the right MCP tool name (~222 tools by category; live `/mcp/schema` is authoritative)
- [reference/function-documentation.md](reference/function-documentation.md) — When documenting functions (V6 protocol + batch dispatch)
- [reference/data-type-investigation.md](reference/data-type-investigation.md) — When investigating struct types from usage patterns
- [reference/orphaned-code-discovery.md](reference/orphaned-code-discovery.md) — When scanning for hidden/missed functions
- [reference/hungarian-notation.md](reference/hungarian-notation.md) — When renaming variables (type-to-prefix table)
- [reference/headless-operations.md](reference/headless-operations.md) — When loading binaries or troubleshooting headless mode
- [reference/gotchas.md](reference/gotchas.md) — When a tool misbehaves (empty `search_strings`, "Auto-analysis failed", load timeouts, GUI-only errors, version mismatches) — non-obvious failure modes + fixes
- [reference/dynamic-analysis.md](reference/dynamic-analysis.md) — When static analysis leaves you stuck: confirm offsets/behavior at runtime (run the target headless under Wine, drive it live via `/proc/<pid>/mem`, `WINEDEBUG` crash triage, the clean-DLL-stub methodology, `tcpdump` protocol RE, PE rebasing/patching)
