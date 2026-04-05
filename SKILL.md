---
name: ghidra-re
description: Reverse engineer, decompile, and analyze binaries using 158 Ghidra MCP tools. Covers function documentation, data type investigation, orphaned code discovery, call graph analysis, struct creation, variable renaming, binary reconnaissance, and malware analysis. Use when the user mentions Ghidra, decompilation, disassembly, binary analysis, DLL/EXE investigation, function renaming, malware analysis, or references function addresses like 0x401000. Do NOT use for source-level debugging, dynamic analysis, or non-Ghidra RE tools.
allowed-tools: mcp__ghidra__* Bash(curl:*)
when_to_use: "Use when the user wants to reverse engineer or analyze a binary with Ghidra. Examples: 'analyze this binary', 'decompile this function', 'what does this DLL do', 'document all functions', 'find hidden functions', 'create a struct', 'trace the call graph', 'check for malware', 'rename this function at 0x401000'."
argument-hint: "[function address, binary path, or task description]"
metadata:
  author: coffeegrind123
  version: "1.2"
---

# Ghidra MCP Reverse Engineering

## General Rules

1. **Pre-flight**: Always `check_connection` before any session work. Without this, all subsequent MCP calls will fail silently or with cryptic errors.

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

## v5.0.0 Breaking Changes

GhidraMCP v5.0.0 uses a bridge with dynamic tool discovery instead of 193 hardcoded handlers. Key changes:

- **Tool count**: 158 tools via bridge (152 from schema + 6 static bridge tools) — down from 193 because the bridge auto-discovers tools dynamically
- **`batch_rename_variables` renamed to `rename_variables`**: The old name no longer exists. Use `rename_variables` for all variable rename operations.
- **`set_variables` is new**: Atomic type+rename in one call. Preferred over separate `batch_set_variable_types` + `rename_variables` to avoid SSA churn.
- **`batch_set_comments` arrays now optional**: `decompiler_comments` and `disassembly_comments` arrays are optional — you can pass only `plate_comment` if that's all you need.
- **`analyze_function_completeness` removed from documentation workflow**: Scoring is now external in v5. Do not call it inside the function documentation protocol.
- **Struct field Hungarian prefixes are server-enforced**: `create_struct`, `add_struct_field`, and `modify_struct_field` auto-prefix field names. Do not manually add prefixes.
- **Bridge tools**: `check_connection`, `list_instances`, `connect_instance`, `load_tool_group`, `check_tools`, `store_function_knowledge` are static bridge tools always available.
- **`check_tools` returns `not_loaded`**: If a tool group isn't loaded, use `connect_instance` or `load_tool_group` to activate it.

## Lifecycle

```
check_connection -> [load binary or verify current program] -> get_current_program_info
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

The headless server's `/load_program` is NOT an MCP tool. Load via HTTP directly:

```bash
curl -s -X POST http://127.0.0.1:8089/load_program -d "file=/absolute/path/to/binary"
```

After loading:
1. `run_analysis` — trigger Ghidra auto-analysis
2. `get_current_program_info` — verify architecture, compiler, format

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

- **Pre-flight**: `check_connection` before dispatching any subagents
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

## Critical Pitfalls

- Do NOT use GUI tools in headless mode — `launch_codebrowser`, `goto_address`, `get_current_selection` will fail or return meaningless results
- Do NOT try to load binaries via MCP tools — `/load_program` is HTTP-only, not exposed in the MCP bridge
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

After completing a Ghidra RE task, if you discovered something non-obvious (a decompiler quirk, a binary-specific pattern, a tool behavior), append it to `LEARNINGS.md`:

```
## YYYY-MM-DD: <brief title>
- **Context**: What you were analyzing
- **Learning**: What was non-obvious
- **Rule**: The new rule to follow
```

## Reference Files

Load these as needed during your workflow:

- [reference/tool-categories.md](reference/tool-categories.md) — When you need to find the right MCP tool name (158 tools by category)
- [reference/function-documentation.md](reference/function-documentation.md) — When documenting functions (V6 protocol + batch dispatch)
- [reference/data-type-investigation.md](reference/data-type-investigation.md) — When investigating struct types from usage patterns
- [reference/orphaned-code-discovery.md](reference/orphaned-code-discovery.md) — When scanning for hidden/missed functions
- [reference/hungarian-notation.md](reference/hungarian-notation.md) — When renaming variables (type-to-prefix table)
- [reference/headless-operations.md](reference/headless-operations.md) — When loading binaries or troubleshooting headless mode
