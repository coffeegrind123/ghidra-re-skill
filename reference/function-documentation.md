# Function Documentation Protocol (V6)

## Critical Rules

1. **Ordering**: Complete ALL naming, prototype, and type changes BEFORE plate comment and inline comments. `set_function_prototype` wipes existing plate comments.
2. **Batching**: Use `set_variables` (atomic type+rename), `batch_set_comments` (plate + optional PRE + EOL in one call). Never loop individual rename/comment calls.
3. **Phantoms**: `extraout_*`, `in_*` variables with `undefined` types are decompiler artifacts. Note in plate comment Special Cases, skip — do not retry type-setting.
4. **Reprocessing**: When re-documenting, always overwrite existing names/comments if analysis produces better results.
5. **Consistency check**: Function name and plate comment must align — the plate comment's one-line summary should describe what the function name implies.
6. **Module prefix decision**: Apply a module prefix (e.g., `Net_SendPacket`, `Gfx_DrawSprite`) using a 2-signal gate: at least 2 of (source file context, behavior domain, callee family) must agree on the module.
7. **Struct creation gate**: Reuse existing structs first. Only create new structs when 3+ validated fields exist across 2+ code paths.

## Step 1: Initialize and Classify

Call `decompile_function` and `get_function_variables` in parallel.

From the results:
- Verify function boundaries; recreate with correct range if incorrect
- If `return_type_resolved` is false: verify EAX at each RET instruction
- Validate existing names — even custom names may be wrong
- Classify the function:

| Classification | Criteria | Depth |
|---|---|---|
| **Thunk/Wrapper** | Single call, no logic | Fast path: Steps 2->6->7 only |
| **Leaf** | No outgoing calls | Focus on algorithm, data flow |
| **Worker** | Meaningful logic with calls | Full workflow |
| **Init/Cleanup** | State setup/teardown | Document sequence and side effects |
| **Callback/Handler** | Event-driven entry | Document triggers and expected state |
| **Public API** | Exported symbol | Maximum rigor, all sections |

## Step 2: Rename Function + Set Prototype

Call `rename_function_by_address` and `set_function_prototype` in parallel.

**Naming**: PascalCase, verb-first (GetPlayerHealth, ProcessInputEvent, ValidateItemSlot). Check collisions with `search_functions_enhanced` first.

**Prototype**: Use typed struct pointers (UnitAny* not int*) and Hungarian camelCase params. Verify calling convention from disassembly.

**Note**: Prototype changes trigger re-decompilation and may create new SSA variables. Always re-fetch variables in Step 3.

## Step 3: Type Audit + Variable Renaming

**IMPORTANT**: Always call `get_function_variables` explicitly — the decompiler may display `int` or `char*` while storage is still `undefined4`. Only `get_function_variables` reveals actual storage types.

**Skip condition**: All variables have custom names AND resolved storage types (no `undefined` in type field).

**Workflow**:
1. `get_function_variables` — check actual storage types
2. Identify variables needing type changes and name changes
3. For failed renames -> PRE_COMMENT. For assembly-only vars -> EOL_COMMENT.

## Step 4: Atomic Variable Type+Rename

Use `set_variables` for atomic type+rename operations. This is preferred over separate `batch_set_variable_types` + `rename_variables` calls because it eliminates SSA churn — the decompiler only re-analyzes once instead of twice.

**Workflow**:
1. Build a single `set_variables` call covering ALL variables that need type changes and/or renames
2. Use lowercase Ghidra builtins (uint, ushort, byte) for types
3. Apply Hungarian prefixes in the rename portion — prefix must match the type being set
4. If variable is dereferenced or has offset arithmetic -> type as pointer (`int *` not `int`)
5. `get_function_variables` after to verify no `undefined` remains and discover new SSA variables
6. If new SSA variables appeared, run a second `set_variables` pass

## Step 5: Structures (skip if none)

**Skip condition**: No field-offset patterns (+0x10, +0x14, etc.) in decompiled code.

**Struct creation gate**: Reuse existing structs first (`search_data_types`). Only create new structs when 3+ validated fields exist across 2+ code paths.

Use `search_data_types` to find matching types. If none exist, create with `create_struct`. Fix duplicates with `consolidate_duplicate_types`.

Note: `add_struct_field` with `replaceAtOffset` behavior overlays undefined bytes only — remove existing fields first if the offset is occupied.

## Step 6: Global Data (skip if none)

**Skip condition**: No DAT_* or s_* names in decompiled code.

Rename ALL DAT_* and s_* globals referenced by this function:
- `apply_data_type` to set type, `rename_or_label` with g_ prefix + Hungarian notation
- DAT_* -> g_dw/g_p/g_pfn/g_a depending on type
- s_* -> g_sz (ANSI) / g_wsz (wide) / g_szFmt (format) / g_szPath (path)

## Step 7: Plate Comment + Inline Comments

**IMPORTANT**: This must be AFTER all naming/prototype/type changes are complete.

Use `batch_set_comments`. The `decompiler_comments` and `disassembly_comments` arrays are now optional in v5.0.0 — you can pass only `plate_comment` if inline comments aren't needed.

**Consistency check**: Verify the plate comment's one-line summary aligns with the function name. If the function is named `ValidatePacketHeader`, the summary should describe packet header validation, not something unrelated.

**Plate comment format** (plain text only):
```
One-line function summary.

Algorithm:
1. [Step with hex magic numbers, e.g., "check type == 0x4e (78)"]
2. [Each step is one clear action]

Parameters:
  paramName: Type - purpose description [IMPLICIT EDX if register-passed]

Returns:
  type: meaning. Success=non-zero, Failure=0/NULL. [all return paths]

Special Cases:
  - [Edge cases, phantom variables, decompiler discrepancies]

Structure Layout: (if accessing structs)
  Offset | Size | Field     | Type  | Description
  +0x00  | 4    | dwType    | uint  | ...
```

**Decompiler PRE_COMMENTs**: At block-start addresses — context, purpose, algorithm step references. Max ~60 chars.
**Disassembly EOL_COMMENTs**: At instruction addresses — concise, max 32 chars. Match to assembly addresses, not decompiler line order.

## Output

```
DONE: FunctionName
Changes: [brief summary]
```

---

## Batch Documentation Protocol

### Pre-flight

1. `check_connection` — if connection refused, stop immediately
2. Verify program is loaded: `get_current_program_info`

### Dispatch Pattern

Max 3 subagents at once. Each subagent follows the V6 protocol above independently.

```
Agent(
  model: "sonnet",  // default
  description: "Document FunctionName",
  prompt: "Follow the V6 function documentation protocol to document
  the function at address 0xADDRESS (currently named 'FUN_XXXXXXXX').

  CRITICAL reminders:
  - Call get_function_variables to check actual storage types
  - Use set_variables for atomic type+rename (not separate calls)
  - If variable is dereferenced -> type as pointer, not int
  - Document BOTH thunk AND body for JMP stubs
  - search_functions_enhanced before renaming to check collisions
  - batch_set_comments decompiler/disassembly arrays are optional
  - Do NOT call analyze_function_completeness (scoring is external)

  Return DONE output when complete."
)
```

### Model Selection

| Condition | Model |
|-----------|-------|
| Default (90%+ of functions) | Sonnet |
| 40+ decompiled lines, deep algorithm | Opus |
| First-pass Sonnet score < 85% | Opus retry |
| Public API entry point | Opus |

### Target Selection Strategies

**By completeness score**: `batch_analyze_completeness` -> filter < 70% -> sort ascending (worst first)

**By call graph**: `get_function_call_graph` -> topological sort -> leaves first, callers after

**By undocumented**: `list_functions` filtered to `FUN_*` or `Ordinal_*` prefix -> batches of 3

**By neighborhood**: Pick documented anchor -> `list_functions` for adjacent undocumented entries

### Common Failure Modes

- **Register-only variables losing symbols**: Call `force_decompile` first to refresh, then retry `get_function_variables`
- **Storage still `undefined4` despite display type**: Explicitly call `set_local_variable_type` with the same type to resolve
- **Thunk-only documentation**: Subagent renames thunk but not implementation body. Verify by checking the body address
- **Name collisions**: Subagents choosing names independently may assign same name. Search for duplicates after each batch
- **`p`-prefix variable typed as `int`**: If variable is dereferenced, must be typed as pointer (`int *`)
- **"No HighVariable found"**: Common for stack arrays. Skip on first failure, note in plate comment

### Error Handling

- Subagent timeout/connection error: retry once, then skip and log
- Score < 50%: flag for manual review
- Score 50-70% with only unfixable deductions (`all_deductions_unfixable`): accept as complete
