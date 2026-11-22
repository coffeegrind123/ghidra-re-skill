# Function Documentation Protocol

## Critical Rules

1. **Loop**: read -> plan -> ONE labelled `batch` per coherent change -> re-read -> save. Never
   loop single rename or comment calls.
2. **Atomic means all or nothing**: one bad op (a phantom variable, a stale name, a type the
   parser does not know) rolls back the whole batch. The error names `op_index`, `tool` and
   `error_type`. Fix that op and resend. Use `dry_run=true` to validate a large plan.
3. **Order inside a batch**: types -> function name -> prototype -> globals -> locals ->
   comments. Plate comments survive `set_function_prototype` on this server; the order is so
   comments describe final names, not to avoid a wipe.
4. **Addresses after a rename**: the old `FUN_*` / `DAT_*` name is gone once renamed. Later ops
   use `"$N.address"` from the rename's result, or the hex address.
5. **Phantoms**: `extraout_*`, `in_*` variables with `undefined` types are decompiler
   artifacts. Leave them out of batches; note them in the plate's Special Cases.
6. **Reprocessing**: when re-documenting, overwrite names and comments if the new analysis is
   better.
7. **Consistency**: the plate comment's one-line summary must describe what the function name
   says.
8. **Module prefix**: add one (`Net_SendPacket`, `Gfx_DrawSprite`) only when at least 2 of
   (source file context, behaviour domain, callee family) agree on the module.
9. **Struct gate**: reuse existing structs first. Create a new one only with 3+ validated
   fields across 2+ code paths.

## Step 1: Read and Classify

Read in parallel: `decompile_function`, `list_decompiler_variables`, `get_function`
(bounds, `signature`, `is_thunk`), `get_xrefs_from` (callees, globals, strings).

- Check function bounds (`list_function_ranges`). Wrong bounds give wrong pseudocode.
- If the return type looks wrong, check EAX/RAX (or the ABI return register) at each RET in
  `disassemble_function`.
- Existing custom names can be wrong; check them.

| Classification | Criteria | Depth |
|---|---|---|
| Thunk/Wrapper | Single call or JMP, no logic | Name + prototype + short plate; then document the target |
| Leaf | No outgoing calls | Algorithm and data flow |
| Worker | Logic with calls | Full protocol |
| Init/Cleanup | State setup/teardown | Sequence and side effects |
| Callback/Handler | Event-driven entry | Triggers and expected state |
| Public API | Exported symbol | Maximum rigour, all sections |

## Step 2: Plan

- **Name**: PascalCase, verb first (`ParseConfigBlock`, `ValidatePacketHeader`). Check it is
  free: `list_functions(filter_pattern="^ParseConfigBlock$")` returns `total: 0`.
- **Prototype**: typed struct pointers (`Connection *`, not `int *`), Hungarian camelCase
  parameter names, Ghidra builtins (`byte`, `uint`, `ushort`, `char *`). `uint8_t`, `size_t`
  and SDK types fail to parse unless a type archive defines them. Check the calling
  convention in the disassembly.
- **Globals**: every `DAT_*` and `s_*` the function uses gets a type and a `g_` Hungarian
  name. `DAT_*` -> `g_dw` / `g_p` / `g_pfn` / `g_a` by type; `s_*` -> `g_sz` / `g_wsz` /
  `g_szFmt` / `g_szPath`.
- **Locals**: from `list_decompiler_variables`, decide type then name. If a variable is
  dereferenced or used with offset arithmetic, type it as a pointer.

## Step 3: Batch A, identity

```json
batch(database="fw_bin", label="doc ParseConfigBlock: identity",
      if_revision=2210, operation_id="doc-4012a0-a", ops=[
  {"tool": "rename_function", "params": {"address": "FUN_004012a0", "new_name": "ParseConfigBlock"}},
  {"tool": "set_function_prototype", "params": {"address": "$0.address", "type_string":
     "int ParseConfigBlock(ConfigBlock *pConfig, char *szText, uint dwLength)"}},
  {"tool": "set_type", "params": {"address": "0x40c120", "type_string": "char *"}},
  {"tool": "rename_symbol", "params": {"address": "0x40c120", "new_name": "g_szConfigPath"}}])
```

Leave local variables for batch B: the prototype change re-runs the decompiler, so read
their names again first.

## Step 4: Re-read

`list_decompiler_variables` and `decompile_function` again. Look for remaining `undefined`
types, new temporaries, and parameters the prototype did not cover. The decompiler display
type can differ from the stored type; trust `list_decompiler_variables`.

## Step 5: Batch B, body and comments

```json
batch(database="fw_bin", label="doc ParseConfigBlock: body",
      operation_id="doc-4012a0-b", ops=[
  {"tool": "rename_decompiler_variable", "params": {"function_address": "0x4012a0",
     "old_name": "uVar3", "new_name": "dwKeyHash"}},
  {"tool": "set_comment", "params": {"address": "0x4012a0", "comment_type": "plate",
     "comment": "Parses one key=value config block into pConfig.\n\nAlgorithm:\n1. ..."}},
  {"tool": "set_comment", "params": {"address": "0x4012d4", "comment_type": "pre",
     "comment": "Step 2: hash the key"}},
  {"tool": "set_comment", "params": {"address": "0x4012e9", "comment_type": "eol",
     "comment": "len > 0x100 -> reject"}}])
```

If a rename keeps failing (register-only storage, stack arrays), drop it from the batch and
put the meaning in a PRE comment at the first use instead.

**Plate comment format** (plain text):
```
One-line function summary.

Algorithm:
1. [Step with hex magic numbers, e.g. "check type == 0x4e (78)"]
2. [One clear action per step]

Parameters:
  paramName: Type - purpose [IMPLICIT EDX if register-passed]

Returns:
  type: meaning. Success=non-zero, Failure=0/NULL. [all return paths]

Special Cases:
  - [Edge cases, phantom variables, decompiler discrepancies]

Structure Layout: (if the function accesses a struct)
  Offset | Size | Field     | Type  | Description
  +0x00  | 4    | dwType    | uint  | ...
```

PRE comments (`comment_type="pre"`, shown above the line in pseudocode): at block starts,
about 60 characters. EOL comments (`"eol"`): at instruction addresses, about 32 characters.
Match them to assembly addresses, not decompiler line order.

## Step 6: Verify and save

`decompile_function` once more; the plate summary must match the name.
`score_documentation(filter_pattern="^ParseConfigBlock$", include_locals=true)` should return
no items (the default `max_score=99` hides fully documented functions).
`save_database(database, comment="doc ParseConfigBlock")`.

## Output

```
DONE: FunctionName
Changes: [brief summary]
```

---

## Batch Documentation Protocol

### Pre-flight

1. `list_databases`: the database is open and ready. If not, `open_database` +
   `wait_for_analysis`.
2. Pick targets (below). Give each subagent the `database` id.

### Target selection

- **By gaps**: `score_documentation(max_score=60, limit=20)` returns `items` of
  `{address, name, score, missing}`, worst first. `include_locals=true` also checks local
  names (one decompile per listed function, slower).
- **By call graph**: leaves first. `execute(read_only=true)` walking `getCalledFunctions` (see
  SKILL.md) returns unnamed functions deepest first.
- **By name**: `list_functions(filter_pattern="^FUN_", limit=50)`.
- **By neighbourhood**: a documented anchor, then the undocumented functions next to it.

Document callees before callers.

### Dispatch

Each database is served by one worker, and writes to it run one at a time. More than about 3
subagents per database mostly wait.

```
Agent(
  model: "sonnet",
  description: "Document FUN_004012a0",
  prompt: "Use the ghidra-re skill. Database id: fw_bin. Document the function at 0x4012a0
  (currently FUN_004012a0) with the function documentation protocol.

  - Read first: decompile_function, list_decompiler_variables, get_function, get_xrefs_from.
  - Check the name is free with list_functions(filter_pattern='^Name$').
  - Two batches (identity, then body and comments), each with a label, if_revision from your
    last read, and operation_id 'doc-4012a0-a' / 'doc-4012a0-b'.
  - On TargetChanged: re-read and retry. Leave extraout_/in_ variables out.
  - If it is a thunk, also document the function it jumps to.
  - save_database when done. Return the DONE block."
)
```

### Model selection

| Condition | Model |
|---|---|
| Default | Sonnet |
| 40+ decompiled lines, deep algorithm | Opus |
| Public API entry point | Opus |
| Poor first pass (score still low) | Opus retry |

### Common failure modes

- **Name collisions**: two subagents pick the same name. Check before renaming; after a round,
  `list_functions(filter_pattern=...)` for duplicates.
- **Thunk-only documentation**: the stub is named, the body is still `FUN_*`. Check the JMP
  target.
- **`p` prefix on an `int`**: a dereferenced variable must be typed as a pointer.
- **Batch rolled back on one variable**: re-read the variable list; the name changed or it is a
  phantom.
- **Retry applied twice**: use `operation_id` on every write a subagent might resend.

### Error handling

- Subagent tool error: read `error_type`, fix, retry once; then skip and log the address.
- Score still under 50 after a pass: flag for manual review.
