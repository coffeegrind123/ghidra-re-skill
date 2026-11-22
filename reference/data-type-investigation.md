# Data Type Investigation Workflow

## Core Principle

Find a type from how it is used across ALL functions that touch it. One function shows a few
fields; the callers together show the structure.

## Phase 1: Find Targets

Parameters with generic pointer types that should be typed:
`int *pConn`, `uint *pData`, `void *pBuffer`, `undefined4 param_1` used with offsets.

**Tools**: `decompile_function`, `list_decompiler_variables`, `list_functions(filter_pattern=...)`,
or `search_text(pattern="\\[E[A-Z]X \\+ 0x[0-9a-f]+\\]")` for offset accesses (x86).

Track findings:
```
| Function | Address | Parameter | Current Type | Offsets Accessed | Inferred Type |
|----------|---------|-----------|--------------|------------------|---------------|
```

## Phase 2: Single Function Analysis

1. `decompile_function` and `disassemble_function` on the function.
2. Find offset accesses in both views:
   ```asm
   MOV EAX, [ESI + 0x4]        ; field at 0x4
   CMP DWORD PTR [ESI + 0xC], 0 ; field at 0xC
   ```
3. Infer field types from use:
   - incremented / counted -> `uint`
   - compared with small values (< 256) -> `byte`
   - shifted or masked -> bit field or index
   - dereferenced -> pointer field

## Phase 3: Cross-Reference Analysis

1. `get_xrefs_to(address=<function>)` or `get_call_graph(address, depth=1)` for the callers.
2. Decompile each caller (`decompile_function`; or `decompile_functions(filter_pattern=...)`
   for a group sharing a name pattern, with a small `limit`).
3. For many callers, collect accesses in one read-only `execute` call instead of N decompiles
   in your context:
   ```python
   import re
   fm = program.getFunctionManager()
   target = fm.getFunctionContaining(toAddr("0x401000"))
   rows = {}
   for caller in target.getCallingFunctions(monitor):
       code = decompile(caller)
       for off in re.findall(r"\+ (0x[0-9a-f]+)\)", code):
           rows.setdefault(off, set()).add(caller.getName())
   return {k: sorted(v) for k, v in sorted(rows.items(), key=lambda kv: int(kv[0], 16))}
   ```
   The regex is a starting point; read the pseudocode of anything ambiguous.
4. Build the master offset map:

```
| Offset | Size | Field Name | Type | Access | Accessed By |
|--------|------|-----------|------|--------|-------------|
| 0x0 | 4 | dwType | uint | R | ProcessConn, ValidateConn |
| 0x4 | 4 | dwFlags | uint | R/W | ProcessConn, ModifyConn |
| 0x8 | 4 | pNext | Connection * | R | EnumerateConns |
```

5. Note gaps and alignment padding.

## Phase 4: Search Existing Types

```
list_structures(filter_pattern="Conn")
get_structure(name="Connection")
list_data_types(filter_pattern="Conn")
```

If most offsets match an existing structure, use it. Check the size via:
- array stride: `LEA ECX, [EBX + EAX*0x23C]` -> stride 0x23C
- allocation size: the malloc/calloc/new argument

## Phase 5: Create the Structure

Field names use Hungarian prefixes; the server does not add them. Prefer one
`parse_type_declaration` with the full layout. Use Ghidra builtins: `uint8_t`/`size_t` fail to
parse unless a type archive defines them.

```json
batch(database="fw_bin", label="type Connection", operation_id="type-connection-v1", ops=[
  {"tool": "parse_type_declaration", "params": {"declaration":
     "struct Connection { uint dwType; uint dwFlags; struct Connection *pNext; ushort wPort; byte bState; byte bPadding; };"}},
  {"tool": "set_function_prototype", "params": {"address": "0x401000",
     "type_string": "int ProcessConn(${0.type_name} *pConn)"}},
  {"tool": "retype_decompiler_variable", "params": {"function_address": "0x401200",
     "variable_name": "param_1", "new_type": "Connection *"}}])
```

For fields known only by offset, start with `create_structure(name, size=N)` and place members
with `add_struct_member(struct_name, member_name, member_type, offset=0x..)`, which replaces
the undefined bytes at that offset. Change members later with `rename_struct_member` and
`retype_struct_member`.

**Identity-based naming**: names say what the object IS (`Connection`, `Session`), not its state
(`InitializedConnection`, `ProcessedData`).

**Helper structures**: separate types for static templates (`HandlerTableEntry`), runtime state
(`HandlerState`), and parameter blocks (`HandlerParams`).

## Phase 6: Apply

For each function that uses it, in the same batch or the next one:
- `set_function_prototype` with `Connection *pConn`, or
- `retype_decompiler_variable(function_address, variable_name, "Connection *")`.

For a global instance: `apply_type_at_address(address, type_name="Connection")`, then
`rename_symbol` with a `g_` name.

## Phase 7: Verify

1. `decompile_function` on each user: field names should replace raw offsets.
2. `get_structure(name)`: offsets and size match the assembly accesses.
3. All functions agree on each field's type.
4. Alignment: the largest field sets it (4-byte fields -> 4-byte alignment).
5. Size matches the stride or allocation size.
6. `save_database`.

## Checklist

- [ ] All functions using the structure found
- [ ] Offset map complete
- [ ] Existing types searched
- [ ] Structure created with an identity name and Hungarian field names
- [ ] Every user's prototype or variable retyped
- [ ] Types confirmed with `list_decompiler_variables`
- [ ] Field offsets match the assembly
- [ ] Size matches stride or allocation
- [ ] Helper structures created where needed
