# Data Type Investigation Workflow

## Core Principle

Investigate how parameters are used across ALL functions to determine true data type. Don't guess from a single instance — cross-reference reveals complete structure definitions.

## Phase 1: Target Pattern Identification

Find parameters with generic pointer types that should be properly typed:
- `int *pUnit`, `uint *pData`, `void *pBuffer`

**Tools**: `search_functions_enhanced` with patterns, `get_function_variables`, `analyze_function_complete`

Track findings:
```
| Function | Address | Parameter | Current Type | Offsets Accessed | Inferred Type |
|----------|---------|-----------|--------------|------------------|---------------|
```

## Phase 2: Single Function Analysis

1. `analyze_function_complete(name, include_xrefs=true, include_disasm=true)`
2. Find offset access patterns in both decompiled and assembly views:
   ```asm
   MOV EAX, [pUnit + 0x4]    # Field at offset 0x4
   CMP DWORD [pUnit + 0xC], 0  # Field at offset 0xC
   ```
3. Determine field types from usage:
   - Increment patterns (++dw → uint)
   - Comparison values (< 256 → byte)
   - Shift operations → bit field or index
   - Dereferenced → pointer field

## Phase 3: Cross-Reference Analysis

1. `get_function_callers` — find all functions using the same parameter type
2. `batch_decompile` callers — cross-reference field accesses
3. Build master offset map from ALL functions:

```
| Offset | Size | Field Name | Type | Access | Accessed By |
|--------|------|-----------|------|--------|-------------|
| 0x0 | 4 | dwType | uint | R | ProcessUnit, ValidateUnit |
| 0x4 | 4 | dwFlags | uint | R/W | ProcessUnit, ModifyUnit |
| 0x8 | 4 | pNext | UnitAny * | R | EnumerateUnits |
```

4. Identify gaps and alignment padding between fields

## Phase 4: Search Existing Structures

```
search_data_types(pattern="Unit")
get_struct_layout(struct_name)
```

Compare your offset map against existing structure layouts. If most offsets match, use the existing structure.

Verify structure size via:
- Array stride patterns: `LEA ECX, [pBase + EAX*0x23C]` → stride = 0x23C
- Allocation size: malloc/calloc argument values

## Phase 5: Create Structure (if needed)

```
create_struct("StructName", [
    {"name": "dwType", "type": "uint"},
    {"name": "dwFlags", "type": "uint"},
    {"name": "pNext", "type": "StructName *"},
    {"name": "wHealth", "type": "ushort"},
    {"name": "bPadding", "type": "byte"},
])
```

**Identity-based naming**: Names describe what the object IS (UnitAny, Skill), not state (InitializedUnit, ProcessedData).

**Helper structures**: Create separate structures for:
- Static data (SkillTableEntry): read-only templates
- Dynamic data (SkillObject): runtime state
- Parameter blocks (SkillData): execution parameters

## Phase 6: Type Application

For each function using the structure:
```
set_parameter_type(function_address, parameter_name, "StructName *")
```

Or use `set_variables` for atomic type+rename across multiple variables at once.

After applying, `force_decompile` to refresh — decompiled view will show proper field names instead of raw offsets.

## Phase 7: Verification

1. **Field offset verification**: Compare structure fields against actual assembly access patterns
2. **Type consistency**: Verify all functions accessing the same field agree on type
3. **Cross-function patterns**: All functions null-check, read same fields consistently
4. **Alignment**: Largest field determines alignment. DWORD fields → 4-byte alignment
5. **Structure size**: Matches expected stride or allocation size

## Verification Checklist

- [ ] All functions using the structure identified
- [ ] Offset map complete from all functions
- [ ] Existing structures searched
- [ ] Structure created with identity-based name
- [ ] All functions updated with correct parameter types
- [ ] Type application verified with `get_function_variables`
- [ ] Decompilation refreshed
- [ ] Field offsets match assembly access
- [ ] Structure size matches stride/allocation
- [ ] Helper structures created for complex types
