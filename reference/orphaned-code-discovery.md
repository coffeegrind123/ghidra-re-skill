# Orphaned Code Discovery Workflow

## Critical Rules

1. **Never auto-create without review**: Scanner finds candidates. You classify and confirm each one before `create_function`.
2. **Iterative**: After creating functions, re-run scanner — new gaps appear as boundaries shift.
3. **Minimal intervention**: Create functions + triage plate comment only. Full V5 documentation is separate.
4. **Multi-binary safe**: `get_current_program_info()` to verify program context before writing.

## Step 0: Select Scope

| Scope | How |
|-------|-----|
| Current binary | Run scanner once |
| Version folder | `list_project_files()` → iterate with `switch_program()` |
| All binaries | `list_project_files("/")` recursively |

## Step 1: Run Scanner

Execute via `run_script_inline`. The scanner performs three passes per gap between consecutive known functions:

**Pass 1**: Already-disassembled instructions not in any function (HIGH confidence)
**Pass 2**: Raw bytes matching known prologue patterns (VARIABLE confidence)
**Pass 3**: Fallback — non-padding bytes with RET (LOW confidence)

### Prologue Patterns (x86)

| Pattern | Bytes | Confidence |
|---------|-------|------------|
| HOTPATCH+FRAME | `8B FF 55 8B EC` | HIGH |
| PUSH_EBP+FRAME | `55 8B EC` | HIGH |
| SUB_ESP_IMM8 | `83 EC xx` | MEDIUM (≥5 bytes) |
| SUB_ESP_IMM32 | `81 EC xx xx xx xx` | MEDIUM (≥5 bytes) |
| PUSH_ESI | `56` | MEDIUM (≥4 bytes) |
| PUSH_EDI | `57` | MEDIUM (≥4 bytes) |
| PUSH_EBX | `53` | MEDIUM (≥4 bytes) |
| PUSH_ECX | `51` | MEDIUM (≥4 bytes) |
| MOVSX variants | `0F BE`, `0F BF` | MEDIUM |
| MOVZX variants | `0F B6`, `0F B7` | MEDIUM |
| XOR_R32 | `33 xx` | MEDIUM (≥4 bytes) |
| TEST_R32 | `85 xx` | MEDIUM (≥4 bytes) |

Padding bytes filtered: `0xCC` (INT3), `0x90` (NOP), `0x00`.

## Step 2: Classify Candidates

### Type A: Import Thunk / Trampoline
- Single JMP instruction (5 bytes)
- Action: `create_function` → plate: `"Import thunk — redirects to <target>"`
- Priority: Low

### Type B: Already Disassembled — Real Function
- HIGH confidence, N > 1 instructions
- Ghidra analyzed but never created function boundary
- Action: `create_function` → decompile → triage plate comment
- Priority: **Highest**

### Type C: Standard Prologue (HIGH)
- PUSH_EBP+FRAME or HOTPATCH+FRAME
- Action: `create_function` (auto-disassembles) → decompile → triage plate
- Priority: High

### Type D: Callee-Save / Operand Prologue (MEDIUM)
- PUSH_ESI, PUSH_EDI, SUB_ESP, MOVSX/MOVZX, XOR, TEST
- Action: `create_function` → decompile → verify standalone function
- Watch for: tail-call targets (via JMP only — should NOT be separate function)
- Common: CRT character classification, string utilities

### Type E: Atypical Start (LOW)
- MOV, PUSH_IMM, CALL_REL32, CMP, etc.
- Action: Inspect first with `inspect_memory_content` or `disassemble_bytes`
- Red flags: address tables, very short sequences (< 8 bytes)

### Type F: Getter / Converter / Thin Wrapper
- Any type, estimated size < 15 bytes
- Sub-patterns: `MOV EAX,[addr]; RET`, `PUSH imm; CALL rel32; RET`
- Action: `create_function` → name if purpose obvious

### Type G: Unknown Prologue (REVIEW)
- Pass 3 hit — first byte doesn't match any known prologue
- Always inspect first with `disassemble_bytes`
- Check MULTI-RET(N) flag — gap likely contains N adjacent functions

## Step 3: Create Functions (Batch)

**Processing order**: B, C, D, F, A, E, G

For each approved candidate:
1. `create_function(address)`
2. `decompile_function(address)` — sanity check
3. `set_plate_comment` with triage metadata:

```
[TRIAGE] Orphaned code discovered by scanner.
Type: <A|B|C|D|E|F|G> — <description>
Confidence: <HIGH|MEDIUM|LOW>
Size: ~N bytes / N instructions
Neighboring: <prev_function> .. <next_function>
Status: Awaiting full documentation (FUNCTION_DOC_WORKFLOW_V6)
```

Process in batches of 5-10. After each batch: verify no errors, spot-check 1-2 decompilations.

## Step 4: Report

```
=== ORPHANED CODE REPORT: <program_name> ===
Created: N functions
  Type A (thunks): N
  Type B (disassembled): N
  Type C (standard prologue): N
  Type D (callee-save): N
  Type E (atypical): N
  Type F (getter/wrapper): N
  Type G (unknown): N
Skipped: N (data/jump table/fragment)
Next: Re-run scanner for newly exposed gaps
```

## Edge Cases

- **Non-contiguous bodies**: Function at [0x100-0x110, 0x130-0x140] creates gap that may belong to same function. Check xrefs first.
- **Shared epilogues**: `POP; RET` shared between functions. `create_function` fails with overlap → skip.
- **Switch/case tables**: Data in .text looks like instructions. Verify with `get_xrefs_to` — if referenced from single switch dispatch, it's a case block.
- **MULTI-RET gaps**: Contains multiple adjacent small functions. Create first, re-scan — gap splits into separate candidates.
- **Code after unconditional JMP**: Ghidra stops analysis after JMP. Function after the JMP may be legitimate.
