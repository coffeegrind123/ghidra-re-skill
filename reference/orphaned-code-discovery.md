# Orphaned Code Discovery Workflow

## Critical Rules

1. **Never auto-create without review**: the scanner finds candidates. Classify and approve
   each one before `create_function`.
2. **Iterate**: after creating functions, re-run the scanner. New gaps appear as boundaries
   move.
3. **Minimal intervention**: create functions and a triage plate comment only. Full
   documentation is a separate task.
4. **One database id per binary**: every call names its `database`. There is no current
   program to switch.

## Step 0: Scope

| Scope | How |
|---|---|
| One binary | Run the scanner once on its database |
| Several programs in a project | `list_project_files(project="/path/to/proj.gpr")`, then `open_database(file_path=<.gpr>, program=<path>)` for each; each gets its own database id |

## Step 1: Run the Scanner

Run with `execute(database, code, read_only=true, timeout_s=300)`. It walks each gap between
consecutive functions in executable memory, skips padding, and reports one candidate per gap:

- **Pass 1**: an instruction already exists at the first non-padding byte, but no function
  (HIGH).
- **Pass 2**: the bytes match a known prologue (x86 patterns below; VARIABLE).
- **Pass 3**: fallback: non-padding bytes that contain a RET opcode (LOW).

This is a template for x86 PE code, not a measured tool: adapt `PROLOGUES`, `PAD` and
`MAX_GAP` to the target, and run it on a binary where you know one orphan exists first.

```python
from ghidra.program.model.address import AddressSet

PROLOGUES = [  # (name, bytes, confidence)
    ("HOTPATCH+FRAME", [0x8B, 0xFF, 0x55, 0x8B, 0xEC], "HIGH"),
    ("PUSH_EBP+FRAME", [0x55, 0x8B, 0xEC], "HIGH"),
    ("SUB_ESP_IMM8", [0x83, 0xEC], "MEDIUM"),
    ("SUB_ESP_IMM32", [0x81, 0xEC], "MEDIUM"),
    ("MOVZX", [0x0F, 0xB6], "MEDIUM"), ("MOVZX", [0x0F, 0xB7], "MEDIUM"),
    ("MOVSX", [0x0F, 0xBE], "MEDIUM"), ("MOVSX", [0x0F, 0xBF], "MEDIUM"),
    ("PUSH_ESI", [0x56], "MEDIUM"), ("PUSH_EDI", [0x57], "MEDIUM"),
    ("PUSH_EBX", [0x53], "MEDIUM"), ("PUSH_ECX", [0x51], "MEDIUM"),
    ("XOR_R32", [0x33], "MEDIUM"), ("TEST_R32", [0x85], "MEDIUM"),
]
PAD = {0xCC, 0x90, 0x00}
MAX_GAP = 0x4000
RETS = {0xC3, 0xC2}

listing = program.getListing()
mem = program.getMemory()
funcs = [f for f in program.getFunctionManager().getFunctions(True) if not f.isExternal()]
out = []
for prev, nxt in zip(funcs, funcs[1:]):
    start = prev.getBody().getMaxAddress().add(1)
    end = nxt.getEntryPoint()
    size = end.subtract(start)
    if size <= 0 or size > MAX_GAP:
        continue
    block = mem.getBlock(start)
    if block is None or not block.isExecute():
        continue
    raw = [b & 0xFF for b in flat.getBytes(start, int(size))]
    i = 0
    while i < len(raw) and raw[i] in PAD:
        i += 1
    if i == len(raw):
        continue
    cand = start.add(i)
    row = {"address": str(cand), "gap": int(size) - i, "prev": prev.getName(),
           "next": nxt.getName(), "rets": sum(1 for b in raw[i:] if b in RETS)}
    if listing.getInstructionAt(cand) is not None:
        n = sum(1 for _ in listing.getInstructions(AddressSet(cand, end.subtract(1)), True))
        row.update(pass_=1, confidence="HIGH", pattern="DISASSEMBLED", instructions=n)
    else:
        hit = next((p for p in PROLOGUES if raw[i:i + len(p[1])] == p[1]), None)
        if hit:
            row.update(pass_=2, confidence=hit[2], pattern=hit[0])
        elif row["rets"]:
            row.update(pass_=3, confidence="LOW", pattern="UNKNOWN")
        else:
            continue
    out.append(row)
return {"total": len(out), "items": out[:200]}
```

`rets` counts RET opcode bytes, including ones inside operands, so treat it as an upper
bound. `rets > 1` (MULTI-RET) suggests several small functions in one gap.

### Prologue patterns (x86)

| Pattern | Bytes | Confidence |
|---|---|---|
| HOTPATCH+FRAME | `8B FF 55 8B EC` | HIGH |
| PUSH_EBP+FRAME | `55 8B EC` | HIGH |
| SUB_ESP_IMM8 | `83 EC xx` | MEDIUM (gap >= 5 bytes) |
| SUB_ESP_IMM32 | `81 EC xx xx xx xx` | MEDIUM (gap >= 5 bytes) |
| PUSH_ESI / PUSH_EDI / PUSH_EBX / PUSH_ECX | `56` / `57` / `53` / `51` | MEDIUM (gap >= 4 bytes) |
| MOVSX | `0F BE`, `0F BF` | MEDIUM |
| MOVZX | `0F B6`, `0F B7` | MEDIUM |
| XOR_R32 | `33 xx` | MEDIUM (gap >= 4 bytes) |
| TEST_R32 | `85 xx` | MEDIUM (gap >= 4 bytes) |

Padding filtered: `0xCC` (INT3), `0x90` (NOP), `0x00`.

## Step 2: Classify Candidates

Inspect uncertain ones with `decode_instructions(address, count=20)` (works on code with no
function) and `read_bytes(address, size=64)`. For raw bytes, `disassemble_at` first.

### Type A: Import thunk / trampoline
- A single JMP (5 bytes).
- Action: `create_function`, plate: "Import thunk: redirects to <target>". Priority: low.

### Type B: Already disassembled, real function
- Pass 1, more than one instruction. Ghidra disassembled it but made no function.
- Action: `create_function`, decompile, triage plate. Priority: **highest**.

### Type C: Standard prologue (HIGH)
- PUSH_EBP+FRAME or HOTPATCH+FRAME.
- Action: `create_function` (it disassembles), decompile, triage plate. Priority: high.

### Type D: Callee-save / operand prologue (MEDIUM)
- PUSH_ESI, PUSH_EDI, SUB_ESP, MOVSX/MOVZX, XOR, TEST.
- Action: `create_function`, decompile, confirm it stands alone.
- Watch for tail-call targets reached only by JMP: not a separate function.
- Common: CRT character classification, string utilities.

### Type E: Atypical start (LOW)
- MOV, PUSH imm, CALL rel32, CMP.
- Action: inspect first. Red flags: address tables, sequences under 8 bytes.

### Type F: Getter / converter / thin wrapper
- Any type, under about 15 bytes: `MOV EAX,[addr]; RET`, `PUSH imm; CALL rel32; RET`.
- Action: `create_function`, name it if the purpose is obvious.

### Type G: Unknown prologue (REVIEW)
- Pass 3 hit. Always inspect first. MULTI-RET means several adjacent functions.

## Step 3: Create Functions

**Order**: B, C, D, F, A, E, G. Batches of 5-10 candidates, one labelled batch each:

```json
batch(database="fw_bin", label="orphans round 1", operation_id="orphans-r1-b1", ops=[
  {"tool": "create_function", "params": {"address": "0x401a30"}},
  {"tool": "set_comment", "params": {"address": "$0.address", "comment_type": "plate",
     "comment": "[TRIAGE] Orphaned code found by scanner.\nType: C - standard prologue\nConfidence: HIGH\nSize: ~${0.size} bytes\nNeighboring: FUN_00401900 .. FUN_00401b10\nStatus: awaiting full documentation"}},
  {"tool": "create_function", "params": {"address": "0x401c80"}},
  {"tool": "set_comment", "params": {"address": "$2.address", "comment_type": "plate",
     "comment": "[TRIAGE] Orphaned code found by scanner.\nType: B - already disassembled\nConfidence: HIGH\nSize: ~${2.size} bytes\nNeighboring: FUN_00401c00 .. FUN_00401d40\nStatus: awaiting full documentation"}}])
```

One `create_function` that fails (overlap, shared epilogue) rolls back the whole batch. Run it
with `dry_run=true` first, drop the op the error names (`op_index`), then run it for real.
After each batch, spot-check 1-2 with `decompile_function`, then `save_database`.

## Step 4: Report

```
=== ORPHANED CODE REPORT: <program> ===
Created: N functions
  Type A (thunks): N
  Type B (disassembled): N
  Type C (standard prologue): N
  Type D (callee-save): N
  Type E (atypical): N
  Type F (getter/wrapper): N
  Type G (unknown): N
Skipped: N (data / jump table / fragment)
Next: re-run the scanner for newly exposed gaps
```

## Edge Cases

- **Non-contiguous bodies**: a function at [0x100-0x110, 0x130-0x140] leaves a gap that may be
  its own. Check `list_function_ranges` and xrefs first.
- **Shared epilogues**: `POP; RET` shared between functions. `create_function` fails: skip.
- **Switch/case tables**: data in `.text` can look like code. `get_xrefs_to` and
  `get_switch_info` / `list_switches`: if one switch dispatch references it, it is a case
  block.
- **MULTI-RET gaps**: create the first function, re-scan; the gap splits.
- **Code after an unconditional JMP**: Ghidra stops flow there. The code after it may be a real
  function.
