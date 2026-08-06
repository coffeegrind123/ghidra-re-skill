# Headless Operations Reference

## Binary Loading

Two paths, with very different analysis behavior — pick by what you need:

- **`load_program(file=<path>)`** — IS exposed as an MCP tool in v5.12.0 and still in v6.0.0 (the HTTP-endpoint
  table below predates this; it is no longer bridge-only). Loads the PE FAST but with **only
  minimal analysis** (exports/symbols; e.g. a 1.5 MB engine shows ~300 functions, not
  thousands), so a target address usually has **no function created** yet —
  `decompile_function` returns `"No function found"`. Workflow for a few specific functions:
  ```
  load_program(file=…)  ->  create_function(address=0x…, name="X")  ->  decompile_function(0x…)
  ```
  Do NOT call `run_analysis` to "finish" it — full auto-analysis can **hang for many minutes**
  on a large binary (param-ID + decompiler analyzers stall on pathological functions). Just
  create the handful of functions you actually need.
- **`import_file(file_path=…, auto_analyze=true)`** — runs the full `analyzeHeadless` pass (all
  functions + xrefs). Slower, same hang risk on big binaries. Needed when you want
  whole-program xrefs: `get_function_callers`/`get_function_callees`/`get_xrefs_to` return
  **nothing** on a `load_program`'d partial program (no xref pass ran).

After loading: `get_current_program_info` to verify image base / arch / `function_count` (a
low count == partial `load_program` state).

**`load_program`-loaded programs are EPHEMERAL**: `save_program` fails ("Location does not
exist for a save operation") and `list_project_files` needs GUI mode, so names/comments you
add live only for the session. For persistent annotation, `import_file` into a project or run
`analyzeHeadless` on the CLI.

## HTTP-Only Endpoints

These exist on the headless server but are NOT in the MCP bridge:

| Endpoint | Method | Params | Purpose |
|----------|--------|--------|---------|
| `/load_program` | POST | `file=<path>` | Import and load binary from disk |
| `/close_program` | POST | `name=<name>` | Close a loaded program |
| `/open_project` | POST | `path=<path>` | Open existing .gpr project |
| `/close_project` | POST | (none) | Close current project |
| `/load_program_from_project` | POST | `path=<path>` | Load program from within project |
| `/get_project_info` | GET | (none) | Current project details |
| `/create_project` | POST | `parentDir`, `name` | Create new project |
| `/delete_project` | POST | `projectPath` | Delete project |

Default server address: `http://127.0.0.1:8089`

## Headless Limitations

These tools require GUI mode and will fail or return meaningless results in headless:
- `launch_codebrowser` — no GUI to launch
- `goto_address` — no GUI cursor
- `get_current_selection` — no GUI selection
- `get_current_address` — no GUI cursor
- `get_current_function` — no GUI context

Use address-based alternatives: `get_function_by_address`, `decompile_function` (by name or address).

## Initial Recon Pattern

1. `list_exports` — exported functions, ordinals, entry points
2. `list_imports` — libraries, APIs (runtime-loaded APIs won't appear here)
3. `list_strings` with `filter` param — interesting strings (IPs, paths, format strings, error messages, API names)

## Finding Code

- `search_byte_patterns` — find references to string addresses or byte sequences
- `get_xrefs_to` — cross-references to an address (only works if Ghidra analyzed the referring code)
- `get_function_by_address` — check if address is inside a known function

## Address bases — add the image base to anything from binutils

A shared object's own vaddrs start at 0; Ghidra loads it at an **image base** (commonly
`0x00010000`). So **every** address from `nm` / `readelf` / `objdump` must have that base
added before it means anything to Ghidra.

Measured on a real `.so`: `ammo_357` `nm` `0x004b5928` → Ghidra `0x004c5928`;
`ammo_556clip` `0x003f2f68` → `0x00402f68`. All exactly `+0x10000`.

The failure mode is silent and misleading — `get_function_by_address` answers
**"No function found"**, which reads as *analysis missed it* rather than *you are 64 KB
too low*.

- Read `image_base` from `list_open_programs` **first**.
- Confirm the delta on **two** known symbols before trusting a sweep.
- Addresses obtained **from** Ghidra (`search_byte_patterns`, `search_functions_enhanced`)
  are already in Ghidra space — do **not** rebase those.

## Data Pattern Searching

When `get_xrefs_to` returns nothing (common for data in unanalyzed regions):
1. Take target address (e.g., `0x0044ebac`)
2. Convert to little-endian bytes: `ac eb 44 00`
3. `search_byte_patterns` with those bytes
4. Finds any code referencing that address as immediate operand

### ⚠ This does NOT work on a 32-bit PIC shared object

Position-independent code does not reference data by absolute address — it uses
`lea reg,[GOTreg + disp32]`. Searching the absolute address returns **"No matches found"**,
which is indistinguishable from "this string is never referenced". It is referenced; the
reference is encoded as a displacement.

```python
disp = (target_addr - got_base) & 0xFFFFFFFF   # search these 4 bytes, little-endian
```

- Get candidate bases from `list_segments`: try **both** `.got` and `.got.plt`. One
  produces exactly one hit in `.text`, the other none. (Measured: the linker used `.got`,
  not `.got.plt`.)
- The GOT register is whatever GCC picked for that function — **not necessarily `ebx`**
  (observed: `esi`). Do not filter on the register.
- Sanity-check direction with a string you know is used before concluding anything.

### "Analysis succeeded" ≠ the functions you need exist

A full `analyzeHeadless` pass on a large PIC `.so` can still under-cover badly — measured
**3,752 functions for 7.5 MB of `.text`**, leaving confirmed call sites with no enclosing
function and `get_xrefs_to` empty (Ghidra does not resolve GOT-relative data refs on i386
PIC either). When that happens, stop trying to coax function discovery and **script the
decode over raw bytes** with `run_script_inline`, which needs no functions at all.

## Dynamic Imports

Some binaries load APIs at runtime via `GetProcAddress`:
- API name strings (e.g., "sendto", "recvfrom") appear in `list_strings` but NOT `list_imports`
- Search for the string address bytes to find the loading code

## Unanalyzed Code

Ghidra auto-analysis may miss functions (common in Delphi/BCB binaries):
1. `read_memory` to examine raw bytes
2. Look for function prologues: `55 8B EC` (push ebp; mov ebp, esp)
3. `create_function` at the prologue address
4. `decompile_function` to get pseudocode

## Server Management

- Start: `bash /opt/ghidra-mcp/run-mcp.sh`
- The script starts headless Ghidra server (background) + Python MCP bridge (stdio)
- Java options: `-Xmx4g -XX:+UseG1GC`
- Java 21 LTS required (Ghidra 12.1)
- Server port configurable via `GHIDRA_MCP_PORT` env var (default 8089)
