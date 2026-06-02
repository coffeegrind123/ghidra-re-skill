# Headless Operations Reference

## Binary Loading

Use `import_file` to load binaries. It runs `analyzeHeadless` and loads the program into the server automatically:

```
import_file(file_path="/absolute/path/to/binary.dll", auto_analyze=true)
```

After loading: `get_current_program_info` to verify architecture, compiler, format.

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

## Data Pattern Searching

When `get_xrefs_to` returns nothing (common for data in unanalyzed regions):
1. Take target address (e.g., `0x0044ebac`)
2. Convert to little-endian bytes: `ac eb 44 00`
3. `search_byte_patterns` with those bytes
4. Finds any code referencing that address as immediate operand

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
