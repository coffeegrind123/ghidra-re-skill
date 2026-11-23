# Tool Map: task -> tool

A short map for ghidra-mcp-next. The full list is the server's `docs/tools.md`; every tool's
typed signature and documentation is the resource `ghidra://api/tools.pyi`. Use
`search_tools(pattern=...)` and `get_schema(tools=[...])` before calling a tool you have not
used in this session.

**Listed** tools (always callable as `mcp__ghidra__<name>`) are marked *L*. All others are
hidden: call them through `call(tool, arguments, database)`, as a `batch` op
(`{"tool": ..., "params": {...}}`), or as `tools.<name>(...)` inside `execute`.

## Session and meta

| Task | Tools |
|---|---|
| Open, wait, close | `open_database` *L*, `wait_for_analysis` *L*, `close_database` *L*, `list_databases` *L* |
| Save to disk | `save_database` *L* |
| Programs in a `.gpr` project | `list_project_files` *L* |
| Wrong processor | `list_targets` *L* (then `open_database(language=, compiler_spec=)`) |
| Find / describe tools | `search_tools` *L*, `get_schema` *L* |
| Call one hidden tool | `call` *L* |
| Atomic multi-edit | `batch` *L* |
| Python against the Ghidra API | `execute` *L* |
| Undo / redo a step | `undo` *L*, `redo` |
| Existing GhidraScripts | `list_ghidra_scripts`, `run_ghidra_script` |
| Re-run analysis | `run_auto_analysis` (all, or `analyzers=[...]`), `reanalyze_range` |
| Analyzer settings | `list_analyzers`, `configure_analyzer` |

## Reading code

| Task | Tools |
|---|---|
| Program summary | `get_database_info` *L* |
| Functions | `list_functions` *L*, `get_function` *L*, `get_function_prototype`, `list_function_ranges`, `get_stack_frame` |
| Decompile | `decompile_function` *L*, `decompile_functions` (expensive, filter it), `get_decompiler_tokens` |
| Disassemble | `disassemble_function` *L*, `decode_instruction`, `decode_instructions`, `disassemble_functions` |
| Variables | `list_decompiler_variables`, `get_function_vars` |
| What is at an address | `get_address_info`, `get_code_unit`, `get_type_info`, `read_bytes` |
| Control flow | `get_basic_blocks`, `get_cfg_edges`, `get_switch_info`, `list_switches` |
| Operands, registers | `get_operand_value`, `find_register_value` (constant propagation over the function), `get_register_name`, `get_processor_info` |
| Documentation gaps | `score_documentation` |
| Triage metrics | `get_function_metrics` (bulk, `sort_by="cyclomatic"` / `"callers"`) |
| P-code and dataflow | `get_function_pcode`, `analyze_dataflow` (where a value comes from / goes) |
| Compare functions | `diff_functions`, `diff_functions_across` (two databases) |
| Analysis problems | `get_analysis_problems` |

## Navigation and search

| Task | Tools |
|---|---|
| References | `get_xrefs_to` *L*, `get_xrefs_from` *L*, `get_call_graph`, `find_decompiled_calls` |
| Whole call graph | `analyze_call_graph` (summary, path, scc, roots, leaves, edges) |
| Missed code | `find_code_gaps`, `score_documentation` |
| Strings | `list_strings` *L*, `find_code_by_string` *L*, `create_string` |
| Bytes / instruction text | `search_bytes` (`??` / `?` wildcards), `search_text` |
| Imports, exports, entry | `list_imports`, `list_exports`, `list_entry_points` |
| Names | `list_names`, `list_demangled_names`, `demangle_name`, `demangle_at_address` |
| Memory layout | `list_memory_blocks`, `list_program_tree` |
| Bookmarks | `set_bookmark`, `list_bookmarks`, `delete_bookmark` |
| Library code | `apply_function_id`, `list_data_type_archives` |

## Editing

| Task | Tools |
|---|---|
| Rename | `rename_function`, `rename_symbol` (labels, globals, `DAT_*`), `rename_decompiler_variable` |
| Extra labels | `create_label` (optionally in a namespace), `delete_label` |
| Named constants | `set_equate`, `remove_equate`, `list_equates` |
| Tags | `tag_function`, `list_function_tags` |
| C++ methods | `set_function_class`, `list_class_members` |
| Variable storage, flow | `set_variable_storage`, `set_flow_override`, `clear_flow_and_repair` |
| Prototype, convention, flags | `set_function_prototype`, `set_function_calling_convention`, `set_function_flags` |
| Retype a variable | `retype_decompiler_variable` |
| Comments | `set_comment` (`comment_type`: eol, pre, post, plate, repeatable), `set_decompiler_comment`, `set_function_comment`, `get_comment`, `get_function_comment`, `get_decompiler_comments` |
| Functions | `create_function`, `delete_function`, `add_function_range`, `remove_function_range` |
| Code and data | `disassemble_at`, `clear_code_units`, `create_data`, `create_array`, `set_type`, `apply_type_at_address`, `set_operand_format` |
| Patching | `assemble_instruction` (dry run), `patch_instruction`, `patch_bytes` |
| Xrefs | `add_code_xref`, `add_data_xref`, `delete_code_xref`, `delete_data_xref` |
| Memory blocks | `create_memory_block`, `rename_memory_block`, `set_memory_block_permissions`, `delete_memory_block`, `set_image_base` |
| Colors | `set_color`, `get_color` |

## Types

| Task | Tools |
|---|---|
| Whole type from C | `parse_type_declaration`, `parse_c_source` |
| Structs | `create_structure`, `add_struct_member`, `rename_struct_member`, `retype_struct_member`, `delete_struct_member`, `get_structure`, `list_structures`, `delete_structure` |
| Enums | `create_enum`, `add_enum_member`, `rename_enum_member`, `delete_enum_member`, `get_enum_members`, `list_enums`, `rename_enum`, `delete_enum` |
| Any type | `get_data_type`, `list_data_types`, `delete_data_type`, `rename_data_type`, `clone_data_type` |
| Organise | `list_data_type_categories`, `create_data_type_category`, `move_data_type`, `consolidate_data_types` (merge duplicates) |
| Who uses a type / field | `find_data_type_uses` |

## Across databases (several open at once)

| Task | Tools |
|---|---|
| Hashes | `get_function_hashes` (FID / Version Tracking) |
| Match functions | `match_functions` (unique hashes; `algorithm="fuzzy"` adds similarity matches) |
| Copy documentation | `propagate_documentation` (names, prototypes, comments, locals, the types they use; one undo step), or `get_function_documentation` + `apply_function_documentation` |
| Compare | `diff_functions_across` |

## Ghidra Server

| Task | Tools |
|---|---|
| State | `get_version_state`, `get_version_history`, `list_checkouts` |
| Edit and publish | `checkout_file`, `checkin_file`, `undo_checkout` (destructive) |
| Repositories (no database) | `list_repositories`, `create_repository`, `list_repository_files`, `list_repository_checkouts` |
| Admin | `list_server_users`, `set_repository_permission`, `terminate_checkout` |
| Share a local program | `add_to_repository` |

## Utility

`convert_number` converts between hex, decimal, octal and binary.
