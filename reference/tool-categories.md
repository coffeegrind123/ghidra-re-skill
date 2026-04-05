# Ghidra MCP Tool Reference (158 Tools)

## Tool Categories from /mcp/schema

v5.0.0 uses dynamic tool discovery via bridge. 152 tools from schema + 6 static bridge tools.

## Analysis (17 tools)
| Tool | Purpose |
|------|---------|
| `analyze_control_flow` | Cyclomatic complexity, loops, branches |
| `analyze_data_region` | Analyze memory region structure |
| `analyze_for_documentation` | Analyze function for documentation readiness |
| `analyze_function_complete` | Comprehensive function analysis |
| `analyze_function_completeness` | Documentation completeness score |
| `batch_analyze_completeness` | Batch completeness analysis |
| `detect_array_bounds` | Detect array boundaries |
| `find_code_gaps` | Find gaps between known functions |
| `find_dead_code` | Unreachable code detection |
| `find_next_undefined_function` | Find undefined functions |
| `find_similar_functions` | Find similar functions by structure |
| `get_field_access_context` | Field access patterns |
| `inspect_memory_content` | View raw memory content |
| `list_analyzers` | List available analyzers |
| `run_analysis` | Trigger auto-analysis |
| `search_byte_patterns` | Search for byte patterns |
| `search_functions_enhanced` | Advanced function search with filters |

## Comment (6 tools)
| Tool | Purpose |
|------|---------|
| `batch_set_comments` | Bulk comment setting (plate + optional PRE + EOL) |
| `clear_function_comments` | Clear all comments for function |
| `get_plate_comment` | Get function plate comment |
| `set_decompiler_comment` | Set decompiler comment |
| `set_disassembly_comment` | Set disassembly comment |
| `set_plate_comment` | Set function plate comment |

## Datatype (29 tools)
| Tool | Purpose |
|------|---------|
| `add_struct_field` | Add field to structure (auto-prefixes Hungarian) |
| `analyze_struct_field_usage` | Structure field access patterns |
| `apply_data_classification` | Apply data classification |
| `apply_data_type` | Apply type to address |
| `clone_data_type` | Clone data type with new name |
| `create_array_type` | Create array data type |
| `create_data_type_category` | Create category folder |
| `create_enum` | Create enumeration |
| `create_function_signature` | Create function signature type |
| `create_pointer_type` | Create pointer data type |
| `create_struct` | Create custom structure (auto-prefixes fields) |
| `create_typedef` | Create typedef alias |
| `create_union` | Create union data type |
| `delete_data_type` | Delete a data type |
| `get_enum_values` | Get enumeration values |
| `get_struct_layout` | Detailed field layout of structure |
| `get_type_size` | Byte size of a data type |
| `get_valid_data_types` | Valid Ghidra builtin types |
| `import_data_types` | Import types from GDT/header |
| `list_data_type_categories` | List all categories |
| `list_data_types` | Available data types |
| `modify_struct_field` | Modify existing field (auto-prefixes Hungarian) |
| `move_data_type_to_category` | Move type to different category |
| `remove_struct_field` | Remove field from structure |
| `search_data_types` | Search for data types |
| `suggest_field_names` | AI-assisted field name suggestions |
| `validate_data_type` | Validate data type syntax |
| `validate_data_type_exists` | Check if data type exists |
| `validate_function_prototype` | Validate prototype string |

## Documentation (11 tools)
| Tool | Purpose |
|------|---------|
| `apply_function_documentation` | Import documentation to target function |
| `batch_string_anchor_report` | String anchor analysis |
| `bulk_fuzzy_match` | Bulk fuzzy match across all functions |
| `compare_programs_documentation` | Compare documentation between programs |
| `diff_functions` | Diff two functions side by side |
| `find_similar_functions_fuzzy` | Fuzzy similarity matching |
| `find_undocumented_by_string` | Find functions by string reference |
| `get_bulk_function_hashes` | Paginated bulk hashing with filter |
| `get_function_documentation` | Export complete function documentation |
| `get_function_hash` | SHA-256 hash of normalized opcodes |
| `get_function_signature` | Get function prototype string |

## Function (21 tools)
| Tool | Purpose |
|------|---------|
| `batch_decompile` | Batch decompile multiple functions |
| `batch_rename_function_components` | Bulk renaming |
| `clear_instruction_flow_override` | Clear flow override |
| `create_function` | Create function at address |
| `decompile_function` | Decompile to C pseudocode |
| `delete_function` | Delete function at address |
| `disassemble_bytes` | Raw byte disassembly |
| `disassemble_function` | Disassembly listing |
| `force_decompile` | Force fresh decompilation (bypass cache) |
| `get_function_by_address` | Function at address |
| `get_function_variables` | Get all function variables with storage types |
| `rename_function` | Rename function by name |
| `rename_function_by_address` | Rename function by address |
| `rename_variable` | Rename single variable |
| `rename_variables` | Rename function variables (dict) |
| `set_function_no_return` | Mark function as non-returning |
| `set_function_prototype` | Set function signature (WIPES plate comments) |
| `set_local_variable_type` | Set variable type (rejects no-op if type unchanged) |
| `set_parameter_type` | Set parameter type |
| `set_variable_storage` | Control variable storage location |
| `set_variables` | Atomic type+rename in one call (preferred) |

## Listing (20 tools)
| Tool | Purpose |
|------|---------|
| `convert_number` | Number base conversion |
| `get_entry_points` | Binary entry points |
| `get_external_location` | Specific external location detail |
| `get_function_count` | Total function count |
| `list_calling_conventions` | Available calling conventions |
| `list_classes` | List namespace/class names |
| `list_data_items` | Defined data labels and values |
| `list_data_items_by_xrefs` | Data items sorted by xref count |
| `list_exports` | Exported symbols and functions |
| `list_external_locations` | External location references |
| `list_functions` | List all functions (paginated) |
| `list_functions_enhanced` | List with isThunk/isExternal flags |
| `list_globals` | Global variables |
| `list_imports` | Imported symbols and libraries |
| `list_methods` | List class methods |
| `list_namespaces` | Available namespaces |
| `list_segments` | Memory segments and layout |
| `list_strings` | Extracted strings with analysis |
| `search_functions` | Search functions by name/pattern |
| `search_strings` | Search strings by regex/substring |

## Malware (5 tools)
| Tool | Purpose |
|------|---------|
| `analyze_api_call_chains` | API call threat patterns |
| `detect_crypto_constants` | Detect cryptographic constants |
| `detect_malware_behaviors` | Malware behavior categories |
| `extract_iocs_with_context` | Extract IOCs from strings |
| `find_anti_analysis_techniques` | Anti-analysis techniques |

## Program (21 tools)
| Tool | Purpose |
|------|---------|
| `analysis_status` | Current analysis status |
| `create_memory_block` | Create a new memory block |
| `delete_bookmark` | Delete a bookmark |
| `get_address_spaces` | List address spaces |
| `get_current_program_info` | Current program details |
| `get_metadata` | Program metadata and info |
| `import_file` | Import file into program |
| `list_bookmarks` | List all bookmarks |
| `list_open_programs` | List all open programs |
| `list_project_files` | List project files |
| `list_scripts` | List available scripts |
| `open_program` | Open program from project |
| `read_memory` | Read raw bytes from memory |
| `reanalyze` | Re-run analysis on program |
| `run_ghidra_script` | Execute script by name |
| `run_script` | Run a script |
| `run_script_inline` | Execute inline script code |
| `save_program` | Save current program |
| `set_bookmark` | Create or update bookmark |
| `set_image_base` | Set program image base |
| `switch_program` | Switch active program |

## Symbol (11 tools)
| Tool | Purpose |
|------|---------|
| `batch_create_labels` | Bulk label creation |
| `batch_delete_labels` | Bulk label deletion |
| `can_rename_at_address` | Check if address can be renamed |
| `create_label` | Create label at address |
| `delete_label` | Delete label at address |
| `get_function_labels` | Get labels in function |
| `rename_data` | Rename data item |
| `rename_external_location` | Rename external reference |
| `rename_global_variable` | Rename global variable |
| `rename_label` | Rename existing label |
| `rename_or_label` | Rename or create label |

## Xref (11 tools)
| Tool | Purpose |
|------|---------|
| `analyze_call_graph` | Build function call graph |
| `get_assembly_context` | Assembly context |
| `get_bulk_xrefs` | Bulk cross-reference lookup |
| `get_full_call_graph` | Complete call graph for program |
| `get_function_call_graph` | Function relationship graph |
| `get_function_callees` | Get function callees |
| `get_function_callers` | Get function callers |
| `get_function_jump_targets` | Jump target addresses from disassembly |
| `get_function_xrefs` | Function cross-references |
| `get_xrefs_from` | Cross-references from address |
| `get_xrefs_to` | Cross-references to address |

## Static Bridge Tools (6 tools)

These are always available regardless of tool group loading:

| Tool | Purpose |
|------|---------|
| `check_connection` | Verify MCP bridge connectivity |
| `list_instances` | List available Ghidra instances |
| `connect_instance` | Connect to a specific Ghidra instance |
| `load_tool_group` | Load a tool category on demand |
| `check_tools` | Check which tool groups are loaded |
| `store_function_knowledge` | Store function data to knowledge DB |

Additional knowledge DB tools (`query_knowledge_context`, `export_system_knowledge`, etc.) are available when the knowledge database is active.
