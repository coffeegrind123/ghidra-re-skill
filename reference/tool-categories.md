# Ghidra MCP Tool Reference (193 Tools)

## Core Operations (11 tools)
| Tool | Purpose |
|------|---------|
| `check_connection` | Verify MCP connectivity |
| `get_metadata` | Program metadata and info |
| `get_version` | Server version information |
| `get_function_count` | Total function count |
| `get_entry_points` | Binary entry points |
| `get_current_address` | Cursor address (GUI only) |
| `get_current_function` | Function at cursor (GUI only) |
| `get_current_selection` | Current selection context (GUI only) |
| `read_memory` | Read raw bytes from memory |
| `save_program` | Save current program |
| `exit_ghidra` | Save and exit Ghidra |

## Function Analysis (28 tools)
| Tool | Purpose |
|------|---------|
| `list_functions` | List all functions (paginated) |
| `list_functions_enhanced` | List with isThunk/isExternal flags |
| `list_classes` | List namespace/class names |
| `search_functions_enhanced` | Advanced function search with filters |
| `decompile_function` | Decompile to C pseudocode |
| `force_decompile` | Force fresh decompilation (bypass cache) |
| `batch_decompile` | Batch decompile multiple functions |
| `get_function_callers` | Get function callers |
| `get_function_callees` | Get function callees |
| `get_function_call_graph` | Function relationship graph |
| `get_full_call_graph` | Complete call graph for program |
| `get_function_signature` | Get function prototype string |
| `get_function_hash` | SHA-256 hash of normalized opcodes |
| `get_bulk_function_hashes` | Paginated bulk hashing with filter |
| `get_function_jump_targets` | Jump target addresses from disassembly |
| `get_function_metrics` | Complexity metrics |
| `get_function_xrefs` | Function cross-references |
| `analyze_function_complete` | Comprehensive function analysis |
| `analyze_function_completeness` | Documentation completeness score |
| `batch_analyze_completeness` | Batch completeness analysis |
| `find_similar_functions_fuzzy` | Fuzzy similarity matching |
| `bulk_fuzzy_match` | Bulk fuzzy match across all functions |
| `diff_functions` | Diff two functions side by side |
| `validate_function_prototype` | Validate prototype string |
| `can_rename_at_address` | Check if address can be renamed |
| `delete_function` | Delete function at address |
| `get_function_variables` | Get all function variables with storage types |
| `get_function_labels` | Get labels in function |

## Memory & Data (14 tools)
| Tool | Purpose |
|------|---------|
| `list_segments` | Memory segments and layout |
| `list_data_items` | Defined data labels and values |
| `list_data_items_by_xrefs` | Data items sorted by xref count |
| `get_function_by_address` | Function at address |
| `disassemble_function` | Disassembly listing |
| `disassemble_bytes` | Raw byte disassembly |
| `get_xrefs_to` | Cross-references to address |
| `get_xrefs_from` | Cross-references from address |
| `get_bulk_xrefs` | Bulk cross-reference lookup |
| `analyze_data_region` | Analyze memory region structure |
| `inspect_memory_content` | View raw memory content |
| `detect_array_bounds` | Detect array boundaries |
| `search_byte_patterns` | Search for byte patterns |
| `create_memory_block` | Create a new memory block |

## Cross-Binary Documentation (6 tools)
| Tool | Purpose |
|------|---------|
| `get_function_documentation` | Export complete function documentation |
| `apply_function_documentation` | Import documentation to target function |
| `compare_programs_documentation` | Compare documentation between programs |
| `build_function_hash_index` | Build persistent JSON hash index |
| `lookup_function_by_hash` | Find matching functions in index |
| `propagate_documentation` | Apply docs to all matching instances |

## Data Types & Structures (28 tools)
| Tool | Purpose |
|------|---------|
| `list_data_types` | Available data types |
| `search_data_types` | Search for data types |
| `get_data_type_size` | Byte size of a data type |
| `get_valid_data_types` | Valid Ghidra builtin types |
| `get_struct_layout` | Detailed field layout of structure |
| `validate_data_type` | Validate data type syntax |
| `validate_data_type_exists` | Check if data type exists |
| `create_struct` | Create custom structure |
| `add_struct_field` | Add field to structure |
| `modify_struct_field` | Modify existing field |
| `remove_struct_field` | Remove field from structure |
| `create_enum` | Create enumeration |
| `get_enum_values` | Get enumeration values |
| `create_array_type` | Create array data type |
| `create_typedef` | Create typedef alias |
| `create_union` | Create union data type |
| `create_pointer_type` | Create pointer data type |
| `clone_data_type` | Clone data type with new name |
| `apply_data_type` | Apply type to address |
| `delete_data_type` | Delete a data type |
| `consolidate_duplicate_types` | Merge duplicate types |
| `suggest_field_names` | AI-assisted field name suggestions |
| `create_data_type_category` | Create category folder |
| `move_data_type_to_category` | Move type to different category |
| `list_data_type_categories` | List all categories |
| `import_data_types` | Import types from GDT/header |

## Symbols & Labels (15 tools)
| Tool | Purpose |
|------|---------|
| `list_imports` | Imported symbols and libraries |
| `list_exports` | Exported symbols and functions |
| `list_external_locations` | External location references |
| `get_external_location` | Specific external location detail |
| `list_strings` | Extracted strings with analysis |
| `search_memory_strings` | Search strings by regex/substring |
| `list_namespaces` | Available namespaces |
| `list_globals` | Global variables |
| `create_label` | Create label at address |
| `batch_create_labels` | Bulk label creation |
| `delete_label` | Delete label at address |
| `batch_delete_labels` | Bulk label deletion |
| `rename_label` | Rename existing label |
| `rename_or_label` | Rename or create label |
| `rename_global_variable` | Rename global variable |

## Renaming & Documentation (15 tools)
| Tool | Purpose |
|------|---------|
| `rename_function` | Rename function by name |
| `rename_function_by_address` | Rename function by address |
| `rename_data` | Rename data item |
| `rename_variables` | Rename function variables (dict) |
| `rename_external_location` | Rename external reference |
| `batch_rename_function_components` | Bulk renaming |
| `set_decompiler_comment` | Set decompiler comment |
| `set_disassembly_comment` | Set disassembly comment |
| `set_plate_comment` | Set function plate comment |
| `get_plate_comment` | Get function plate comment |
| `batch_set_comments` | Bulk comment setting (plate + PRE + EOL) |
| `clear_function_comments` | Clear all comments for function |
| `list_bookmarks` | List all bookmarks |
| `set_bookmark` | Create or update bookmark |
| `delete_bookmark` | Delete a bookmark |

## Type System (8 tools)
| Tool | Purpose |
|------|---------|
| `set_function_prototype` | Set function signature (WIPES plate comments) |
| `set_local_variable_type` | Set variable type |
| `set_parameter_type` | Set parameter type |
| `batch_set_variable_types` | Bulk type setting |
| `set_variable_storage` | Control variable storage location |
| `set_function_no_return` | Mark function as non-returning |
| `clear_instruction_flow_override` | Clear flow override |
| `list_calling_conventions` | Available calling conventions |

## Ghidra Script Management (9 tools)
| Tool | Purpose |
|------|---------|
| `list_scripts` | List available scripts |
| `run_script` | Run a script |
| `list_ghidra_scripts` | List custom Ghidra scripts |
| `save_ghidra_script` | Save new script |
| `get_ghidra_script` | Get script contents |
| `run_ghidra_script` | Execute script by name |
| `run_script_inline` | Execute inline script code |
| `update_ghidra_script` | Update existing script |
| `delete_ghidra_script` | Delete script |

## Multi-Program Support (5 tools)
| Tool | Purpose |
|------|---------|
| `list_open_programs` | List all open programs |
| `get_current_program_info` | Current program details |
| `switch_program` | Switch active program |
| `list_project_files` | List project files |
| `open_program` | Open program from project |

## Project Lifecycle (5 tools)
| Tool | Purpose |
|------|---------|
| `create_project` | Create new Ghidra project |
| `open_project` | Open existing project |
| `close_project` | Close current project |
| `delete_project` | Delete a project |
| `list_projects` | List projects in directory |

## Project Organization (4 tools)
| Tool | Purpose |
|------|---------|
| `create_folder` | Create folder in project tree |
| `move_file` | Move domain file |
| `move_folder` | Move folder |
| `delete_file` | Delete domain file |

## Analysis Tools (15 tools)
| Tool | Purpose |
|------|---------|
| `find_next_undefined_function` | Find undefined functions |
| `find_undocumented_by_string` | Find functions by string reference |
| `batch_string_anchor_report` | String anchor analysis |
| `get_assembly_context` | Assembly context |
| `analyze_struct_field_usage` | Structure field access patterns |
| `get_field_access_context` | Field access patterns |
| `create_function` | Create function at address |
| `analyze_control_flow` | Cyclomatic complexity, loops |
| `analyze_call_graph` | Build function call graph |
| `analyze_api_call_chains` | API call threat patterns |
| `detect_malware_behaviors` | Malware behavior categories |
| `find_anti_analysis_techniques` | Anti-analysis techniques |
| `find_dead_code` | Unreachable code detection |
| `extract_iocs_with_context` | Extract IOCs from strings |
| `apply_data_classification` | Apply data classification |

## Analysis Control (3 tools)
| Tool | Purpose |
|------|---------|
| `list_analyzers` | List available analyzers |
| `configure_analyzer` | Enable/disable analyzer |
| `run_analysis` | Trigger auto-analysis |

## Server Connection (3 tools)
| Tool | Purpose |
|------|---------|
| `connect_server` | Connect to Ghidra Server |
| `disconnect_server` | Disconnect from server |
| `server_status` | Check connection status |

## Server Repositories (4 tools)
| Tool | Purpose |
|------|---------|
| `list_repositories` | List repositories |
| `create_repository` | Create new repository |
| `list_repository_files` | List files in repository folder |
| `get_repository_file` | File metadata in repository |

## Version Control (4 tools)
| Tool | Purpose |
|------|---------|
| `checkout_file` | Check out file |
| `checkin_file` | Check in file with comment |
| `undo_checkout` | Undo checkout |
| `add_to_version_control` | Add file to version control |

## Version History (2 tools)
| Tool | Purpose |
|------|---------|
| `get_version_history` | Full version history |
| `get_checkouts` | Active checkout status |

## Admin (4 tools)
| Tool | Purpose |
|------|---------|
| `terminate_checkout` | Force-terminate checkout |
| `terminate_all_checkouts` | Force-terminate all checkouts |
| `list_server_users` | List all server users |
| `set_user_permissions` | Set repository access level |

## Knowledge Database (5 tools)
| Tool | Purpose |
|------|---------|
| `store_function_knowledge` | Store function data to knowledge DB |
| `query_knowledge_context` | Search documented functions by keyword |
| `store_ordinal_mapping` | Store ordinal-to-name mapping |
| `get_ordinal_mapping` | Look up ordinal name |
| `export_system_knowledge` | Export documented functions as markdown |
