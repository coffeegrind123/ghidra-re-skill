# ghidra-re

An [Agent Skill](https://docs.anthropic.com/en/docs/agents-and-tools/agent-skills/overview) for reverse engineering native binaries with [ghidra-mcp-next](https://github.com/coffeegrind123/ghidra-mcp-next), a headless Ghidra MCP server built around transactions: 22 listed tools, about 120 more through `search_tools`, atomic `batch` edits, and Python `execute` against the Ghidra API.

## What it does

Gives Claude structured workflows for binary analysis in headless Ghidra:

- **Change loop**: read, plan, one labelled atomic `batch` per coherent change, re-read, save. Retry-safe writes with `operation_id`, conflict detection with `if_revision`.
- **Function documentation**: name, prototype, globals, locals, plate and inline comments, with Hungarian notation and Ghidra builtin types.
- **Batch documentation**: targets from `score_documentation` (worst first), parallel subagents per database.
- **Data type investigation**: struct definitions from offset access patterns across callers.
- **Orphaned code discovery**: a three-pass gap scanner run through `execute`.
- **Call graph analysis**: callers, callees, transitive walks in Python.
- **Security analysis**: suspicious imports, strings, byte signatures, anti-analysis patterns.
- **Ghidra Server**: checkout, checkin, history.
- **Dynamic analysis companion**: confirming static findings at runtime (Wine, `/proc/<pid>/mem`, stub DLLs, tcpdump, PE rebasing).

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) or any agent supporting the [Agent Skills spec](https://agentskills.io/specification)
- [ghidra-mcp-next](https://github.com/coffeegrind123/ghidra-mcp-next) configured as an MCP server named `ghidra` (tools appear as `mcp__ghidra__*`)
- Ghidra 12.0 or newer, JDK 21, Python 3.12+

## Installation

### Claude Code

Clone into your skills directory:

```bash
git clone https://github.com/coffeegrind123/ghidra-re-skill.git ~/.claude/skills/ghidra-re
```

Or for project-scoped use:

```bash
git clone https://github.com/coffeegrind123/ghidra-re-skill.git .claude/skills/ghidra-re
```

The skill is discovered on the next Claude Code session start.

### Claude.ai / Claude API

Package as a `.skill` zip and upload through Settings > Features (claude.ai) or the Skills API.

## File structure

```
ghidra-re/
├── SKILL.md                              # Core skill
├── LEARNINGS.md                          # Staging buffer for new findings
├── README.md
└── reference/
    ├── tool-categories.md                # Task -> tool name map
    ├── function-documentation.md         # Documentation protocol (single + batch)
    ├── data-type-investigation.md        # Struct discovery from usage
    ├── orphaned-code-discovery.md        # Gap scanner, types A-G
    ├── hungarian-notation.md             # Type normalization + prefix table
    ├── headless-operations.md            # Opening, analysis, addressing, byte search
    ├── gotchas.md                        # Non-obvious failure modes + fixes
    └── dynamic-analysis.md               # Runtime RE companion
```

SKILL.md metadata (~100 tokens) is always loaded; the body loads when triggered; reference files load only when a workflow needs them.

## Trigger conditions

Reverse engineer, decompile, disassemble, binary analysis, Ghidra, DLL/EXE/ELF investigation, function documentation, struct creation, orphaned code, call graphs, malware analysis.

## Example requests

```
> Open /path/to/libexample.so in Ghidra and give me an overview
> Document the function at 0x10001A40
> Find the 20 least documented functions and document them, callees first
> The first parameter of ProcessRequest is used as a struct pointer; work out its type
> Scan for functions Ghidra's auto-analysis missed
```

## License

Proprietary
