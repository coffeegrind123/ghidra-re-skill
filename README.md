# ghidra-re

An [Agent Skill](https://docs.anthropic.com/en/docs/agents-and-tools/agent-skills/overview) for reverse engineering binaries with [Ghidra MCP](https://github.com/bethington/ghidra-mcp) v6.0.0 (~222 tools via the Python bridge wheel; 272 shipped, the rest GUI-only).

## What it does

Gives Claude structured workflows for binary analysis in Ghidra's headless mode:

- **Function documentation** — V5 protocol: decompile → rename → prototype → types → variables → globals → comments → verify. Enforces correct ordering (prototype changes wipe plate comments) and Hungarian notation.
- **Batch documentation** — Parallel subagent dispatch (max 3) with model selection (Sonnet default, Opus for complex functions).
- **Data type investigation** — Cross-function analysis to discover struct definitions from offset access patterns.
- **Orphaned code discovery** — 3-pass scanner finds valid functions missed by Ghidra auto-analysis.
- **Call graph analysis** — Callers, callees, full graph traversal, bulk xrefs.
- **Security analysis** — Malware behaviors, anti-analysis techniques, IOC extraction.

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) or any agent supporting the [Agent Skills spec](https://agentskills.io/specification)
- [Ghidra MCP server](https://github.com/bethington/ghidra-mcp) running in headless mode (Python bridge + Java headless server on port 8089)
- Ghidra 12.1 with Java 21 LTS

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

The skill is automatically discovered on next Claude Code session start.

### Claude.ai / Claude API

Package as a `.skill` zip and upload through Settings > Features (claude.ai) or the Skills API.

## File structure

```
ghidra-re/
├── SKILL.md                              # Core skill (217 lines)
├── LEARNINGS.md                          # Append-only refinement log
├── README.md
└── reference/
    ├── tool-categories.md                # MCP tools by category (~222 headless)
    ├── function-documentation.md         # V5 protocol (single + batch)
    ├── data-type-investigation.md        # Struct discovery via usage analysis
    ├── orphaned-code-discovery.md        # 3-pass gap scanner, types A-G
    ├── hungarian-notation.md             # Type normalization + prefix table
    ├── headless-operations.md            # Binary loading, HTTP endpoints
    ├── gotchas.md                        # Non-obvious failure modes + fixes
    └── dynamic-analysis.md               # Runtime RE companion: Wine + /proc/mem + stubs + tcpdump
```

Progressive disclosure: SKILL.md metadata (~100 tokens) is always loaded. The SKILL.md body loads when triggered. Reference files load only when needed for specific workflows.

## Trigger conditions

The skill activates when you mention: reverse engineer, decompile, disassemble, binary analysis, Ghidra, DLL/EXE investigation, function documentation, struct creation, orphaned code, call graphs, or malware analysis.

## Key workflows

### Load and analyze a binary

```
> Load steam_api.dll into Ghidra and give me an overview
```

### Document a specific function

```
> Document the function at 0x10001A40 in the current binary
```

### Batch document undocumented functions

```
> Find all FUN_* functions and document them in batches
```

### Investigate a data type

```
> The first parameter of ProcessUnit is used as a struct pointer — investigate what type it is
```

### Find orphaned code

```
> Scan for hidden functions that Ghidra's auto-analysis missed
```

## License

Proprietary
