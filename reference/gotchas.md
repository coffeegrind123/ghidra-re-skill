# GhidraMCP Gotchas

Hard-won, non-obvious failure modes — mostly headless-server and v4→v5 quirks.
Read this when a tool behaves unexpectedly (empty results, "failed", timeouts).
Append new ones as you hit them; promote durable rules into SKILL.md.

## Loading & analysis

- **`load_program` "times out" at ~30s but keeps working.** The HTTP layer caps at
  30s; the import + auto-analysis continue server-side. Do NOT retry (you'll queue a
  second load). Poll `analysis_status` / `list_open_programs` until `analyzing:false`.

- **`reanalyze` → `"Auto-analysis failed"` usually means analysis is ALREADY running**
  (e.g. the one `load_program` auto-started), not a real failure. Confirm with
  `analysis_status` (`analyzing:true`, watch `function_count` climb). `run_analysis`
  on an already-analyzed program returns instantly with `new_functions:0` — that's it
  reporting persisted state, not re-running.

- **v5.x headless auto-analysis can throw `NullPointerException`
  (`GhidraScriptUtil.bundleHost is null`, `ProgramScriptService`) and roll back** —
  `function_count` reverts to the initial export count and `analyzed` stays `false`.
  BUT partial analysis (functions, strings, xrefs) often persists and is usable; call
  `run_analysis` to read the persisted state, then proceed. Symptom in the poll:
  count climbs (e.g. →5857) then drops back (→308). Check `/tmp/ghidra-mcp-server.log`
  for the NPE to distinguish this from a real OOM (memory was fine in our case).

- **Low `-Xmx` is NOT always the cause of analysis failure.** A 12 MB program analyzed
  fine under `-Xmx2g`; the rollback above was the bundleHost NPE, not heap. Check the
  server log before bumping heap.

## Strings

- **`search_strings` returns ZERO matches unless you pass `encoding: "ascii"`.** The
  default (empty) encoding matches nothing — you'll think the binary has no strings.
  Always pass `encoding:"ascii"` (or `"unicode"`). The older `list_strings` (filter
  param) did not need this.

- **Strings/xrefs are only populated once the relevant analyzers finish.** If
  `search_strings`/`get_xrefs_to` come back empty right after load, analysis is
  probably still running (or rolled back per the NPE above) — re-check status.

## Headless vs GUI

- **GUI-only tools fail on the headless server**: `create_project`, `open_program`,
  `list_project_files`, `project_info`, `launch_codebrowser`, `goto_address`,
  `get_current_selection` return "requires GUI mode". Use the **HTTP-only endpoints**
  on port 8089 instead — `POST /load_program?file=...`, `POST /create_project`,
  `GET /get_project_info`, `GET /analysis_status?program=NAME` — via curl. (In v5.12.0
  `load_program` is also exposed as an MCP tool.)

- **Older servers (v4.0.0-headless) lack `import_file`** — there is no MCP load tool;
  use the HTTP `/load_program` endpoint. v5.12.0 adds `load_program` + `import_file`.

- **Write tools could silently fail with `"<arg> is required"` on v4.0.0-headless even
  when the arg was supplied** (`rename_function`, `rename_function_by_address`) — a
  param-threading bug in that build. Read tools were unaffected. Fixed by v5.12.0.

## Server / versioning

- **The headless server runs from the JAR on `run-mcp.sh`'s `JAR_PATH` classpath, NOT
  the extension in `$GHIDRA_HOME/Extensions`.** A version mismatch between the
  installed extension and the running JAR is possible and harmless for headless.

- **Editing server files does not hot-swap the running process.** To change the server
  version/heap, edit `run-mcp.sh` then reconnect the MCP (`/mcp` → reconnect, or
  restart the client). The live process keeps its old config until then.

- **GhidraMCP releases are built against a specific Ghidra version** (e.g. v5.12.0 →
  Ghidra 12.1). Running the JAR against an older framework risks `NoSuchMethod` at
  boot — match them. The **release extension ZIP's `lib/GhidraMCP-<ver>.jar` already
  contains the `com.xebyte.headless` server classes**, so no Maven build is needed:
  point `JAR_PATH` at it and run. Pre-flight a new server on an alt port before
  reconnecting the live one.

## Addresses & cross-binary porting

- **Default Ghidra image base for these PE DLLs is `0x01d00000`** → Ghidra address =
  `0x01d00000 + RVA`. Handy when reconciling RVAs from external notes/tools.

- **Porting offsets between two builds of the same codebase** (e.g. two engine
  variants — same code, different module): find ONE anchored global in the new binary
  (anchor via a unique nearby string, e.g. `"Connecting to %s..."` → its referencing
  function), then apply the *internal struct deltas* from the known binary and verify
  each lands on a sane global. Deltas survive even when global bases shift. (Worked
  cleanly porting `cls`/`cmd_text` offsets between two GoldSrc engine DLLs.)

- **`get_xrefs_to` capping at the `limit`** (default 100) is itself signal — a global
  with 100+ xrefs is a heavily-used state var (e.g. a connection-state global), which
  helps confirm you found the right one.

## Live-memory RE: match the EXACT binary the target runs

- **RE the exact binary the live process maps — not a convenient local copy.** Offsets
  from one build are garbage against another. Offsets derived from a repo copy of
  `sw.dll` (1.5 MB, older build) read all-zero against the process's freshly-downloaded
  `sw.dll` (3.5 MB, post-update build) — same name, different binary. ALWAYS `md5sum` /
  size-compare the analyzed file vs the one in the target (`/proc/<pid>/maps`, or
  `docker cp` it out and RE that). For a stable harness, pin the target's version
  (e.g. DepotDownloader `-manifest`) and RE that exact build once.
- **All-zero reads at a plausible base ≠ wrong offset.** It usually means wrong-binary
  OR not-yet-initialized. Distinguish: if several *independent* globals also read 0 while
  the process is demonstrably past init (e.g. drawing UI in `/proc/<pid>` traces),
  suspect a binary/build mismatch, not your offset math.

## More analysis/strings quirks (v5.12.0)

- **`search_strings` can return empty for a while after load even with
  `encoding:"ascii"` — the ASCII Strings analyzer is a LATER phase; give it time.** Poll
  `analysis_status` until `function_count` stops climbing AND a known string resolves.
  `load_program` kicks off async analysis; `function_count` jumps (e.g. 318 → 4105) as
  it runs. `run_analysis` returning `new_functions:0, duration ~3ms` with a high
  `total_functions` means analysis already finished (reporting persisted state) — but
  defined strings may still be a beat behind the function count.
- **Fallback when defined strings aren't ready: `search_memory_strings`** (raw memory
  scan, analyzer-independent) finds string bytes regardless of analysis state.
- **On v5.12.0 use the MCP `load_program` tool, not the HTTP `/load_program` endpoint**
  — the HTTP param changed (`file=` now returns `"file path required"`); the MCP tool
  `load_program({file:"/abs/path"})` works.
