# IDA Pro MCP

> [!IMPORTANT]
> **I recommend using the [Official Hex-Rays IDA MCP Server](https://github.com/HexRaysSA/ida-mcp) instead!**
> 
> See the [announcement blog post](https://hex-rays.com/blog/hex-rays-ida-mcp-server) for more information.

Simple [MCP Server](https://modelcontextprotocol.io/introduction) to allow vibe reversing in IDA Pro.

https://github.com/user-attachments/assets/6ebeaa92-a9db-43fa-b756-eececce2aca0

The binaries and prompt for the video are available in the [mcp-reversing-dataset](https://github.com/mrexodia/mcp-reversing-dataset) repository.

## Prerequisites

- [Python](https://www.python.org/downloads/) (**3.11 or higher**)
  - Use `idapyswitch` to switch to the newest Python version
- [IDA Pro](https://hex-rays.com/ida-pro) (8.3 or higher, 9 recommended), **IDA Free is not supported**
- Supported MCP Client (pick one you like)
  - [Amazon Q Developer CLI](https://aws.amazon.com/q/developer/)
  - [Augment Code](https://www.augmentcode.com/)
  - [Claude](https://claude.ai/download)
  - [Claude Code](https://claude.com/product/claude-code)
  - [Cline](https://cline.bot)
  - [Codex](https://github.com/openai/codex)
  - [Copilot CLI](https://docs.github.com/en/copilot)
  - [Crush](https://github.com/charmbracelet/crush)
  - [Cursor](https://cursor.com)
  - [Gemini CLI](https://google-gemini.github.io/gemini-cli/)
  - [Kilo Code](https://kilo.ai/)
  - [Kiro](https://kiro.dev/)
  - [LM Studio](https://lmstudio.ai/)
  - [Opencode](https://opencode.ai/)
  - [Qodo Gen](https://www.qodo.ai/)
  - [Qwen Coder](https://qwenlm.github.io/qwen-code-docs/)
  - [Roo Code](https://roocode.com)
  - [Trae](https://trae.ai/)
  - [VS Code](https://code.visualstudio.com/)
  - [VS Code Insiders](https://code.visualstudio.com/insiders)
  - [Warp](https://www.warp.dev/)
  - [Windsurf](https://windsurf.com)
  - [Zed](https://zed.dev/)
  - [Kimi Code](https://moonshotai.github.io/kimi-code/en/)
  - [Other MCP Clients](https://modelcontextprotocol.io/clients#example-clients): Run `ida-pro-mcp --config` to get the JSON config for your client.

**Note**: This requires having idalib activated globally and [uv](https://astral.sh/uv) installed:

```bash
# windows
uv run "C:\Program Files\IDA Professional 9.3\idalib\python\py-activate-idalib.py"
# macos
uv run "/Applications/IDA Professional 9.3.app/Contents/MacOS/idalib/python/py-activate-idalib.py"
# linux
uv run "/path/to/idapro-9.3/idalib/python/py-activate-idalib.py"
```

## Installation (Claude Code)

To install the latest IDA Pro MCP in Claude Code:

```bash
claude plugin marketplace add mrexodia/claude-marketplace
claude plugin uninstall ida-pro-mcp@mrexodia
claude plugin install ida-pro-mcp@mrexodia
```

## Installation (Codex)

To install the latest IDA Pro MCP in Codex:

```bash
codex plugin marketplace add mrexodia/codex-marketplace
codex plugin remove ida-pro-mcp@mrexodia
codex plugin add ida-pro-mcp@mrexodia
```

## Installation (Kimi Code)

To install the latest IDA Pro MCP in Kimi Code, run this slash command in the chat:

```
/plugins install https://github.com/mrexodia/ida-pro-mcp/tree/main
/reload
```

This installs the `idalib` MCP server and the `idapython` skill. Plugins are copied to
`$KIMI_CODE_HOME/plugins/managed/`, so `uv` must be on your `PATH`. The first session after
installing is slower, because `uv` resolves the dependencies before the server responds.

## Installation (GUI)

**Note**: the MCP plugin is no longer recommended and will eventually be deprecated. Use `idalib-mcp` instead.

If you want to configure the MCP server manually from the IDA GUI:

```sh
pip uninstall ida-pro-mcp
pip install https://github.com/mrexodia/ida-pro-mcp/archive/refs/heads/main.zip
```

Configure the MCP servers and install the IDA Plugin:

```
ida-pro-mcp --install
```

**Important**: Make sure you completely restart IDA and your MCP client for the installation to take effect. Some clients (like Claude) run in the background and need to be quit from the tray icon.

## Prompt Engineering

LLMs are prone to hallucinations and you need to be specific with your prompting. For reverse engineering the conversion between integers and bytes are especially problematic. Below is a minimal example prompt, feel free to start a discussion or open an issue if you have good results with a different prompt:

```md
Your task is to analyze a crackme in IDA Pro. You can use the MCP tools to retrieve information. In general use the following strategy:

- Inspect the decompilation and add comments with your findings
- Rename variables to more sensible names
- Change the variable and argument types if necessary (especially pointer and array types)
- Change function names to be more descriptive
- If more details are necessary, disassemble the function and add comments with your findings
- NEVER convert number bases yourself. Use the `int_convert` MCP tool if needed!
- Do not attempt brute forcing, derive any solutions purely from the disassembly and simple python scripts
- Create a report.md with your findings and steps taken at the end
- When you find a solution, prompt to user for feedback with the password you found
```

This prompt was just the first experiment, please share if you found ways to improve the output!

Another prompt by [@can1357](https://github.com/can1357):

```md
Your task is to create a complete and comprehensive reverse engineering analysis. Reference AGENTS.md to understand the project goals and ensure the analysis serves our purposes.

Use the following systematic methodology:

1. **Decompilation Analysis**
   - Thoroughly inspect the decompiler output
   - Add detailed comments documenting your findings
   - Focus on understanding the actual functionality and purpose of each component (do not rely on old, incorrect comments)

2. **Improve Readability in the Database**
   - Rename variables to sensible, descriptive names
   - Correct variable and argument types where necessary (especially pointers and array types)
   - Update function names to be descriptive of their actual purpose

3. **Deep Dive When Needed**
   - If more details are necessary, examine the disassembly and add comments with findings
   - Document any low-level behaviors that aren't clear from the decompilation alone
   - Use sub-agents to perform detailed analysis

4. **Important Constraints**
   - NEVER convert number bases yourself - use the int_convert MCP tool if needed
   - Use MCP tools to retrieve information as necessary
   - Derive all conclusions from actual analysis, not assumptions

5. **Documentation**
   - Produce comprehensive RE/*.md files with your findings
   - Document the steps taken and methodology used
   - When asked by the user, ensure accuracy over previous analysis file
   - Organize findings in a way that serves the project goals outlined in AGENTS.md or CLAUDE.md
```

Live stream discussing prompting and showing some real-world malware analysis:

[![](https://img.youtube.com/vi/iFxNuk3kxhk/0.jpg)](https://www.youtube.com/watch?v=iFxNuk3kxhk)

## Tips for Enhancing LLM Accuracy

Large Language Models (LLMs) are powerful tools, but they can sometimes struggle with complex mathematical calculations or exhibit "hallucinations" (making up facts). Make sure to tell the LLM to use the `int_convert` MCP tool and you might also need [math-mcp](https://github.com/EthanHenrickson/math-mcp) for certain operations.

Another thing to keep in mind is that LLMs will not perform well on obfuscated code. Before trying to use an LLM to solve the problem, take a look around the binary and spend some time (automatically) removing the following things:

- String encryption
- Import hashing
- Control flow flattening
- Code encryption
- Anti-decompilation tricks

You should also use a tool like Lumina or FLIRT to try and resolve all the open source library code and the C++ STL, this will further improve the accuracy.

## Transports & Headless MCP

You can run an SSE server to connect to the user interface like this:

```sh
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse
```

After installing [`idalib`](https://docs.hex-rays.com/core/idalib/getting-started) you can also run a headless MCP server. You can start with an initial binary:

```sh
uv run idalib-mcp --host 127.0.0.1 --port 8745 path/to/executable
```

Or start without a binary and open arbitrary files later with `idb_open(...)`:

```sh
uv run idalib-mcp --host 127.0.0.1 --port 8745
```

For stdio-based clients, use:

```sh
uv run idalib-mcp --stdio
```

Database workers are persistent: each one runs as a detached process that
outlives the supervisor that spawned it. When a new supervisor (over stdio
or HTTP) calls `idb_open` for a binary that is already open under a worker
on this host, the supervisor adopts that worker transparently — there is
no separate "shared" mode to enable. Workers self-exit when no request has
hit them for an idle interval.

_Note_: The `idalib` feature was contributed by [Willi Ballenthin](https://github.com/williballenthin).

## Headless idalib Session Model

`idalib-mcp` is a supervisor that keeps each open database in its own idalib worker process. Workers register themselves in a host-local discovery directory and outlive the supervisor that spawned them; any subsequent supervisor that wants the same path adopts the running worker. A worker self-exits when no request has hit it for its idle TTL (default 4 hours; `0` = never). Set the server default with `--worker-idle-ttl SEC` or `IDA_MCP_WORKER_IDLE_TTL`, or per database with `idb_open(idle_ttl_sec=...)`. Call `idb_close` to release a worker eagerly (freeing a slot toward `--max-workers`), adopted GUI/worker instances are detached rather than killed.

`idb_open` picks the backend via its `mode` parameter:

- `prefer_headless` (default): spawn an idalib worker (or adopt one that already has the file open).
- `force_headless`: same, but never adopt a running GUI even if one has the file.
- `prefer_gui`: adopt a running GUI for the file; otherwise spawn an idalib worker.
- `force_gui`: adopt a running GUI for the file; otherwise launch a new IDA GUI process.

Every tool call must carry an explicit `database` argument. There is no implicit "current database" — callers name the session they want to operate on.

```sh
uv run idalib-mcp --stdio --max-workers 4
```

Typical flow:

```python
idb_open("/path/to/binary_a.exe", preferred_session_id="binary_a")
idb_open("/path/to/library.dll", preferred_session_id="library")

decompile("main", database="binary_a")
xrefs_to("ImportantExport", database="library")
```

`database` must be the session ID returned by `idb_open` (or shown in `idb_list`); filenames and paths are not accepted.

### Management tools

- `idb_open(input_path, mode="prefer_headless", run_auto_analysis=True, build_caches=True, init_hexrays=True, idle_ttl_sec=None, preferred_session_id="", directory=None, bitness=None, processor=None, keep_stale_components=False, autosave=True, autosave_idle_sec=60, instance="", on_conflict="error")`: Open a binary, warm up subsystems (strings cache, Hex-Rays), and return its session ID. If a worker for this path is already running on the host, it is adopted and `preferred_session_id` is ignored.
  - **Path resolution:** `input_path` may be absolute, partial (`system/foo.dll`), a bare filename known from `list_pe_images` / `--search-root`, or the `.i64` itself. Misses return `suggestions`. Duplicate filenames return `candidates` with hashes. Success reports the file's `sha256`/`md5`.
  - **Attach to a running IDA GUI:** `instance="<port|pid>"` (from `idb_list`) works directly in the GUI's database, with no path needed and no save conflicts.
  - **Already open elsewhere:** if a GUI, or any other IDA process, holds the database, the open does not create a second writer. It returns a `conflict` and `options`. Re-call with `on_conflict="use_gui"` (attach to the GUI), `"copy"` (private writable copy of the last saved database), or `"read_only"` (private copy, with `idb_save`/autosave refused). idalib has no native read-only mode, hence the copy.
  - **Load fixups:** `bitness`/`processor` are applied after load via `set_bitness`.
  - **Stale components:** unsaved `.id0/.id1/...` left by a worker that died are moved to `.ida_stale/`. Components held open by a live process are never touched.
  - **Idle shutdown:** `idle_ttl_sec` is how long the worker waits with no requests before saving, closing and exiting. Omitted means the server default (4 hours); `0` means never.
  - **Idle auto-save:** on by default. A changed database is saved once no request has arrived for `autosave_idle_sec` seconds. Pass `autosave=False` to disable it, or use `idb_autosave` later.
- `idb_list()`: List open sessions and running GUI IDA instances. Each entry has `adopted` (True if this supervisor manages it, False for GUIs/workers discovered but not yet opened via `idb_open`), `backend` (`worker` or `gui`), `is_active`, and process IDs.
- `idb_close(database, save=True)`: Save (optionally), unregister the session, and terminate its owned worker, freeing a slot toward `--max-workers`. Adopted GUI/worker instances are detached, not killed. `save=False` also clears a wedged worker.
- `idb_save(session_id, path="")`: Save a session's IDB to disk. Forwarded as a regular worker tool (`database=<id>` injected) — same signature in both backends.
- `idb_autosave(enabled=None, idle_sec=None, save_now=False, database=<id>)`: Show or change idle auto-save for a headless session.
- `list_pe_images(directory, recursive=False, hash=True, include_non_pe=False)`, `idb_aliases(filename=None)`, `idb_search_roots()`: Discover binaries and inspect the filename alias registry used by `idb_open`. `--search-root DIR` (repeatable, plus `--search-root-recursive`) pre-scans directories at startup.
- Per-database health: call `server_health(database=<id>)` (forwarded). `idb_list()` reports `is_active` from the supervisor's TCP/RPC probe.

With the GUI proxy (`ida-pro-mcp`), `list_instances()` and `select_instance(port)` switch between several open IDA windows, per MCP session.

Worker controls:

- `--max-workers N`: maximum simultaneous database workers (`0` = unlimited, default `4`).
- `IDA_MCP_MAX_WORKERS`: environment default for `--max-workers`.

The bundled Codex plugin forwards the runtime's `IDA_MCP_*` configuration variables from the Codex host environment:

- Capacity and lifecycle: `IDA_MCP_MAX_WORKERS`, `IDA_MCP_OPEN_TIMEOUT`, `IDA_MCP_WEDGED_GRACE_SEC`, `IDA_MCP_WORKER_CALL_TIMEOUT`.
- Health probes: `IDA_MCP_HEALTH_TCP_TIMEOUT`, `IDA_MCP_HEALTH_RPC_TIMEOUT`, `IDA_MCP_HEALTH_RETRIES`, `IDA_MCP_HEALTH_RETRY_BACKOFF`.
- Worker behavior: `IDA_MCP_TOOL_TIMEOUT_SEC`, `IDA_MCP_ANALYSIS_PROMPT`, `IDA_MCP_URL`.
- Request logging: `IDA_MCP_LOG_REQUESTS`, `IDA_MCP_LOG_SKIP_METHODS`.


## MCP Resources

**Resources** represent browsable state (read-only data) following MCP's philosophy.

**Core IDB State:**
- `ida://idb/metadata` - IDB file info (path, arch, base, size, hashes)
- `ida://idb/segments` - Memory segments with permissions
- `ida://idb/entrypoints` - Entry points (main, TLS callbacks, etc.)

**UI State:**
- `ida://cursor` - Current cursor position and function
- `ida://selection` - Current selection range

**Type Information:**
- `ida://types` - All local types
- `ida://structs` - All structures/unions
- `ida://struct/{name}` - Structure definition with fields

**Lookups:**
- `ida://import/{name}` - Import details by name
- `ida://export/{name}` - Export details by name
- `ida://xrefs/from/{addr}` - Cross-references from address

## Core Functions

- `lookup_funcs(queries)`: Get function(s) by address or name (auto-detects, accepts list or comma-separated string).
- `int_convert(inputs)`: Convert numbers to different formats (decimal, hex, bytes, ASCII, binary).
- `list_funcs(queries)`: List functions (paginated, filtered).
- `list_globals(queries)`: List global variables (paginated, filtered).
- `imports(offset, count)`: List all imported symbols with module names (paginated).
- `decompile(addrs, include_addresses, max_lines, offset)`: Decompile one or more functions (list or comma-separated, max 50); always returns a list, one result per address, with per-item errors and a resumable `cursor`.
- `disasm(addr)`: Disassemble function with full details (arguments, stack frame, etc).
- `xrefs_to(addrs)`: Get all cross-references to address(es).
- `xrefs_to_field(queries)`: Get cross-references to specific struct field(s).
- `callees(addrs)`: Get functions called by function(s) at address(es).

## Modification Operations

- `add_bookmark(addr, name, prefix)`: Add or replace the IDA bookmark at an address; set `prefix=""` for no prefix.
- `set_comments(items)`: Set comments at address(es) in both disassembly and decompiler views.
- `patch_asm(items)`: Patch assembly instructions at address(es).
- `declare_type(decls)`: Declare C type(s) in the local type library.
- `define_func(items)`: Define function(s) at address(es). Optionally specify `end` for explicit bounds, and `thumb` (ARM) to decode as Thumb/ARM.
- `get_func_flags(addrs)` / `set_func_flags(items, reanalyze_callers=True)`: Read or set function flags (`noreturn`, `thunk`, `lib`, `hidden`, `static`, `far`). Changing `noreturn` re-analyzes every caller so flow after the calls is rebuilt. `func_query` also reports and filters these flags.
- `define_code(items)`: Convert bytes to code instruction(s) at address(es).
- `undefine(items)`: Undefine item(s) at address(es), converting back to raw bytes. Optionally specify `end` or `size`.

## Load & Segment Operations

IDA fixes addressing width and processor module at load time, and idalib cannot
pass load options to it (`open_database(args=...)` aborts with IDA internal
error 30602), so these repair the database after it is open. They work on
databases opened earlier too.

- `set_bitness(bitness, segments, processor, undefine, reanalyze)`: Change segment addressing width to 16/32/64-bit, optionally switching processor module. Defaults to every segment plus the database-wide bitness, undefining and re-analyzing what it changed. Raw and extender images load at the host width, so a 32-bit image decodes as 64-bit code until this is called.
- `load_raw_file(path, base, bitness, file_offset, size, segment_name, as_code, reanalyze)`: Map a headerless blob (extracted overlay, dumped image, extender payload) into the open database at a chosen address. Overlapping an existing segment is refused.
- `analyze(ranges=None, mode="plan")`: Run auto-analysis over ranges (`start-end`, `start:size`, segment names; default all) and block until it finishes. It works even when the database was opened without analysis, and reports elapsed time and function counts before and after.
- `set_sreg(items, undefine=False, reanalyze=True)` / `get_sreg(addrs, reg="T")`: Set or read a segment register over ranges. On 32-bit ARM, `reg="T", value=1` marks Thumb code (0 = ARM), bounded to `[start, end)`. Also works for other processors' segment registers.
- `create_segment(start, end|size, name, sclass, bitness, permissions)`: Create an empty segment -- a BSS range the input file doesn't contain, for instance -- instead of zero-padding the input to fake it.
- `rebase(new_base|delta)`: Move the whole program to a different load address, letting the loader fix up stored addresses.

After a width change the affected segments are left undefined, and a raw image
has no entry points for auto-analysis to follow: seed it with `define_code` or
`define_func` at a known anchor. Segment views (`ida://idb/segments`,
`survey_binary`) report `bitness` so the current width is visible.

## Memory Reading Operations

- `get_bytes(regions)`: Read raw bytes at address(es) as hex -- `{addr, size}` or a list of them. Nothing has to be defined first, so it is the first thing to reach for when disassembly looks wrong.
- `get_int(queries)`: Read integer values using ty (i8/u64/i16le/i16be/etc).
- `get_string(addrs)`: Read null-terminated string(s).
- `get_global_value(queries)`: Read global variable value(s) by address or name (auto-detects, compile-time values).

## Stack Frame Operations

- `stack_frame(addrs)`: Get stack frame variables for function(s).
- `declare_stack(items)`: Create stack variable(s) at specified offset(s).
- `delete_stack(items)`: Delete stack variable(s) by name.

## Structure Operations

- `read_struct(queries)`: Read structure field values at specific address(es).
- `search_structs(filter)`: Search structures by name pattern.

## Debugger Operations (Extension)

Debugger tools are hidden by default. Enable with `?ext=dbg` query parameter:

```
http://127.0.0.1:13337/mcp?ext=dbg
```

**Control:**
- `dbg_start()`: Start debugger process.
- `dbg_exit()`: Exit debugger process.
- `dbg_continue()`: Continue execution.
- `dbg_run_to(addr)`: Run to address.
- `dbg_step_into()`: Step into instruction.
- `dbg_step_over()`: Step over instruction.

**Breakpoints:**
- `dbg_bps()`: List all breakpoints.
- `dbg_add_bp(addrs)`: Add breakpoint(s).
- `dbg_delete_bp(addrs)`: Delete breakpoint(s).
- `dbg_toggle_bp(items)`: Enable/disable breakpoint(s).

**Registers:**
- `dbg_regs()`: All registers, current thread.
- `dbg_regs_all()`: All registers, all threads.
- `dbg_regs_remote(tids)`: All registers, specific thread(s).
- `dbg_gpregs()`: GP registers, current thread.
- `dbg_gpregs_remote(tids)`: GP registers, specific thread(s).
- `dbg_regs_named(names)`: Named registers, current thread.
- `dbg_regs_named_remote(tid, names)`: Named registers, specific thread.

**Stack & Memory:**
- `dbg_stacktrace()`: Call stack with module/symbol info.
- `dbg_read(regions)`: Read memory from debugged process.
- `dbg_write(regions)`: Write memory to debugged process.

## Advanced Analysis Operations

- `py_eval(code)`: Execute arbitrary Python code in IDA context (returns dict with result/stdout/stderr, supports Jupyter-style evaluation).
- `analyze_funcs(addrs)`: Comprehensive function analysis (decompilation, assembly, xrefs, callees, callers, strings, constants, basic blocks).

## Pattern Matching & Search

- `find_regex(queries)`: Search strings with case-insensitive regex (paginated).
- `find_bytes(patterns, limit=1000, offset=0)`: Find byte pattern(s) in binary (e.g., "48 8B ?? ??"). Max limit: 10000.
- `find_insns(sequences, limit=1000, offset=0)`: Find instruction sequence(s) in code. Max limit: 10000.
- `find(type, targets, limit=1000, offset=0)`: Advanced search (immediate values, strings, data/code references). Max limit: 10000.

## Control Flow Analysis

- `basic_blocks(addrs)`: Get basic blocks with successors and predecessors.

## Type Operations

- `set_type(edits)`: Apply type(s) to functions, globals, locals, or stack variables.
- `infer_types(addrs)`: Infer types at address(es) using Hex-Rays or heuristics.

## Export Operations

- `export_funcs(addrs, format)`: Export function(s) in specified format (json, c_header, or prototypes).
- `export_func_list(filter, ranges, path, offset)` / `import_func_list(data|path, create_missing, update_bounds, overwrite_names, overwrite_comments, apply_flags, rebase, dry_run)`: Bulk-sync function starts, ends, names, comments, flags and Thumb mode with another database (e.g. Ghidra) in the `ida-mcp-funcs` JSON format; see [docs/func-list-format.md](docs/func-list-format.md).

## Graph Operations

- `callgraph(roots, max_depth)`: Build call graph from root function(s) with configurable depth.

## Batch Operations

- `rename(batch)`: Unified batch rename operation for functions, globals, locals, and stack variables (accepts dict with optional `func`, `data`, `local`, `stack` keys).
- `patch(patches)`: Patch multiple byte sequences at once.
- `put_int(items)`: Write integer values using ty (i8/u64/i16le/i16be/etc).

**Key Features:**

- **Type-safe API**: All functions use strongly-typed parameters with TypedDict schemas for better IDE support and LLM structured outputs
- **Batch-first design**: Most operations accept both single items and lists
- **Consistent error handling**: All batch operations return `[{..., error: null|string}, ...]`
- **Cursor-based pagination**: Search functions return `cursor: {next: offset}` or `{done: true}` (default limit: 1000, enforced max: 10000 to prevent token overflow)
- **Performance**: Strings are cached with MD5-based invalidation to avoid repeated `build_strlist` calls in large projects

## Development

Adding new features is a super easy and streamlined process. All you have to do is add a new `@tool` function to the modular API files in `src/ida_pro_mcp/ida_mcp/api_*.py` and your function will be available in the MCP server without any additional boilerplate! Below is a video where I add the `get_metadata` function in less than 2 minutes (including testing):

https://github.com/user-attachments/assets/951de823-88ea-4235-adcb-9257e316ae64

To test the MCP server itself:

```sh
npx -y @modelcontextprotocol/inspector
```

This will open a web interface at http://localhost:5173 and allow you to interact with the MCP tools for testing.

For testing I create a symbolic link to the IDA plugin and then POST a JSON-RPC request directly to `http://localhost:13337/mcp`. After [enabling symbolic links](https://learn.microsoft.com/en-us/windows/apps/get-started/enable-your-device-for-development) you can run the following command:

```sh
uv run ida-pro-mcp --install
```

Generate the changelog of direct commits to `main`:

```sh
git log --first-parent --no-merges 1.2.0..main "--pretty=- %s"
```
