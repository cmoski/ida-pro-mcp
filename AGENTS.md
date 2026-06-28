# AGENTS.md

Operational notes for agents working on this repo. See `CLAUDE.md` for the
project overview, conventions, and test commands. This file captures gotchas
that aren't obvious from the code.

## Reloading code into a running deployment (gateway / idalib)

When this server runs behind a gateway (e.g. the Chang gateway exposing the
`ida-pro` backend), there are **three independent restart layers**, each with
different reach. Picking the wrong one looks like "my change didn't take effect"
even though the code on disk is correct. This has bitten us more than once.

1. **Worker tools** — anything in `ida_mcp/api_*.py` (e.g. `rename`, `search_text`,
   the `submit_job`/`job_*` tools). These run in the per-database **idalib worker
   subprocess**, which imports the current `ida_mcp` code **when the session is
   opened**.
   - A gateway `hard` reload only respawns workers that have **no open session**.
   - An **already-open session keeps its old-code worker**. To load new
     worker-side code you must **close and reopen the session**
     (`idalib_close` → `idalib_open`), which spawns a fresh worker that imports
     the latest code.

2. **Supervisor tools** — anything defined in `idalib_supervisor.py` with
   `@mcp.tool` (e.g. `idalib_open`, `list_pe_images`, `idalib_*`). These run in
   the long-lived **supervisor process**, which the gateway's worker-reload does
   **not** restart. Loading supervisor-side changes requires a **manual bounce of
   the supervisor / backend process** (or a full gateway restart that respawns
   the backend).

3. **Gateway schema cache** — the gateway caches each tool's `outputSchema` from
   the backend's manifest. After the backend serves a new schema, refresh the
   cache with a `hard=true` (warm) respawn so re-pulled manifests replace the
   stale ones. Symptom of a stale cache: a structurally-correct response is
   rejected with `Invalid structured content ... is not of type ...`.

   Note: output-schema validation also happens **inside the worker** against the
   worker's own (code-matched) schema. If a worker emits a value its own schema
   forbids, fix the code+schema together — that's a real bug, not a cache issue.

### Quick decision guide
- Changed an `api_*.py` tool and have a session open? **close + reopen** it.
- Changed `idalib_supervisor.py`? **restart the supervisor process**.
- Response rejected by schema validation after a confirmed code update?
  **`hard=true` warm reload** to refresh the gateway manifest cache.

## Verifying changes live

Always run the headless suite first (`uv run ida-mcp-test ...`, see `CLAUDE.md`),
then exercise the change through the live gateway. When opening a binary whose
path differs between your view and the server (e.g. an `F:\` path that only
exists server-side under a `--search-root`), `idalib_open` resolves it by
filename / trailing path components and returns `sha256`+`md5` for verification.
