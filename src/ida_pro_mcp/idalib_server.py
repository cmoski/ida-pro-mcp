import argparse
import logging
import os
import signal
import threading
import time
from pathlib import Path
from typing import Annotated, Any, TypedDict

# idapro must go first to initialize idalib
import idapro
import ida_auto
import ida_funcs
import ida_idp
import ida_loader

from ida_pro_mcp.ida_mcp import MCP_SERVER, MCP_UNSAFE
from ida_pro_mcp.ida_mcp.api_core import (
    ServerWarmupResult,
    invalidate_strings_cache,
    server_warmup,
)
from ida_pro_mcp.ida_mcp import listing_index
from ida_pro_mcp.ida_mcp.auto_steps import step_analysis
from ida_pro_mcp.ida_mcp.discovery import register_instance, unregister_instance
from ida_pro_mcp.ida_mcp.http import IdaMcpHttpRequestHandler
from ida_pro_mcp.ida_mcp.mainthread import get_pump
from ida_pro_mcp.ida_mcp.sync import (
    get_thread_timeout_override,
    set_thread_timeout_override,
)
from ida_pro_mcp.ida_mcp.profile import apply_profile, load_profile
from ida_pro_mcp.ida_mcp.rpc import (
    configured_download_base_url,
    set_download_base_url,
    tool,
)
from ida_pro_mcp.autosave import IdleAutosave
from ida_pro_mcp.idalib_session_manager import get_session_manager
from ida_pro_mcp.worker_lifecycle import WorkerLifecycle


class IdalibSessionInfo(TypedDict):
    session_id: str
    input_path: str
    filename: str
    created_at: str
    last_accessed: str
    is_analyzing: bool
    metadata: dict[str, Any]


class IdalibSessionListInfo(IdalibSessionInfo, total=False):
    is_active: bool


class AnalysisStatus(TypedDict, total=False):
    state: str  # "running" | "done" | "not_started" | "failed"
    background: bool
    elapsed_sec: float
    steps: int
    slices: int
    funcs: int
    max_step_ms: float
    finished_age_sec: float | None
    error: str | None
    note: str


class IdalibOpenResult(TypedDict, total=False):
    success: bool
    session: IdalibSessionInfo
    warmup: ServerWarmupResult | None
    analysis: AnalysisStatus
    message: str
    error: str


class IdbAutosaveResult(TypedDict, total=False):
    enabled: bool
    idle_sec: float
    dirty: bool
    saves: int
    last_save_age_sec: float | None
    last_save_ok: bool | None
    last_error: str | None
    saved_now: bool
    error: str


class IdalibListResult(TypedDict, total=False):
    sessions: list[IdalibSessionListInfo]
    count: int
    error: str


logger = logging.getLogger(__name__)

IDB_MANAGEMENT_TOOLS = {
    "idb_open",
    "idb_list",
    "idb_autosave",
    "analysis_status",
}


_LIFECYCLE = WorkerLifecycle()
_PUMP = get_pump()
# Idle auto-save: on by default, configurable per session via idb_open /
# idb_autosave. Saves while the worker sits idle so a crash or kill loses at
# most the work since the last idle period, not everything since open.
_AUTOSAVE = IdleAutosave()
_AUTOSAVE_TIMEOUT_SEC = 300.0
# While background analysis keeps changing the database, auto-save at most
# this often (a checkpoint), plus once when analysis finishes.
_ANALYSIS_CHECKPOINT_SEC = 900.0
# Length of one background-analysis slice. A queued tool call waits at most
# about this long (plus the duration of a single analysis step).
_ANALYSIS_SLICE_SEC = 0.1
_INDEX_SLICE_SEC = 0.1
_LISTING_INDEX_ENV = "IDA_MCP_LISTING_INDEX"

# IDB events that mean the database content changed. Any of them marks the
# database dirty for the idle auto-saver.
_DIRTY_EVENTS = (
    "renamed",
    "cmt_changed",
    "extra_cmt_changed",
    "range_cmt_changed",
    "func_added",
    "func_updated",
    "deleting_func",
    "set_func_start",
    "set_func_end",
    "func_tail_appended",
    "func_tail_deleted",
    "func_noret_changed",
    "ti_changed",
    "op_ti_changed",
    "op_type_changed",
    "local_types_changed",
    "byte_patched",
    "make_code",
    "make_data",
    "destroyed_items",
    "segm_added",
    "segm_deleted",
    "segm_moved",
    "segm_name_changed",
    "sgr_changed",
    "bookmark_changed",
    "frame_udm_created",
    "frame_udm_deleted",
    "frame_udm_renamed",
    "frame_udm_changed",
    "lt_udm_created",
    "lt_udm_deleted",
    "lt_udm_renamed",
    "lt_udm_changed",
    "lt_edm_created",
    "lt_edm_deleted",
    "lt_edm_renamed",
    "lt_edm_changed",
)


class _DirtyHooks(ida_idp.IDB_Hooks):
    pass


def _mark_dirty_handler(self, *args):
    _AUTOSAVE.mark_dirty()
    return 0


for _event in _DIRTY_EVENTS:
    if hasattr(ida_idp.IDB_Hooks, _event):
        setattr(_DirtyHooks, _event, _mark_dirty_handler)

_DIRTY_HOOKS: _DirtyHooks | None = None


def _install_dirty_hooks() -> None:
    global _DIRTY_HOOKS
    if _DIRTY_HOOKS is not None:
        return
    hooks = _DirtyHooks()
    if hooks.hook():
        _DIRTY_HOOKS = hooks
    else:
        logger.warning("Could not install IDB hooks; idle auto-save disabled")
        _AUTOSAVE.configure(enabled=False)


def _pause_dirty_hooks(paused: bool) -> None:
    """Analysis fires millions of IDB events; a Python callback for each
    slows it down noticeably. While background analysis runs, each slice that
    made progress marks the database dirty instead."""
    hooks = _DIRTY_HOOKS
    if hooks is None:
        return
    try:
        if paused:
            hooks.unhook()
        else:
            hooks.hook()
    except Exception:
        logger.debug("toggling dirty hooks failed", exc_info=True)


# -- background auto-analysis --------------------------------------------


class _AnalysisTracker:
    """Progress of the database's auto-analysis. Read from any thread."""

    def __init__(self):
        self._lock = threading.Lock()
        self.state = "not_started"
        self.background = False
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self.steps = 0
        self.slices = 0
        self.funcs = 0
        self.max_step_ms = 0.0
        self.error: str | None = None
        self.session = None

    def start(self, session, funcs: int) -> None:
        with self._lock:
            self.state = "running"
            self.background = True
            self.started_at = time.monotonic()
            self.finished_at = None
            self.steps = self.slices = 0
            self.funcs = funcs
            self.max_step_ms = 0.0
            self.error = None
            self.session = session

    def mark_done_without_background(self) -> None:
        with self._lock:
            self.state = "done"
            self.background = False

    def record(self, steps: int, max_step_ms: float, funcs: int) -> None:
        with self._lock:
            self.steps += steps
            self.slices += 1
            self.funcs = funcs
            self.max_step_ms = max(self.max_step_ms, max_step_ms)

    def finish(self, error: str | None = None) -> None:
        with self._lock:
            self.state = "failed" if error else "done"
            self.error = error
            self.finished_at = time.monotonic()
            if self.session is not None:
                self.session.is_analyzing = False

    @property
    def running(self) -> bool:
        with self._lock:
            return self.state == "running"

    def snapshot(self) -> AnalysisStatus:
        with self._lock:
            now = time.monotonic()
            end = self.finished_at if self.finished_at is not None else now
            out: AnalysisStatus = {
                "state": self.state,
                "background": self.background,
                "elapsed_sec": round(end - self.started_at, 1) if self.started_at else 0.0,
                "steps": self.steps,
                "slices": self.slices,
                "funcs": self.funcs,
                "max_step_ms": self.max_step_ms,
                "finished_age_sec": (
                    round(now - self.finished_at, 1) if self.finished_at is not None else None
                ),
                "error": self.error,
            }
        if out["state"] == "running":
            out["note"] = (
                "Auto-analysis is still running in the background. Tools work now, "
                "but functions, xrefs, names and types may be incomplete until state "
                "is 'done'. Call analyze(mode='wait') to block until it finishes."
            )
        return out


_ANALYSIS = _AnalysisTracker()


def _analysis_slice() -> bool:
    """One background slice on the main thread. True when analysis is done."""
    try:
        result = step_analysis(_ANALYSIS_SLICE_SEC)
    except Exception as e:
        logger.exception("Background auto-analysis failed")
        _finish_background_analysis(error=str(e))
        return True
    _ANALYSIS.record(result["steps"], result["max_step_ms"], ida_funcs.get_func_qty())
    if result["steps"]:
        _AUTOSAVE.mark_dirty()
    if result["finished"]:
        _finish_background_analysis()
        return True
    return False


def _finish_background_analysis(error: str | None = None) -> None:
    _ANALYSIS.finish(error)
    _pause_dirty_hooks(False)
    # Strings defined during analysis were not in any cache built earlier.
    invalidate_strings_cache()
    snap = _ANALYSIS.snapshot()
    logger.info(
        "Background auto-analysis %s: %.1fs, %d steps, %d functions",
        snap["state"],
        snap["elapsed_sec"],
        snap["steps"],
        snap["funcs"],
    )
    # Checkpoint the finished analysis: losing hours of it to a crash hurts.
    if error is None and _AUTOSAVE.enabled and _AUTOSAVE.dirty:
        if _AUTOSAVE.run_save(_save_database_now):
            logger.info("Saved database after auto-analysis")
    if error is None:
        _start_background_index()


def _listing_index_enabled() -> bool:
    value = os.environ.get(_LISTING_INDEX_ENV, "1").strip().lower()
    return value not in ("0", "false", "no", "off")


def _index_slice() -> bool:
    """One background slice of listing-index building (for search_text)."""
    index = listing_index.get_index()
    done = index.build_step(_INDEX_SLICE_SEC)
    if done:
        status = index.status()
        logger.info(
            "Listing index built: %d windows, %.1f MB, %.0fs rendering",
            status["windows"],
            status["mb"],
            index.render_seconds,
        )
    return done


def _start_background_index() -> None:
    """Build the search_text listing index between tool calls. Main thread."""
    if not _listing_index_enabled():
        return
    if not _PUMP.active:
        _PENDING_INDEX[0] = True
        return
    if _PUMP.has_background():
        return  # analysis still running; it starts the index when it finishes
    _PUMP.set_background(_index_slice, label="listing_index")


_PENDING_INDEX = [False]


def _start_background_analysis(session) -> bool:
    """Attach stepped auto-analysis to the pump. Main thread only."""
    ida_auto.enable_auto(True)
    if ida_auto.auto_is_ok():
        _ANALYSIS.mark_done_without_background()
        session.is_analyzing = False
        return False
    session.is_analyzing = True
    _ANALYSIS.start(session, ida_funcs.get_func_qty())
    _pause_dirty_hooks(True)
    _AUTOSAVE.mark_dirty()
    if _PUMP.active:
        _PUMP.set_background(_analysis_slice, label="auto_analysis")
    else:
        # No pump yet (initial CLI open before serving): it attaches below.
        _PENDING_BACKGROUND[0] = True
    return True


_PENDING_BACKGROUND = [False]


def _save_database_now() -> tuple[bool, str | None]:
    """In-place native save (same as idb_save with no path). Main thread only."""
    if get_session_manager()._active_session_id is None:
        return False, "no database open"
    ok = bool(ida_loader.save_database(None, 0))
    return ok, None if ok else "save_database returned false"


def _save_via_pump() -> tuple[bool, str | None]:
    if _PUMP.active and not _PUMP.on_main_thread():
        return _PUMP.submit(_save_database_now, label="autosave", timeout=_AUTOSAVE_TIMEOUT_SEC)
    return _save_database_now()


def _autosave_tick() -> None:
    """Watchdog poll: save if dirty, enabled, and idle long enough."""
    if _AUTOSAVE.maybe_save(
        idle_for_sec=_LIFECYCLE.idle_for_sec(),
        # Only a running tool call blocks a save; background analysis yields.
        busy=_PUMP.busy_status() is not None,
        save=_save_via_pump,
        min_interval_sec=_ANALYSIS_CHECKPOINT_SEC if _ANALYSIS.running else 0.0,
    ):
        logger.info("Idle auto-save completed")
_REGISTERED_PORT: int | None = None
_BOUND_HOST: str = ""
_BOUND_PORT: int = 0


def _register_in_discovery(host: str, port: int, input_path: Path) -> None:
    global _REGISTERED_PORT
    try:
        register_instance(
            host=host,
            port=port,
            pid=os.getpid(),
            binary=input_path.name,
            idb_path=str(input_path),
            backend="worker",
        )
        _REGISTERED_PORT = port
        logger.info("Registered idalib worker in discovery (port %d)", port)
    except Exception:
        logger.exception("Failed to register worker in discovery")


def _deregister_from_discovery() -> None:
    global _REGISTERED_PORT
    if _REGISTERED_PORT is None:
        return
    try:
        unregister_instance(_REGISTERED_PORT)
    except Exception:
        logger.debug("Failed to unregister worker", exc_info=True)
    _REGISTERED_PORT = None


@tool
def idb_open(
    input_path: Annotated[str, "Path to the binary file to analyze"],
    run_auto_analysis: Annotated[bool, "Run automatic analysis on the binary"] = True,
    build_caches: Annotated[bool, "Build core caches after open"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays decompiler after open"] = True,
    wait_analysis: Annotated[
        bool,
        "Block until auto-analysis finishes before returning. Default false: "
        "return right after loading and analyze in the background.",
    ] = False,
    idle_ttl_sec: Annotated[
        float,
        "Seconds with no requests before the worker self-exits (0 = never).",
    ] = 14400,
    preferred_session_id: Annotated[
        str,
        "Preferred session ID (auto-generated if empty). Ignored if the file is already open.",
    ] = "",
    autosave: Annotated[bool, "Save automatically while idle (default true)"] = True,
    autosave_idle_sec: Annotated[
        float, "Idle seconds before an auto-save (default 60, min 5)"
    ] = IdleAutosave.DEFAULT_IDLE_SEC,
) -> IdalibOpenResult:
    """Open a binary, activate it, and warm up subsystems in one call.

    Auto-analysis runs in the background by default: the call returns once the
    file is loaded, and tools work while analysis continues (results may be
    incomplete until analysis_status() reports 'done').
    """

    if _PUMP.active and not _PUMP.on_main_thread():
        # open_database and everything after it must run on the IDA thread.
        return _PUMP.submit(
            lambda: idb_open(
                input_path,
                run_auto_analysis,
                build_caches,
                init_hexrays,
                wait_analysis,
                idle_ttl_sec,
                preferred_session_id,
                autosave,
                autosave_idle_sec,
            ),
            label="idb_open",
        )

    # Opening is bounded by the supervisor's open timeout, not the 30s
    # per-tool deadline: the @idasync helpers it calls (server_warmup's cache
    # build, health payload) can take minutes on multi-GB databases, and a
    # deadline hit there failed the whole open and got the worker killed.
    previous_override = get_thread_timeout_override()
    set_thread_timeout_override(0)
    try:
        return _idb_open_body(
            input_path,
            run_auto_analysis,
            build_caches,
            init_hexrays,
            wait_analysis,
            idle_ttl_sec,
            preferred_session_id,
            autosave,
            autosave_idle_sec,
        )
    finally:
        set_thread_timeout_override(previous_override)


def _idb_open_body(
    input_path: str,
    run_auto_analysis: bool,
    build_caches: bool,
    init_hexrays: bool,
    wait_analysis: bool,
    idle_ttl_sec: float,
    preferred_session_id: str,
    autosave: bool,
    autosave_idle_sec: float,
) -> IdalibOpenResult:
    try:
        manager = get_session_manager()
        resolved_path = Path(input_path).resolve()
        load_started_at = time.monotonic()
        background = run_auto_analysis and not wait_analysis
        already_open = any(
            s.get("input_path") == str(resolved_path) for s in manager.list_sessions()
        )
        opened_session_id = manager.open_binary(
            resolved_path,
            # Background mode loads without the blocking auto_wait (which in
            # idalib holds the GIL and ignores cancellation) and steps the
            # analysis queue from the pump instead.
            run_auto_analysis=run_auto_analysis and not background,
            session_id=preferred_session_id or None,
        )
        session = manager.activate_session(opened_session_id)
        if not already_open:
            if background:
                _start_background_analysis(session)
            elif run_auto_analysis:
                _ANALYSIS.mark_done_without_background()
        warmup: ServerWarmupResult | None = None
        if build_caches or init_hexrays:
            warmup = server_warmup(
                wait_auto_analysis=False,
                # The strings list is incomplete mid-analysis; it is built
                # lazily on first use and rebuilt after analysis finishes.
                build_caches=build_caches and not _ANALYSIS.running,
                init_hexrays=init_hexrays,
            )
        if not already_open and not _ANALYSIS.running:
            _start_background_index()
        _LIFECYCLE.set_idle_ttl(float(idle_ttl_sec), time.monotonic() - load_started_at)
        _AUTOSAVE.configure(enabled=autosave, idle_sec=autosave_idle_sec)
        if _REGISTERED_PORT is None and _BOUND_HOST and _BOUND_PORT:
            _register_in_discovery(_BOUND_HOST, _BOUND_PORT, session.input_path)
        analysis = _ANALYSIS.snapshot()
        message = f"Binary opened: {session.input_path.name} ({opened_session_id})"
        if analysis.get("state") == "running":
            message += "; auto-analysis continues in the background"
        return {
            "success": True,
            "session": session.to_dict(),
            "warmup": warmup,
            "analysis": analysis,
            "message": message,
        }
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


@tool
def idb_list() -> IdalibListResult:
    """List open IDA sessions."""

    try:
        manager = get_session_manager()
        sessions = manager.list_sessions()
        return {"sessions": sessions, "count": len(sessions)}
    except Exception as e:
        return {"error": f"Failed to list sessions: {e}"}


@tool
def analysis_status() -> AnalysisStatus:
    """Report auto-analysis progress for this database.

    state: 'running' (background analysis in progress: tools work, but results
    may be incomplete), 'done', 'not_started' (opened with
    run_auto_analysis=false), or 'failed'. Answers immediately, even while the
    database is busy.
    """
    return _ANALYSIS.snapshot()


@tool
def idb_autosave(
    enabled: Annotated[bool | None, "Turn idle auto-save on/off (omit to keep)"] = None,
    idle_sec: Annotated[
        float | None, "Idle seconds before saving (min 5; omit to keep)"
    ] = None,
    save_now: Annotated[bool, "Also save immediately"] = False,
) -> IdbAutosaveResult:
    """Show or change idle auto-save for this database (on by default).

    While enabled, a changed database is saved once no request has arrived for
    idle_sec seconds, so a crash loses at most the work since the last idle
    period. Disable it for scratch experiments you don't want persisted.
    """
    _AUTOSAVE.configure(enabled=enabled, idle_sec=idle_sec)
    result: IdbAutosaveResult = {}
    if save_now:
        result["saved_now"] = _AUTOSAVE.run_save(_save_via_pump)
    result.update(_AUTOSAVE.snapshot())  # type: ignore[typeddict-item]
    return result


def _install_dispatch_hook() -> None:
    """Wrap the registry dispatcher so every request bumps the watchdog timer."""
    original = MCP_SERVER.registry.dispatch

    def touching_dispatch(request):
        try:
            return original(request)
        finally:
            _LIFECYCLE.touch()

    MCP_SERVER.registry.dispatch = touching_dispatch


def main():
    parser = argparse.ArgumentParser(description="MCP server for IDA Pro via idalib")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show debug messages"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to listen on, default: 127.0.0.1",
    )
    parser.add_argument(
        "--port", type=int, default=8745, help="Port to listen on, default: 8745"
    )
    parser.add_argument(
        "--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)"
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Restrict exposed tools to those listed in a profile file "
            "(one name per line, # for comments). idb_* management tools "
            "are always kept."
        ),
    )
    parser.add_argument(
        "input_path",
        type=Path,
        nargs="?",
        help="Path to the input file to analyze (optional).",
    )
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
        idapro.enable_console_messages(True)
    else:
        log_level = logging.INFO
        idapro.enable_console_messages(False)

    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    global _BOUND_HOST, _BOUND_PORT
    _BOUND_HOST = args.host
    _BOUND_PORT = args.port

    session_manager = get_session_manager()

    if args.input_path is not None:
        if not args.input_path.exists():
            raise FileNotFoundError(f"Input file not found: {args.input_path}")

        logger.info("opening initial database: %s", args.input_path)
        resolved = args.input_path.resolve()
        session_id = session_manager.open_binary(resolved, run_auto_analysis=False)
        logger.info("Initial session created: %s", session_id)
        _start_background_analysis(session_manager.activate_session(session_id))
        _register_in_discovery(args.host, args.port, resolved)
    else:
        logger.info(
            "No initial binary specified. Use idb_open() to load binaries dynamically."
        )

    def _on_lifecycle_exit(reason: str) -> None:
        logger.info("Worker lifecycle requesting shutdown: %s", reason)
        # MCP_SERVER.stop() must be called from outside the serve_forever
        # thread; our watchdog thread qualifies.
        _PUMP.stop()
        try:
            MCP_SERVER.stop()
        except Exception:
            logger.exception("MCP_SERVER.stop() failed during lifecycle shutdown")

    # Background analysis counts as busy: don't idle-exit mid-analysis.
    _LIFECYCLE.set_busy_probe(
        lambda: _PUMP.busy_status() is not None or _PUMP.has_background()
    )
    _install_dirty_hooks()
    _LIFECYCLE.set_tick(_autosave_tick)
    _LIFECYCLE.start(on_shutdown=_on_lifecycle_exit)
    _install_dispatch_hook()

    def cleanup_and_exit(signum, frame):
        logger.info("Signal %s received; shutting down", signum)
        # The main thread runs the pump, not serve_forever, so stopping the
        # server from a helper thread is both safe and required.
        _PUMP.stop()

        def _stop():
            try:
                MCP_SERVER.stop()
            except Exception:
                logger.exception("MCP_SERVER.stop() failed in signal handler")

        threading.Thread(target=_stop, daemon=True, name="signal-stop").start()

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    if not args.unsafe:
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        if MCP_UNSAFE:
            logger.info("Unsafe tools disabled (start with --unsafe to enable)")

    if args.profile is not None:
        try:
            whitelist = load_profile(args.profile)
        except (OSError, UnicodeDecodeError) as e:
            raise SystemExit(f"Failed to read profile '{args.profile}': {e}")
        kept, unknown = apply_profile(
            MCP_SERVER.tools.methods,
            whitelist,
            protected=IDB_MANAGEMENT_TOOLS,
        )
        if unknown:
            logger.warning(
                "Profile references unknown tool(s) (ignored): %s", ", ".join(unknown)
            )
        logger.info(
            "Profile applied: %d whitelisted + %d management tool(s) active",
            len(kept),
            len(IDB_MANAGEMENT_TOOLS),
        )

    from ida_pro_mcp.ida_mcp import trace

    trace.install_tracer()
    logger.info("Tracing tools/call to IDB netnode %s", trace.IDB_NETNODE_NAME)

    # Only a non-blank IDA_MCP_URL counts as "the operator set it" (#383).
    if configured_download_base_url() is None:
        set_download_base_url(f"http://{args.host}:{args.port}")

    try:
        # HTTP on background threads keeps ping/health/cancel answerable while
        # a tool occupies IDA. Arm first: requests may arrive before run().
        _PUMP.arm()
        if _PENDING_BACKGROUND[0]:
            _PENDING_BACKGROUND[0] = False
            _PUMP.set_background(_analysis_slice, label="auto_analysis")
        elif _PENDING_INDEX[0]:
            _PENDING_INDEX[0] = False
            _start_background_index()
        MCP_SERVER.serve(
            host=args.host,
            port=args.port,
            background=True,
            threaded=True,
            request_handler=IdaMcpHttpRequestHandler,
        )
        _PUMP.run()
    finally:
        # Reached once the pump stops: signal handler, watchdog, or an error.
        logger.info("Server loop exited; cleaning up")
        _PUMP.stop()
        try:
            MCP_SERVER.stop()
        except Exception:
            logger.exception("MCP_SERVER.stop() failed during cleanup")
        _LIFECYCLE.stop()
        _deregister_from_discovery()
        try:
            session_manager.close_all_sessions()
        except Exception:
            logger.exception("close_all_sessions raised during cleanup")


if __name__ == "__main__":
    main()
