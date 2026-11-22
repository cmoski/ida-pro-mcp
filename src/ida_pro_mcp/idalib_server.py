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
import ida_idp
import ida_loader

from ida_pro_mcp.ida_mcp import MCP_SERVER, MCP_UNSAFE
from ida_pro_mcp.ida_mcp.api_core import (
    ServerWarmupResult,
    server_warmup,
)
from ida_pro_mcp.ida_mcp.discovery import register_instance, unregister_instance
from ida_pro_mcp.ida_mcp.http import IdaMcpHttpRequestHandler
from ida_pro_mcp.ida_mcp.mainthread import get_pump
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


class IdalibOpenResult(TypedDict, total=False):
    success: bool
    session: IdalibSessionInfo
    warmup: ServerWarmupResult | None
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
}


_LIFECYCLE = WorkerLifecycle()
_PUMP = get_pump()
# Idle auto-save: on by default, configurable per session via idb_open /
# idb_autosave. Saves while the worker sits idle so a crash or kill loses at
# most the work since the last idle period, not everything since open.
_AUTOSAVE = IdleAutosave()
_AUTOSAVE_TIMEOUT_SEC = 300.0

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
        busy=_LIFECYCLE.is_busy(),
        save=_save_via_pump,
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
    """Open a binary, activate it, and warm up subsystems in one call."""

    if _PUMP.active and not _PUMP.on_main_thread():
        # open_database and everything after it must run on the IDA thread.
        return _PUMP.submit(
            lambda: idb_open(
                input_path,
                run_auto_analysis,
                build_caches,
                init_hexrays,
                idle_ttl_sec,
                preferred_session_id,
                autosave,
                autosave_idle_sec,
            ),
            label="idb_open",
        )

    try:
        manager = get_session_manager()
        resolved_path = Path(input_path).resolve()
        load_started_at = time.monotonic()
        opened_session_id = manager.open_binary(
            resolved_path,
            run_auto_analysis=run_auto_analysis,
            session_id=preferred_session_id or None,
        )
        session = manager.activate_session(opened_session_id)
        warmup: ServerWarmupResult | None = None
        if build_caches or init_hexrays:
            warmup = server_warmup(
                wait_auto_analysis=False,
                build_caches=build_caches,
                init_hexrays=init_hexrays,
            )
        _LIFECYCLE.set_idle_ttl(float(idle_ttl_sec), time.monotonic() - load_started_at)
        _AUTOSAVE.configure(enabled=autosave, idle_sec=autosave_idle_sec)
        if _REGISTERED_PORT is None and _BOUND_HOST and _BOUND_PORT:
            _register_in_discovery(_BOUND_HOST, _BOUND_PORT, session.input_path)
        return {
            "success": True,
            "session": session.to_dict(),
            "warmup": warmup,
            "message": (
                f"Binary opened: {session.input_path.name} ({opened_session_id})"
            ),
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
        session_id = session_manager.open_binary(resolved, run_auto_analysis=True)
        logger.info("Initial session created: %s", session_id)
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

    _LIFECYCLE.set_busy_probe(lambda: _PUMP.busy_status() is not None)
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
