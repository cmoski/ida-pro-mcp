"""Headless idalib MCP supervisor.

This module is the public ``idalib-mcp`` entry point. It intentionally does
not import idapro/IDAPython modules. Instead it exposes the MCP transport and
routes IDA-facing calls to per-database ``idalib_server`` worker subprocesses.
"""

from __future__ import annotations

import argparse
import copy
import http.client
import importlib.util
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Annotated, Any, Optional, TypedDict

try:
    from . import idalib_paths as _paths
except ImportError:  # executed as a top-level script
    import idalib_paths as _paths  # type: ignore[no-redef]


logger = logging.getLogger(__name__)

_DATABASE_ARG = "database"
_DATABASE_ARG_SCHEMA = {
    "type": "string",
    "description": (
        "Session ID returned by idb_open. Use idb_list to enumerate "
        "open sessions."
    ),
}
_DATABASE_REQUIRED_ERROR = (
    "database is required. Pass database=<session_id> with every tool call. "
    "Open a session with idb_open or enumerate with idb_list."
)

IDB_OPEN_MODES = {
    "prefer_headless",
    "force_headless",
    "prefer_gui",
    "force_gui",
}

IDB_MANAGEMENT_TOOLS = {
    "idb_open",
    "idb_list",
    "idb_close",
    "idb_aliases",
    "idb_search_roots",
    "list_pe_images",
}

def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


# A worker cannot answer a ping while a tool occupies its IDA main thread, so
# probing must separate "process gone" (reap) from "alive but busy" (wait).
WORKER_TCP_HEALTH_TIMEOUT_SEC = _env_float("IDA_MCP_HEALTH_TCP_TIMEOUT", 2.0)
WORKER_RPC_HEALTH_TIMEOUT_SEC = _env_float("IDA_MCP_HEALTH_RPC_TIMEOUT", 10.0)
WORKER_QUICK_TCP_TIMEOUT_SEC = 0.5
WORKER_QUICK_RPC_TIMEOUT_SEC = 2.0
WORKER_HEALTH_RETRIES = int(_env_float("IDA_MCP_HEALTH_RETRIES", 3))
WORKER_HEALTH_RETRY_BACKOFF_SEC = _env_float("IDA_MCP_HEALTH_RETRY_BACKOFF", 1.0)
# How long a live-but-silent worker is tolerated before counting as wedged.
# Generous: analysing a large database legitimately takes a while. 0 disables.
WORKER_WEDGED_GRACE_SEC = _env_float("IDA_MCP_WEDGED_GRACE_SEC", 1800.0)
# Backstop on a forwarded tools/call; the worker has its own per-tool
# timeouts. 0 waits indefinitely.
WORKER_CALL_TIMEOUT_SEC = _env_float("IDA_MCP_WORKER_CALL_TIMEOUT", 900.0)

PARTIAL_DATABASE_EXTENSIONS = (".id0", ".id1", ".id2", ".nam", ".til")

# Upper bound (seconds) on how long a worker may take to open and auto-analyze a
# binary before it is reaped and an error is returned. A malformed or hostile
# binary can drive IDA's auto-analysis into an effectively unbounded loop; with
# no limit this silently wedges the worker process (and the blocking supervisor
# RPC waiting on it) forever, with no progress feedback and no recovery.
# Set IDA_MCP_OPEN_TIMEOUT=0 to wait indefinitely (previous behavior).
WORKER_OPEN_TIMEOUT_SEC = _env_float("IDA_MCP_OPEN_TIMEOUT", 1800.0)


def _import_zeromcp():
    """Import vendored zeromcp without importing ida_mcp/__init__.py."""
    import http.server  # noqa: F401 - prevent local http.py shadowing stdlib

    pkg_dir = Path(__file__).resolve().parent / "ida_mcp"
    sys.path.insert(0, str(pkg_dir))
    try:
        from zeromcp import McpServer  # type: ignore
    finally:
        sys.path.remove(str(pkg_dir))
    return McpServer


McpServer = _import_zeromcp()


def _import_discovery():
    """Import pure-Python GUI instance discovery without importing ida_mcp."""
    path = Path(__file__).resolve().parent / "ida_mcp" / "discovery.py"
    spec = importlib.util.spec_from_file_location("ida_pro_mcp_idalib_supervisor_discovery", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not import discovery module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_discovery = _import_discovery()


def _discovered_instance_backend(instance: dict[str, Any]) -> str:
    backend = instance.get("backend")
    if backend == "worker":
        return "worker"
    if backend == "gui":
        return "gui"
    return "gui"


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
    busy: bool
    backend: str
    owned: bool
    adopted: bool
    pid: int | None
    worker_pid: int | None


IdalibOpenCandidate = _paths.IdalibOpenCandidate
PeImageInfo = _paths.PeImageInfo
PeImageError = _paths.PeImageError
ListPeImagesResult = _paths.ListPeImagesResult


class IdalibOpenResult(TypedDict, total=False):
    success: bool
    session: IdalibSessionInfo
    warmup: dict[str, Any] | None
    message: str
    error: str
    # Path resolution / verification extras.
    sha256: str
    md5: str
    notes: list[str]
    suggestions: list[str]
    candidates: list[IdalibOpenCandidate]
    load_fixup: dict[str, Any]
    autosave: dict[str, Any]


class IdalibListResult(TypedDict, total=False):
    sessions: list[IdalibSessionListInfo]
    count: int
    error: str


class IdalibCloseResult(TypedDict, total=False):
    success: bool
    session_id: str
    backend: str
    owned: bool
    saved: bool | None
    save_error: str
    message: str
    error: str


@dataclass
class WorkerSession:
    session_id: str
    input_path: str
    filename: str
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    is_analyzing: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    host: str = "127.0.0.1"
    port: int = 0
    process: subprocess.Popen | None = None
    backend: str = "worker"
    owned: bool = True
    pid: int | None = None
    last_warmup: dict[str, Any] | None = None
    unresponsive_since: float | None = None

    def to_dict(self) -> IdalibSessionInfo:
        return {
            "session_id": self.session_id,
            "input_path": self.input_path,
            "filename": self.filename,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "is_analyzing": self.is_analyzing,
            "metadata": self.metadata,
        }

    def to_list_dict(self, *, active: bool | None = None) -> IdalibSessionListInfo:
        return {
            **self.to_dict(),
            "is_active": self.is_alive() if active is None else active,
            "backend": self.backend,
            "owned": self.owned,
            "adopted": True,
            "pid": self.pid,
            "worker_pid": self.process.pid if self.process is not None else None,
        }

    def is_alive(self) -> bool:
        if self.backend == "gui":
            try:
                return bool(_discovery.probe_instance(self.host, self.port, timeout=0.5))
            except Exception:
                return False
        return self.process is not None and self.process.poll() is None


class IdalibSupervisor:
    def __init__(
        self,
        mcp: Any,
        *,
        max_workers: int = 4,
        worker_args: list[str] | None = None,
    ):
        self.mcp = mcp
        self.max_workers = max_workers
        self.worker_args = worker_args or []
        self.sessions: dict[str, WorkerSession] = {}
        self.path_to_session: dict[str, str] = {}
        # Bare-filename aliases, --search-root roots, decisive path resolution.
        self.paths = _paths.PathResolver(
            lambda: [s.input_path for s in list(self.sessions.values()) if s.input_path]
        )
        self._schema_worker: WorkerSession | None = None
        self._tools_cache: dict[tuple[str, ...], list[dict]] = {}
        self._resources_cache: dict[str, list[dict]] = {}
        self._lock = RLock()

    # ------------------------------------------------------------------
    # Worker process lifecycle
    # ------------------------------------------------------------------

    def _pick_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def _spawn_worker(self) -> WorkerSession:
        port = self._pick_port()
        cmd = [
            sys.executable,
            "-m",
            "ida_pro_mcp.idalib_server",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            *self.worker_args,
        ]
        logger.info("Spawning idalib worker on 127.0.0.1:%d", port)
        # Detach so the worker survives this supervisor's exit: on Windows
        # spawn in a new process group; on Unix put it in its own session.
        creationflags = 0
        start_new_session = False
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            start_new_session = True
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
            start_new_session=start_new_session,
        )
        worker = WorkerSession(
            session_id=f"__worker_schema_{uuid.uuid4().hex[:8]}",
            input_path="",
            filename="",
            host="127.0.0.1",
            port=port,
            process=process,
            backend="worker",
            owned=True,
            pid=process.pid,
        )
        try:
            self._wait_worker_ready(worker)
        except Exception:
            self._terminate_worker(worker)
            raise
        return worker

    def _wait_worker_ready(self, worker: WorkerSession, timeout: float = 120.0) -> None:
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if worker.process is not None and worker.process.poll() is not None:
                raise RuntimeError(
                    f"idalib worker exited early with code {worker.process.returncode}"
                )
            try:
                self._worker_rpc(worker, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, timeout=2.0)
                return
            except Exception as e:
                last_error = e
                time.sleep(0.2)
        raise TimeoutError(f"idalib worker did not become ready: {last_error}")

    def _terminate_worker(self, worker: WorkerSession) -> None:
        if worker.backend != "worker" or not worker.owned:
            return
        proc = worker.process
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
            proc.wait(timeout=5)

    @staticmethod
    def _partial_database_paths(input_path: str) -> tuple[Path, ...]:
        base = Path(input_path)
        return tuple(
            base.with_name(base.name + ext)
            for ext in PARTIAL_DATABASE_EXTENSIONS
        )

    @classmethod
    def _existing_partial_database_parts(cls, input_path: str) -> set[Path]:
        return {
            part
            for part in cls._partial_database_paths(input_path)
            if part.exists()
        }

    @classmethod
    def _cleanup_partial_database(
        cls,
        input_path: str,
        *,
        preserve: set[Path] | None = None,
    ) -> None:
        """Remove leftover unpacked IDA database parts after a failed/aborted open.

        When a worker is reaped mid-open (for example on an analysis timeout), the
        partially written .id0/.id1/.id2/.nam/.til files are left next to the input.
        IDA then rejects every subsequent open of that path with
        "database is corrupted beyond repair", turning a one-off failure into a
        permanent one. The packed .i64/.idb (a complete saved database) and any
        unpacked parts that predated this open attempt are kept.
        """
        preserved = preserve or set()
        for part in cls._partial_database_paths(input_path):
            if part in preserved:
                continue
            try:
                if part.exists():
                    part.unlink()
            except OSError:
                pass

    def shutdown(self) -> None:
        """Forget local session state without killing persistent workers.

        Spawned workers self-exit after their idle TTL. The only process the
        supervisor is responsible for is the schema worker, which is
        supervisor-private and has no DB; terminate it explicitly.
        """
        with self._lock:
            schema = self._schema_worker
            self.sessions.clear()
            self.path_to_session.clear()
            self._schema_worker = None
        if schema is not None:
            self._terminate_worker(schema)

    def _schema_or_idle_worker(self) -> WorkerSession:
        with self._lock:
            for worker in self.sessions.values():
                if worker.backend == "worker" and worker.is_alive():
                    return worker
            if self._schema_worker is not None and self._schema_worker.is_alive():
                return self._schema_worker
            self._schema_worker = self._spawn_worker()
            return self._schema_worker

    def _take_schema_worker_for_session(self) -> WorkerSession | None:
        if self._schema_worker is not None and self._schema_worker.is_alive():
            worker = self._schema_worker
            self._schema_worker = None
            return worker
        self._schema_worker = None
        return None

    def _prune_dead_worker_sessions_locked(self) -> None:
        stale_session_ids = [
            session.session_id
            for session in self.sessions.values()
            if session.backend == "worker" and session.owned and self._process_exited(session)
        ]
        for session_id in stale_session_ids:
            stale = self._unregister_session_locked(session_id)
            if stale is not None:
                self._terminate_worker(stale)

    def _allocate_worker_locked(self) -> WorkerSession:
        worker = self._take_schema_worker_for_session()
        if worker is not None:
            return worker

        self._prune_dead_worker_sessions_locked()
        owned_workers = sum(
            1
            for session in self.sessions.values()
            if session.backend == "worker" and session.owned and session.is_alive()
        )
        if self.max_workers <= 0 or owned_workers < self.max_workers:
            return self._spawn_worker()

        raise RuntimeError(
            f"Maximum idalib worker count reached ({self.max_workers}). "
            "Wait for an existing worker to be released or increase --max-workers."
        )

    # ------------------------------------------------------------------
    # JSON-RPC forwarding
    # ------------------------------------------------------------------

    def _worker_request_path(self) -> str:
        enabled = sorted(getattr(self.mcp._enabled_extensions, "data", set()))
        if enabled:
            return f"/mcp?ext={','.join(enabled)}"
        return "/mcp"

    def _worker_rpc(
        self,
        worker: WorkerSession,
        payload: dict[str, Any],
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        conn = http.client.HTTPConnection(worker.host, worker.port, timeout=timeout)
        try:
            conn.request(
                "POST",
                self._worker_request_path(),
                body,
                {
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
            )
            response = conn.getresponse()
            raw = response.read().decode("utf-8")
            if response.status >= 400:
                raise RuntimeError(f"HTTP {response.status} {response.reason}: {raw}")
            return json.loads(raw)
        finally:
            conn.close()

    def call_worker_tool(
        self,
        worker: WorkerSession,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> Any:
        response = self._worker_rpc(
            worker,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            },
            timeout=timeout,
        )
        if "error" in response:
            raise RuntimeError(response["error"].get("message", "Unknown worker error"))
        result = response.get("result", {})
        if result.get("isError"):
            content = result.get("content") or []
            message = content[0].get("text", "Unknown worker tool error") if content else "Unknown worker tool error"
            raise RuntimeError(message)
        return result.get("structuredContent")

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def _normalize_input_path(self, input_path: str) -> str:
        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        return str(path.resolve())

    def _path_key(self, path: str) -> str:
        return os.path.normcase(str(Path(path).resolve()))

    def _candidate_idb_paths(self, resolved_path: str) -> set[str]:
        path = Path(resolved_path)
        candidates = {self._path_key(str(path))}
        lower_name = path.name.lower()
        if not lower_name.endswith((".i64", ".idb")):
            candidates.add(self._path_key(str(path) + ".i64"))
            candidates.add(self._path_key(str(path) + ".idb"))
        return candidates

    def _find_instance_for_path(
        self, resolved_path: str, *, backend: str | None = None
    ) -> dict[str, Any] | None:
        """Find a registered IDA instance (GUI or persistent worker) that has
        `resolved_path` open. If `backend` is given, only return instances of
        that backend type."""
        candidates = self._candidate_idb_paths(resolved_path)
        try:
            instances = _discovery.discover_instances()
        except Exception:
            logger.debug("Instance discovery failed", exc_info=True)
            return None

        matches = []
        for instance in instances:
            instance_backend = _discovered_instance_backend(instance)
            if backend is not None and instance_backend != backend:
                continue
            idb_path = str(instance.get("idb_path") or "")
            if not idb_path:
                continue
            try:
                idb_key = self._path_key(idb_path)
            except Exception:
                idb_key = os.path.normcase(idb_path)
            if idb_key in candidates:
                matches.append(instance)

        if len(matches) > 1:
            logger.warning(
                "Multiple IDA instances matched %s; using the first registered instance",
                resolved_path,
            )
        return matches[0] if matches else None

    def _register_session_locked(self, session: WorkerSession, resolved_path: str) -> None:
        self.sessions[session.session_id] = session
        for candidate in self._candidate_idb_paths(resolved_path):
            self.path_to_session[candidate] = session.session_id

    def _session_is_reachable(self, session: WorkerSession) -> bool:
        return bool(self._probe_session_health(session)["reachable"])

    def _session_is_usable(self, session: WorkerSession) -> bool:
        """True unless the session is provably gone; a busy worker stays usable.

        Quick timeouts: callers hold the lock and a dead worker refuses the
        connection at once, so waiting longer only pins the lock.
        """
        health = self._probe_session_health(
            session,
            tcp_timeout=WORKER_QUICK_TCP_TIMEOUT_SEC,
            rpc_timeout=WORKER_QUICK_RPC_TIMEOUT_SEC,
        )
        return self._health_state(health) != "dead"

    def _concurrent_session_for_path(self, resolved: str) -> WorkerSession | None:
        """Session another thread registered for `resolved` while we opened.

        Two clients can now open the same binary at once; the loser's idb_open
        fails on the database lock. Return the winner rather than erroring —
        and never clean up working files that are now the winner's.
        """
        with self._lock:
            existing = self.path_to_session.get(self._path_key(resolved))
            if existing is None:
                return None
            session = self.sessions.get(existing)
            if session is None or not self._session_is_usable(session):
                return None
            session.last_accessed = datetime.now()
            return session

    def _process_exited(self, session: WorkerSession) -> bool:
        process = session.process
        return process is not None and process.poll() is not None

    def _probe_session_health(
        self,
        session: WorkerSession,
        *,
        tcp_timeout: float | None = None,
        rpc_timeout: float | None = None,
    ) -> dict[str, Any]:
        """Classify a session as ok / busy / dead.

        `busy` is alive but not answering, i.e. mid tool call. Only `dead`
        justifies reaping.
        """
        result: dict[str, Any] = {
            "backend": session.backend,
            "process_alive": None,
            "tcp_connect": None,
            "rpc_ping": None,
            "reachable": False,
            "state": "dead",
            "failed_probe": None,
            "error": None,
        }

        if session.backend != "worker":
            alive = session.is_alive()
            result["process_alive"] = alive
            result["reachable"] = alive
            result["state"] = "ok" if alive else "dead"
            if not alive:
                result["failed_probe"] = "process"
                result["error"] = "instance is not responding"
            return result

        if self._process_exited(session):
            result["process_alive"] = False
            result["failed_probe"] = "process"
            result["error"] = "worker process is not running"
            return result
        # Adopted workers have no Popen handle, so liveness is unknown here.
        result["process_alive"] = True if session.process is not None else None

        def busy(probe: str, error: str) -> dict[str, Any]:
            result["failed_probe"] = probe
            result["error"] = error
            # A completed TCP handshake proves the listener is up, which is
            # all we have for adopted workers we hold no process handle for.
            alive = result["process_alive"] is True or result["tcp_connect"] is True
            result["state"] = "busy" if alive else "dead"
            return result

        try:
            with socket.create_connection(
                (session.host, session.port),
                timeout=tcp_timeout or WORKER_TCP_HEALTH_TIMEOUT_SEC,
            ):
                pass
        except Exception as e:
            logger.debug(
                "Worker session %s failed TCP health probe",
                session.session_id,
                exc_info=True,
            )
            result["tcp_connect"] = False
            return busy("tcp_connect", str(e))
        result["tcp_connect"] = True

        try:
            response = self._worker_rpc(
                session,
                {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                timeout=rpc_timeout or WORKER_RPC_HEALTH_TIMEOUT_SEC,
            )
        except Exception as e:
            logger.debug(
                "Worker session %s failed JSON-RPC ping health probe",
                session.session_id,
                exc_info=True,
            )
            result["rpc_ping"] = False
            return busy("rpc_ping", str(e))

        if "error" in response:
            result["rpc_ping"] = False
            return busy(
                "rpc_ping", response["error"].get("message", "JSON-RPC ping returned error")
            )

        result["rpc_ping"] = True
        result["reachable"] = True
        result["state"] = "ok"
        return result

    @staticmethod
    def _health_state(health: dict[str, Any]) -> str:
        state = health.get("state")
        if state:
            return str(state)
        return "ok" if health.get("reachable") else "dead"

    def _probe_session_health_retrying(self, session: WorkerSession) -> dict[str, Any]:
        health = self._probe_session_health(session)
        for attempt in range(1, max(0, WORKER_HEALTH_RETRIES)):
            if self._health_state(health) != "busy":
                break
            time.sleep(WORKER_HEALTH_RETRY_BACKOFF_SEC * attempt)
            health = self._probe_session_health(session)
        health["state"] = self._health_state(health)
        return health

    def _record_health_state(self, session: WorkerSession, state: str) -> bool:
        """Track how long a live worker has been silent. Returns True if wedged."""
        if state != "busy":
            session.unresponsive_since = None
            return False
        now = time.monotonic()
        if session.unresponsive_since is None:
            session.unresponsive_since = now
        if WORKER_WEDGED_GRACE_SEC <= 0:
            return False
        return (now - session.unresponsive_since) >= WORKER_WEDGED_GRACE_SEC

    def _unregister_session_locked(self, session_id: str) -> WorkerSession | None:
        session = self.sessions.pop(session_id, None)
        stale_paths = [
            path_key
            for path_key, bound_session_id in self.path_to_session.items()
            if bound_session_id == session_id
        ]
        for path_key in stale_paths:
            self.path_to_session.pop(path_key, None)
        return session

    def _discard_opened_worker_session(self, worker: WorkerSession) -> None:
        # Race lost: we opened a worker but a competing thread already
        # registered another worker for the same path. The losing worker is
        # only known to us, so just terminate the process.
        self._terminate_worker(worker)

    def _make_gui_session(self, resolved_path: str, session_id: str, instance: dict[str, Any]) -> WorkerSession:
        idb_path = str(instance.get("idb_path") or resolved_path)
        filename = Path(idb_path).name or Path(resolved_path).name
        return WorkerSession(
            session_id=session_id,
            input_path=idb_path,
            filename=filename,
            metadata={"backend": "gui", "requested_path": resolved_path},
            host=str(instance.get("host") or "127.0.0.1"),
            port=int(instance.get("port") or 0),
            process=None,
            backend="gui",
            owned=False,
            pid=int(instance["pid"]) if instance.get("pid") is not None else None,
        )

    def _adopt_worker_instance(
        self, resolved_path: str, session_id: str, instance: dict[str, Any]
    ) -> WorkerSession | None:
        """Register a session pointing at a persistent worker discovered via
        the registry. Returns None if the worker is no longer reachable."""
        worker_stub = WorkerSession(
            session_id=session_id,
            input_path=str(instance.get("idb_path") or resolved_path),
            filename=Path(str(instance.get("idb_path") or resolved_path)).name,
            host=str(instance.get("host") or "127.0.0.1"),
            port=int(instance.get("port") or 0),
            process=None,
            backend="worker",
            owned=False,
            pid=int(instance["pid"]) if instance.get("pid") is not None else None,
        )
        if not self._session_is_reachable(worker_stub):
            return None
        self._register_session_locked(worker_stub, resolved_path)
        logger.info(
            "Adopted persistent worker %s:%s for %s",
            worker_stub.host,
            worker_stub.port,
            resolved_path,
        )
        return worker_stub

    def _launch_gui_and_adopt(self, resolved_path: str, session_id: str) -> WorkerSession:
        launched = _discovery.launch_gui_instance(resolved_path)
        if not launched.get("success"):
            raise RuntimeError(launched.get("error") or "Failed to launch GUI IDA process")
        if "host" not in launched or "port" not in launched:
            raise RuntimeError(
                launched.get("message") or "GUI IDA launched but did not register"
            )
        instance = {
            "host": launched["host"],
            "port": launched["port"],
            "pid": launched.get("pid"),
            "binary": launched.get("binary", Path(resolved_path).name),
            "idb_path": resolved_path,
        }
        with self._lock:
            existing = self.path_to_session.get(self._path_key(resolved_path))
            if existing is not None:
                existing_session = self.sessions.get(existing)
                if existing_session is not None and self._session_is_usable(existing_session):
                    existing_session.last_accessed = datetime.now()
                    return existing_session
                self._unregister_session_locked(existing)
            if session_id in self.sessions:
                raise ValueError(f"Session already exists: {session_id}")
            session = self._make_gui_session(resolved_path, session_id, instance)
            self._register_session_locked(session, resolved_path)
            logger.info(
                "Launched and adopted GUI IDA %s:%s for %s",
                session.host,
                session.port,
                resolved_path,
            )
            return session

    def open_session(
        self,
        input_path: str,
        *,
        mode: str = "prefer_headless",
        run_auto_analysis: bool = True,
        build_caches: bool = True,
        init_hexrays: bool = True,
        idle_ttl_sec: int = 600,
        session_id: str | None = None,
    ) -> WorkerSession:
        if mode not in IDB_OPEN_MODES:
            raise ValueError(
                f"Unknown mode: {mode!r}. Expected one of: {sorted(IDB_OPEN_MODES)}."
            )
        resolved = self._normalize_input_path(input_path)
        with self._lock:
            existing = self.path_to_session.get(self._path_key(resolved))
            if existing is not None:
                session = self.sessions.get(existing)
                if session is not None and self._session_is_usable(session):
                    session.last_accessed = datetime.now()
                    return session
                self._unregister_session_locked(existing)

            if session_id is None:
                session_id = str(uuid.uuid4())[:8]
            elif session_id in self.sessions:
                raise ValueError(f"Session already exists: {session_id}")

            if mode in ("prefer_gui", "force_gui"):
                gui_instance = self._find_instance_for_path(resolved, backend="gui")
                if gui_instance is not None:
                    session = self._make_gui_session(resolved, session_id, gui_instance)
                    self._register_session_locked(session, resolved)
                    logger.info(
                        "Using GUI IDA instance %s:%s for %s",
                        session.host,
                        session.port,
                        resolved,
                    )
                    return session
                if mode == "force_gui":
                    # Drop the lock so the long-running subprocess launch + poll
                    # doesn't block other supervisor operations.
                    break_for_launch = True
                else:
                    break_for_launch = False
            else:
                break_for_launch = False
                # Headless modes never look at GUI instances. Try to attach
                # to a persistent idalib worker that already has this path
                # open (orphan from a previous supervisor).
                worker_instance = self._find_instance_for_path(resolved, backend="worker")
                if worker_instance is not None:
                    adopted = self._adopt_worker_instance(resolved, session_id, worker_instance)
                    if adopted is not None:
                        return adopted

            if not break_for_launch:
                worker = self._allocate_worker_locked()

        if break_for_launch:
            return self._launch_gui_and_adopt(resolved, session_id)

        open_timeout = (WORKER_OPEN_TIMEOUT_SEC or None) if run_auto_analysis else None
        preexisting_parts = self._existing_partial_database_parts(resolved)
        try:
            opened = self.call_worker_tool(
                worker,
                "idb_open",
                {
                    "input_path": resolved,
                    "run_auto_analysis": run_auto_analysis,
                    "build_caches": build_caches,
                    "init_hexrays": init_hexrays,
                    "idle_ttl_sec": idle_ttl_sec,
                    "preferred_session_id": session_id,
                },
                timeout=open_timeout,
            )
            if isinstance(opened, dict) and opened.get("error"):
                raise RuntimeError(str(opened["error"]))
        except TimeoutError:
            self._terminate_worker(worker)
            winner = self._concurrent_session_for_path(resolved)
            if winner is not None:
                return winner
            self._cleanup_partial_database(resolved, preserve=preexisting_parts)
            raise RuntimeError(
                f"idalib worker timed out after {open_timeout:.0f}s while opening and "
                f"analyzing {resolved}. The binary may drive auto-analysis into an "
                f"unbounded loop. Retry with run_auto_analysis=false (open without "
                f"analysis and decompile on demand), or raise IDA_MCP_OPEN_TIMEOUT."
            ) from None
        except Exception:
            self._terminate_worker(worker)
            winner = self._concurrent_session_for_path(resolved)
            if winner is not None:
                return winner
            self._cleanup_partial_database(resolved, preserve=preexisting_parts)
            raise

        worker_session = opened.get("session", {}) if isinstance(opened, dict) else {}
        session = WorkerSession(
            session_id=session_id,
            input_path=str(worker_session.get("input_path") or resolved),
            filename=str(worker_session.get("filename") or Path(resolved).name),
            is_analyzing=bool(worker_session.get("is_analyzing", False)),
            metadata=dict(worker_session.get("metadata") or {}),
            host=worker.host,
            port=worker.port,
            process=worker.process,
            backend="worker",
            owned=True,
            pid=worker.process.pid if worker.process is not None else None,
            last_warmup=opened.get("warmup") if isinstance(opened, dict) else None,
        )
        with self._lock:
            existing = self.path_to_session.get(self._path_key(resolved))
            if existing is not None:
                existing_session = self.sessions.get(existing)
                if existing_session is not None and self._session_is_usable(existing_session):
                    existing_session.last_accessed = datetime.now()
                else:
                    self._unregister_session_locked(existing)
                    existing_session = None
            else:
                existing_session = None

            session_collision_error = None
            if existing_session is None:
                existing_by_id = self.sessions.get(session_id)
                if existing_by_id is not None:
                    if self._session_is_usable(existing_by_id):
                        existing_by_id.last_accessed = datetime.now()
                        session_collision_error = ValueError(f"Session already exists: {session_id}")
                    else:
                        self._unregister_session_locked(session_id)

            if existing_session is None and session_collision_error is None:
                self._register_session_locked(session, resolved)
                return session

        self._discard_opened_worker_session(worker)
        if session_collision_error is not None:
            raise session_collision_error
        return existing_session

    def _resolve_gui_fallback_path(self, session: WorkerSession) -> str:
        candidates = [session.input_path]
        requested_path = session.metadata.get("requested_path")
        if isinstance(requested_path, str) and requested_path and requested_path not in candidates:
            candidates.append(requested_path)

        errors = []
        for candidate in candidates:
            try:
                return self._normalize_input_path(candidate)
            except FileNotFoundError as e:
                errors.append(str(e))

        raise FileNotFoundError(
            "Could not reopen GUI-backed session headlessly. Tried: "
            + ", ".join(candidates)
            + (f" ({'; '.join(errors)})" if errors else "")
        )

    def _reopen_gui_session_headless(self, session: WorkerSession) -> WorkerSession:
        logger.info(
            "GUI IDA backend for session %s is unavailable; reopening headless",
            session.session_id,
        )
        resolved = self._resolve_gui_fallback_path(session)
        with self._lock:
            worker = self._allocate_worker_locked()
        preexisting_parts = self._existing_partial_database_parts(resolved)
        try:
            opened = self.call_worker_tool(
                worker,
                "idb_open",
                {
                    "input_path": resolved,
                    "run_auto_analysis": False,
                    "build_caches": True,
                    "init_hexrays": True,
                    "preferred_session_id": session.session_id,
                },
            )
            if isinstance(opened, dict) and opened.get("error"):
                raise RuntimeError(str(opened["error"]))
        except Exception:
            self._terminate_worker(worker)
            self._cleanup_partial_database(resolved, preserve=preexisting_parts)
            raise

        worker_session = opened.get("session", {}) if isinstance(opened, dict) else {}
        replacement = WorkerSession(
            session_id=session.session_id,
            input_path=str(worker_session.get("input_path") or resolved),
            filename=str(worker_session.get("filename") or Path(resolved).name),
            is_analyzing=bool(worker_session.get("is_analyzing", False)),
            metadata={**session.metadata, **dict(worker_session.get("metadata") or {}), "fallback_from_gui": True},
            host=worker.host,
            port=worker.port,
            process=worker.process,
            backend="worker",
            owned=True,
            pid=worker.process.pid if worker.process is not None else None,
            last_warmup=opened.get("warmup") if isinstance(opened, dict) else None,
        )
        with self._lock:
            current = self.sessions.get(session.session_id)
            if current is session:
                self._register_session_locked(replacement, resolved)
                return replacement
            if current is not None and self._session_is_usable(current):
                current.last_accessed = datetime.now()
                replacement_session = current
                reopen_error = None
            else:
                if current is not None:
                    self._unregister_session_locked(session.session_id)
                replacement_session = None
                reopen_error = RuntimeError(
                    f"Session '{session.session_id}' was closed or replaced while reopening headlessly"
                )

        self._discard_opened_worker_session(worker)
        if replacement_session is not None:
            return replacement_session
        if reopen_error is not None:
            raise reopen_error
        raise RuntimeError(f"Session '{session.session_id}' changed while reopening headlessly")

    def resolve_session(self, database: str) -> WorkerSession:
        session = self.peek_session(database)
        # Short timeouts: a busy worker is forwarded to anyway, so waiting
        # longer here only adds latency to every call.
        health = self._probe_session_health(
            session,
            tcp_timeout=WORKER_QUICK_TCP_TIMEOUT_SEC,
            rpc_timeout=WORKER_QUICK_RPC_TIMEOUT_SEC,
        )
        state = self._health_state(health)
        wedged = self._record_health_state(session, state)
        if state == "ok":
            session.last_accessed = datetime.now()
            return session
        if state == "busy":
            if not wedged:
                # Mid tool call: let the request queue on the worker rather
                # than killing the analysis.
                logger.info(
                    "Worker session %s is busy (%s); forwarding anyway",
                    session.session_id,
                    health.get("failed_probe"),
                )
                session.last_accessed = datetime.now()
                return session
            # Silent past the grace window: confirm with generous timeouts
            # before killing a process that may still be working.
            confirmed = self._probe_session_health_retrying(session)
            if self._health_state(confirmed) == "ok":
                self._record_health_state(session, "ok")
                session.last_accessed = datetime.now()
                return session
            logger.warning(
                "Worker session %s unresponsive for over %.0fs; reaping",
                session.session_id,
                WORKER_WEDGED_GRACE_SEC,
            )
        if session.backend == "gui":
            return self._reopen_gui_session_headless(session)
        session_id = session.session_id
        with self._lock:
            current = self.sessions.get(session_id)
            if current is session:
                self._unregister_session_locked(session_id)
        self._terminate_worker(session)
        raise RuntimeError(f"Worker for session '{session_id}' is not reachable")

    def peek_session(self, database: str) -> WorkerSession:
        if not database:
            raise RuntimeError(_DATABASE_REQUIRED_ERROR)
        with self._lock:
            session = self.sessions.get(database)
            if session is None:
                raise RuntimeError(f"Session not found: {database}")
            session.last_accessed = datetime.now()
            return session

    def close_session(self, database: str, *, save: bool = True) -> IdalibCloseResult:
        """Save (optionally), unregister, and terminate a session's owned worker.

        Adopted GUI/worker instances (``owned`` is False) are detached rather
        than killed: they keep running so another supervisor can adopt them.
        """
        session = self.peek_session(database)
        saved: bool | None = None
        save_error: str | None = None
        if save and self._session_is_reachable(session):
            try:
                result = self.call_worker_tool(session, "idb_save")
                if isinstance(result, dict):
                    saved = bool(result.get("ok"))
                    if result.get("error"):
                        save_error = str(result["error"])
            except Exception as e:
                save_error = str(e)

        with self._lock:
            if self.sessions.get(database) is session:
                self._unregister_session_locked(database)
        self._terminate_worker(session)
        if saved and session.owned:
            # The worker is SIGTERM'd without a clean close_database(), so the
            # working files it unpacked stay behind; the save above already
            # rewrote the packed database.
            self._cleanup_partial_database(session.input_path)

        info: IdalibCloseResult = {
            "success": True,
            "session_id": database,
            "backend": session.backend,
            "owned": session.owned,
            "saved": saved,
            "message": f"Session closed: {session.filename} ({database})",
        }
        if save_error is not None:
            info["save_error"] = save_error
        return info

    def _session_list_entry(self, session: WorkerSession) -> IdalibSessionListInfo:
        """Listing must stay snappy, so probe with short timeouts only."""
        health = self._probe_session_health(
            session,
            tcp_timeout=WORKER_QUICK_TCP_TIMEOUT_SEC,
            rpc_timeout=WORKER_QUICK_RPC_TIMEOUT_SEC,
        )
        state = self._health_state(health)
        entry = session.to_list_dict(active=state != "dead")
        entry["busy"] = state == "busy"
        return entry

    def list_sessions(self) -> list[IdalibSessionListInfo]:
        with self._lock:
            adopted = [
                self._session_list_entry(session) for session in self.sessions.values()
            ]
            adopted_path_keys = {
                key
                for key in self.path_to_session
            }

        unadopted: list[IdalibSessionListInfo] = []
        try:
            instances = _discovery.discover_instances()
        except Exception:
            logger.debug("discover_instances failed during list_sessions", exc_info=True)
            instances = []
        for inst in instances:
            idb_path = str(inst.get("idb_path") or "")
            if idb_path:
                try:
                    key = self._path_key(idb_path)
                except Exception:
                    key = os.path.normcase(idb_path)
                if key in adopted_path_keys:
                    continue
            try:
                reachable = bool(_discovery.probe_instance(inst["host"], inst["port"], timeout=0.5))
            except Exception:
                reachable = False
            backend = _discovered_instance_backend(inst)
            pid = int(inst["pid"]) if inst.get("pid") is not None else None
            unadopted.append(
                {
                    "session_id": "",
                    "input_path": idb_path,
                    "filename": Path(idb_path).name if idb_path else "",
                    "created_at": str(inst.get("started_at", "")),
                    "last_accessed": "",
                    "is_analyzing": False,
                    "metadata": {"backend": backend, "host": inst.get("host"), "port": inst.get("port")},
                    "is_active": reachable,
                    "backend": backend,
                    "owned": False,
                    "adopted": False,
                    "pid": pid,
                    "worker_pid": pid if backend == "worker" else None,
                }
            )
        return adopted + unadopted

    # ------------------------------------------------------------------
    # Schema/resource forwarding
    # ------------------------------------------------------------------

    def worker_tools(self) -> list[dict]:
        cache_key = tuple(sorted(getattr(self.mcp._enabled_extensions, "data", set())))
        with self._lock:
            cached = self._tools_cache.get(cache_key)
            if cached is not None:
                return copy.deepcopy(cached)
        worker = self._schema_or_idle_worker()
        response = self._worker_rpc(worker, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        tools = response.get("result", {}).get("tools", [])
        filtered = [t for t in tools if t.get("name") not in IDB_MANAGEMENT_TOOLS]
        injected = [self._inject_database_arg(t) for t in filtered]
        with self._lock:
            self._tools_cache[cache_key] = injected
        return copy.deepcopy(injected)

    def _inject_database_arg(self, tool: dict) -> dict:
        tool = copy.deepcopy(tool)
        schema = tool.setdefault("inputSchema", {"type": "object", "properties": {}})
        schema.setdefault("type", "object")
        props = schema.setdefault("properties", {})
        props.setdefault(_DATABASE_ARG, _DATABASE_ARG_SCHEMA)
        required = schema.setdefault("required", [])
        if _DATABASE_ARG not in required:
            required.append(_DATABASE_ARG)
        return tool

    def worker_resources(self, method: str) -> list[dict]:
        with self._lock:
            cached = self._resources_cache.get(method)
            if cached is not None:
                return copy.deepcopy(cached)
        worker = self._schema_or_idle_worker()
        response = self._worker_rpc(worker, {"jsonrpc": "2.0", "id": 1, "method": method})
        key = "resources" if method == "resources/list" else "resourceTemplates"
        items = response.get("result", {}).get(key, [])
        with self._lock:
            self._resources_cache[method] = items
        return copy.deepcopy(items)


mcp = McpServer("ida-pro-mcp")
supervisor: IdalibSupervisor | None = None
_original_dispatch = mcp.registry.dispatch


def _require_supervisor() -> IdalibSupervisor:
    if supervisor is None:
        raise RuntimeError("idalib supervisor not initialized")
    return supervisor


def _call_tool_result(result: Any, *, is_error: bool = False) -> dict:
    response: dict[str, Any] = {
        "content": [{"type": "text", "text": json.dumps(result, separators=(",", ":"))}],
        "isError": is_error,
    }
    if not is_error:
        response["structuredContent"] = result if isinstance(result, dict) else {"result": result}
    return response


def _jsonrpc_result(request_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "result": result, "id": request_id}


def _jsonrpc_error(request_id: Any, code: int, message: str) -> dict | None:
    if request_id is None:
        return None
    return {"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": request_id}


def _handle_stale_components(
    sup: IdalibSupervisor, resolved: str, keep_stale_components: bool, notes: list[str]
) -> None:
    """Move unpacked components left by a dead worker out of the way.

    Only runs when nothing live owns the path: no session in this supervisor,
    no registered GUI/worker instance, and the components are not held open by
    another process (an unregistered IDA). Live components are never touched.
    """
    with sup._lock:
        existing_id = sup.path_to_session.get(sup._path_key(resolved))
        existing = sup.sessions.get(existing_id) if existing_id else None
        # A mapped session only counts as an owner while it is alive; a worker
        # that was killed leaves its mapping behind until the next open.
        if existing is not None and sup._session_is_usable(existing):
            return
    if sup._find_instance_for_path(resolved) is not None:
        return
    components = _paths.database_component_paths(resolved)
    state = _paths.components_lock_state(components)
    if state != "stale":
        return
    if keep_stale_components:
        notes.append(
            "Opening over unsaved components left by a worker that died before "
            f"saving ({', '.join(c.name for c in components)}); the database may "
            "be partially analyzed. Verify function counts."
        )
        return
    moved_to, failures = _paths.quarantine_components(resolved, components)
    if moved_to is not None:
        notes.append(
            "Found unsaved database components left by a worker that died before "
            f"saving; moved them to {moved_to} and opened from the last saved state "
            "(or a fresh analysis if none). Pass keep_stale_components=true to open "
            "them instead."
        )
    if failures:
        notes.append(f"Could not move some stale components: {'; '.join(failures)}")


@mcp.tool
def idb_open(
    input_path: Annotated[
        str,
        "Path to the binary. Absolute, partial (e.g. 'system/foo.dll') or a bare "
        "filename known from list_pe_images / --search-root.",
    ],
    mode: Annotated[
        str,
        "How to open: prefer_headless (default; idalib worker, ignore GUI), "
        "force_headless (idalib worker only, never adopt GUI), "
        "prefer_gui (adopt running GUI if present, else spawn worker), "
        "force_gui (adopt running GUI or launch a new IDA GUI process)."
    ] = "prefer_headless",
    run_auto_analysis: Annotated[bool, "Run automatic analysis on the binary"] = True,
    build_caches: Annotated[bool, "Build core caches after open"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays decompiler after open"] = True,
    idle_ttl_sec: Annotated[
        int,
        "Minimum idle TTL in seconds before the headless worker self-exits.",
    ] = 600,
    preferred_session_id: Annotated[
        str, "Preferred session ID (auto-generated if empty). Ignored if the file is already open in a GUI or worker session."
    ] = "",
    directory: Annotated[
        Optional[str], "Directory hint narrowing filename resolution when names repeat."
    ] = None,
    bitness: Annotated[
        Optional[int],
        "Force addressing width after load (16/32/64), applied via set_bitness. "
        "Needed for raw/extender images that load at the host width.",
    ] = None,
    processor: Annotated[
        Optional[str], "Force processor module after load (metapc, arm, ...)."
    ] = None,
    keep_stale_components: Annotated[
        bool,
        "Open unsaved .id0/.id1/... left by a dead worker instead of moving them "
        "to .ida_stale/ (default false).",
    ] = False,
    autosave: Annotated[
        bool, "Save automatically while idle (default true; headless sessions)"
    ] = True,
    autosave_idle_sec: Annotated[
        float, "Idle seconds before an auto-save (default 60, min 5)"
    ] = 60.0,
) -> IdalibOpenResult:
    """Open a binary and warm it up; returns its session (reused if already open).

    Imperfect paths resolve in one call: exact path, unique known filename,
    best trailing-path match, or a bounded on-disk search; misses return
    suggestions, duplicates return candidates with hashes. Result carries the
    file's sha256/md5.
    """
    sup = _require_supervisor()
    notes: list[str] = []
    try:
        outcome = sup.paths.resolve_open_target(input_path, directory_hint=directory)
        status = outcome["status"]
        if status == "miss":
            suggestions = outcome.get("suggestions") or []
            searched = " (after an on-disk search)" if outcome.get("searched") else ""
            notes.append(
                f"Could not resolve '{input_path}'{searched}. Run list_pe_images on "
                "the containing folder, or idb_aliases() to list the alias registry."
            )
            err: IdalibOpenResult = {
                "success": False,
                "error": f"Could not resolve binary: {input_path}",
                "notes": notes,
            }
            if suggestions:
                notes.append(f"Did you mean: {', '.join(suggestions)}?")
                err["suggestions"] = suggestions
            return err
        if status == "ambiguous":
            cand_paths = outcome.get("candidates") or []
            candidates: list[IdalibOpenCandidate] = []
            for cp in cand_paths[:8]:
                info: IdalibOpenCandidate = {"path": cp, "filename": Path(cp).name}
                try:
                    info["sha256"], info["md5"] = _paths.hash_file_verify(Path(cp))
                except OSError as he:
                    info["error"] = f"{type(he).__name__}: {he}"
                candidates.append(info)
            notes.append(outcome["how"])
            return {
                "success": False,
                "error": (
                    f"Ambiguous: {len(cand_paths)} files match '{input_path}'. "
                    "Re-call idb_open with more path components to pick one."
                ),
                "candidates": candidates,
                "notes": notes,
            }

        resolved = outcome["path"]
        if os.path.normcase(resolved) != os.path.normcase(input_path):
            notes.append(f"Resolved '{input_path}' -> '{resolved}' ({outcome['how']}).")

        _handle_stale_components(sup, resolved, keep_stale_components, notes)

        session = sup.open_session(
            resolved,
            mode=mode,
            run_auto_analysis=run_auto_analysis,
            build_caches=build_caches,
            init_hexrays=init_hexrays,
            idle_ttl_sec=idle_ttl_sec,
            session_id=preferred_session_id or None,
        )
        result: IdalibOpenResult = {
            "success": True,
            "session": session.to_dict(),
            "warmup": session.last_warmup,
            "message": f"Binary opened: {session.filename} ({session.session_id})",
        }
        try:
            result["sha256"], result["md5"] = _paths.hash_file_verify(Path(resolved))
        except OSError:
            pass
        if session.backend == "worker":
            try:
                result["autosave"] = sup.call_worker_tool(
                    session,
                    "idb_autosave",
                    {"enabled": autosave, "idle_sec": autosave_idle_sec},
                )
            except Exception as e:
                notes.append(f"Could not configure idle auto-save: {e}")
        elif autosave:
            notes.append(
                "Idle auto-save applies to headless sessions only; this GUI session "
                "uses IDA's own autosave settings."
            )
        if bitness is not None or processor:
            fixup_args: dict[str, Any] = {}
            if bitness is not None:
                fixup_args["bitness"] = bitness
            if processor:
                fixup_args["processor"] = processor
            try:
                result["load_fixup"] = sup.call_worker_tool(session, "set_bitness", fixup_args)
            except Exception as e:
                notes.append(
                    f"Binary opened, but the load fixup failed: {e}. Call set_bitness "
                    "on this database to retry."
                )
        if notes:
            result["notes"] = notes
        return result
    except Exception as e:
        err = {"success": False, "error": str(e)}
        if notes:
            err["notes"] = notes
        return err


@mcp.tool
def idb_list() -> IdalibListResult:
    """List adopted sessions and discovered GUI/worker instances not yet opened through idb_open."""
    sup = _require_supervisor()
    try:
        sessions = sup.list_sessions()
        return {"sessions": sessions, "count": len(sessions)}
    except Exception as e:
        return {"error": f"Failed to list sessions: {e}"}


@mcp.tool
def idb_close(
    database: Annotated[str, "Session ID returned by idb_open (see idb_list)."],
    save: Annotated[bool, "Save the database before closing"] = True,
) -> IdalibCloseResult:
    """
    Close a session: optionally save it, unregister it from the supervisor, and
    terminate its owned worker (freeing a worker slot). Adopted GUI/worker instances
    are detached, not killed.
    """
    sup = _require_supervisor()
    try:
        return sup.close_session(database, save=save)
    except Exception as e:
        return {"error": str(e)}


@mcp.tool
def idb_aliases(
    filename: Annotated[
        Optional[str],
        "If set, return only paths matching this filename (or empty if unknown).",
    ] = None,
) -> dict:
    """Show filenames known to the supervisor alias registry.

    The registry is populated by ``list_pe_images`` and lets ``idb_open``
    resolve bare filenames to absolute paths — useful when an upstream safety
    layer strips absolute paths from tool arguments.
    """
    sup = _require_supervisor()
    with sup.paths._lock:
        if filename is not None:
            paths = sorted(sup.paths.alias_registry.get(filename, ()))
            return {"filename": filename, "paths": paths, "count": len(paths)}
        snapshot = {
            name: sorted(paths) for name, paths in sup.paths.alias_registry.items()
        }
    return {"count": len(snapshot), "aliases": snapshot}


@mcp.tool
def idb_search_roots() -> dict:
    """Show directories the supervisor pre-scanned at startup via --search-root.

    Each --search-root directory is walked once at supervisor startup and every
    PE image found is registered in the alias registry. This means a freshly
    connected client can call ``idb_aliases()`` immediately to see what
    binaries are available -- no need to know any server-side absolute path or
    call ``list_pe_images`` first.
    """
    sup = _require_supervisor()
    with sup.paths._lock:
        roots = list(sup.paths.search_roots)
    return {"roots": roots, "count": len(roots)}


def _loaded_index(sup: IdalibSupervisor) -> dict[str, str]:
    """Snapshot ``path_key -> session_id`` for live sessions, taken under the supervisor lock."""
    snapshot: list[tuple[str, str]] = []
    with sup._lock:
        for session in sup.sessions.values():
            if not session.input_path:
                continue
            try:
                if not session.is_alive():
                    continue
            except Exception:
                continue
            try:
                key = sup._path_key(session.input_path)
            except Exception:
                key = os.path.normcase(session.input_path)
            snapshot.append((key, session.session_id))
    return dict(snapshot)


@mcp.tool
def list_pe_images(
    directory: Annotated[str, "Absolute path to the directory to scan"],
    recursive: Annotated[bool, "Recurse into subdirectories"] = False,
    max_files: Annotated[int, "Max files to include before truncating (soft cap)"] = 2000,
    max_errors: Annotated[int, "Max per-file/dir errors to record before truncating"] = 100,
    time_budget_sec: Annotated[
        float, "Wall-clock budget for the scan; 0 disables. Truncates when exceeded."
    ] = 60.0,
    hash: Annotated[
        bool, "Compute SHA1/CRC32 per file. Disable for a fast discovery pass."
    ] = True,
    include_non_pe: Annotated[
        bool,
        "Also list non-PE files (LE/LX extender images, NE, plain MZ, ELF, "
        "Mach-O and headerless blobs). Each entry's `format` says which.",
    ] = False,
) -> ListPeImagesResult:
    """List PE images (EXE, DLL, SYS, OCX, ...) under a directory.

    Filters to files with a valid MZ + PE\\0\\0 header, so LE/LX extender images,
    16-bit NE binaries and headerless/raw blobs are invisible by default -- pass
    ``include_non_pe=True`` to list every file with its detected ``format`` (PE, NE,
    LE, LX, MZ, ELF, MACHO, RAW) instead. Each entry includes size, UTC
    mtime, machine/arch/bitness, and Characteristics flags (is_executable_image, is_dll,
    is_system). When ``hash=True`` (default) each entry also includes SHA1 and CRC32 over
    the full file contents; when ``hash=False`` sha1 and crc32 are returned as empty
    strings (the fields are always present so the published schema stays consistent),
    which is much faster on large trees. Entries already opened in this supervisor are
    flagged (loaded + session_id).

    The ``path`` field is relative to the queried ``directory`` (forward-slash
    separated) -- non-recursive scans return paths equal to the filename, recursive
    scans return ``subdir/file.exe`` style relatives. Absolute paths stay strictly
    server-internal: the alias registry built by this call uses absolute paths under
    the hood so callers can pass either ``path`` or ``filename`` to ``idb_open``.

    Intended for shared/supervisor mode so clients can pick a binary for idb_open and
    compare against on-disk copies. ``directory`` must be an absolute path. For recursive
    scans of very large trees: use ``hash=False`` for discovery, then call again with
    ``hash=True`` on a narrowed directory. Scans truncate when any of ``max_files``,
    ``max_errors``, or ``time_budget_sec`` is hit; the result reports ``limit_hit``.

    Fallback: if ``directory`` does not exist on the server but ``--search-root``
    was configured at startup, the supervisor scans the configured roots instead
    and tags each entry with its ``source_root``. This lets agents that don't
    know which paths the server has reachable -- e.g. a Linux-mounted view that
    differs from the Windows-side mount -- still get a useful response.
    """
    from datetime import timezone

    sup = _require_supervisor()
    result: ListPeImagesResult = {
        "directory": directory,
        "recursive": bool(recursive),
        "count": 0,
        "images": [],
    }

    dir_path = Path(directory)
    if not dir_path.is_absolute():
        result["error"] = "directory must be an absolute path"
        return result

    # Decide which directories to scan. Normal path: just the requested one.
    # Fallback path: the requested directory doesn't exist on the server, but
    # --search-root directories were configured -- scan those and tag entries
    # with source_root so the caller knows.
    notes: list[str] = []
    scan_targets: list[tuple[Path, str]] = []  # (scan_root, source_root_str or "")
    fallback = False
    searched_roots: list[str] = []

    if dir_path.exists():
        if not dir_path.is_dir():
            result["error"] = f"not a directory: {directory}"
            return result
        scan_targets.append((dir_path, ""))
    elif sup.paths.search_roots:
        fallback = True
        with sup.paths._lock:
            configured_roots = list(sup.paths.search_roots)
        for raw_root in configured_roots:
            root_path = Path(raw_root)
            if root_path.exists() and root_path.is_dir():
                scan_targets.append((root_path, raw_root))
                searched_roots.append(raw_root)
        if not scan_targets:
            result["error"] = (
                f"directory not found: {directory}; configured search roots are "
                f"all unreachable: {configured_roots}"
            )
            return result
        notes.append(
            f"Directory '{directory}' not found on server; falling back to "
            f"{len(searched_roots)} configured --search-root director"
            f"{'y' if len(searched_roots) == 1 else 'ies'}."
        )
    else:
        result["error"] = (
            f"directory not found: {directory}. No --search-root configured "
            f"so no fallback is available; call idb_search_roots() to see "
            f"what was configured."
        )
        return result

    loaded = _loaded_index(sup)

    # Each pending entry pairs the wire-format PeImageInfo (relative `path`) with the
    # absolute filesystem path used for internal cross-referencing and registry
    # population. Absolute paths never escape this function except inside `notes`
    # (intentional debug aid) and aggregated via record_aliases (server-internal).
    pending: list[tuple[PeImageInfo, str]] = []
    errors: list[PeImageError] = []
    truncated = False
    limit_hit: str | None = None
    deadline = time.monotonic() + time_budget_sec if time_budget_sec > 0 else None

    def _record_error(path: str, exc: BaseException) -> None:
        nonlocal truncated, limit_hit
        if len(errors) >= max_errors:
            if not truncated:
                truncated = True
                limit_hit = "max_errors"
            return
        errors.append({"path": path, "error": f"{type(exc).__name__}: {exc}"})

    # Count immediate subdirectories skipped by a non-recursive scan so we can
    # tell the caller what they'd reach with recursive=True (the mplayer case:
    # executables landed one level down in system/ and Programs/).
    skipped_subdirs = 0

    def _record_subdir(_path: str) -> None:
        nonlocal skipped_subdirs
        skipped_subdirs += 1

    on_subdir = None if recursive else _record_subdir

    for scan_root, source_root in scan_targets:
        if truncated:
            break
        for full_path, st in _paths._iter_candidate_files(
            scan_root, bool(recursive), _record_error, on_subdir=on_subdir
        ):
            if len(pending) >= max_files:
                truncated = True
                limit_hit = "max_files"
                break
            if deadline is not None and time.monotonic() >= deadline:
                truncated = True
                limit_hit = "time_budget"
                break

            try:
                with open(full_path, "rb") as fh:
                    if include_non_pe:
                        header = _paths._sniff_binary_header(fh, st.st_size)
                    else:
                        header = _paths._parse_pe_header(fh, st.st_size)
                        if header is not None:
                            header = {**header, "format": "PE"}
            except OSError as e:
                _record_error(str(full_path), e)
                continue
            if header is None:
                continue

            sha1 = ""
            crc32 = ""
            if hash:
                try:
                    sha1, crc32 = _paths._hash_file(full_path)
                except OSError as e:
                    _record_error(str(full_path), e)
                    continue

            abs_path = str(full_path)
            try:
                key = sup._path_key(abs_path)
            except Exception:
                key = os.path.normcase(abs_path)
            session_id = loaded.get(key)

            try:
                rel_path = full_path.relative_to(scan_root).as_posix()
            except ValueError:
                # Walker promised a file under scan_root; if relative_to ever
                # fails, fall back to the basename so we still emit something
                # non-absolute on the wire.
                rel_path = full_path.name

            mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()

            entry: PeImageInfo = {
                "path": rel_path,
                "filename": full_path.name,
                "size": int(st.st_size),
                "mtime": mtime,
                "format": header["format"],
                "sha1": sha1,
                "crc32": crc32,
                "machine": header["machine"],
                "arch": header["arch"],
                "bitness": header["bitness"],
                "characteristics": header["characteristics"],
                "is_executable_image": header["is_executable_image"],
                "is_dll": header["is_dll"],
                "is_system": header["is_system"],
                "loaded": session_id is not None,
                "session_id": session_id,
                "source_root": source_root,
            }
            pending.append((entry, abs_path))

    pending.sort(key=lambda pair: (pair[0].get("source_root", ""), pair[0]["path"].lower()))
    # Record (filename -> absolute path) so callers can later open these binaries
    # by bare filename (or by the relative `path` we just returned, which the
    # idb_open basename fallback handles). The registry keeps absolute paths
    # internally; only the wire response uses relative paths.
    sup.paths.record_aliases({entry["filename"]: abs_p for entry, abs_p in pending})
    images = [entry for entry, _ in pending]
    result["images"] = images
    result["count"] = len(images)
    if errors:
        result["errors"] = errors
    if truncated:
        result["truncated"] = True
        if limit_hit is not None:
            result["limit_hit"] = limit_hit
    if fallback:
        result["fallback_to_search_roots"] = True
        result["searched_roots"] = searched_roots
    if not recursive and skipped_subdirs and not truncated:
        notes.append(
            f"{skipped_subdirs} subdirector"
            f"{'y' if skipped_subdirs == 1 else 'ies'} not scanned; "
            f"pass recursive=True to descend into them."
        )
    if notes:
        result["notes"] = notes
    return result


@mcp.resource("ida://databases")
def databases_resource() -> dict:
    """List open idalib worker databases."""
    sup = _require_supervisor()
    databases = sup.list_sessions()
    return {"databases": databases, "count": len(databases)}


def _handle_tools_list(request_obj: dict[str, Any]) -> dict[str, Any]:
    sup = _require_supervisor()
    local_tools = mcp._mcp_tools_list().get("tools", [])
    worker_tools = sup.worker_tools()
    return _jsonrpc_result(request_obj.get("id"), {"tools": worker_tools + local_tools})


def _handle_tools_call(request_obj: dict[str, Any]) -> dict[str, Any] | None:
    sup = _require_supervisor()
    params = request_obj.get("params") or {}
    tool_name = params.get("name", "")
    request_id = request_obj.get("id")

    if tool_name in IDB_MANAGEMENT_TOOLS:
        return _original_dispatch(request_obj)

    arguments = copy.deepcopy(params.get("arguments") or {})
    database = arguments.pop(_DATABASE_ARG, None)
    if not isinstance(database, str) or not database:
        return _jsonrpc_result(
            request_id,
            _call_tool_result({"error": _DATABASE_REQUIRED_ERROR}, is_error=True),
        )
    try:
        session = sup.resolve_session(database)
    except Exception as e:
        return _jsonrpc_result(request_id, _call_tool_result({"error": str(e)}, is_error=True))

    forwarded = copy.deepcopy(request_obj)
    forwarded.setdefault("params", {})["arguments"] = arguments
    try:
        return sup._worker_rpc(
            session, forwarded, timeout=WORKER_CALL_TIMEOUT_SEC or None
        )
    except socket.timeout:
        return _jsonrpc_result(
            request_id,
            _call_tool_result(
                {
                    "error": (
                        f"Worker for session '{database}' did not respond within "
                        f"{WORKER_CALL_TIMEOUT_SEC:.0f}s; it is still busy with an "
                        f"earlier call. The session is kept open — retry later or "
                        f"raise IDA_MCP_WORKER_CALL_TIMEOUT."
                    ),
                    "busy": True,
                },
                is_error=True,
            ),
        )
    except Exception as e:
        return _jsonrpc_result(request_id, _call_tool_result({"error": str(e)}, is_error=True))


def _handle_resources_list(request_obj: dict[str, Any]) -> dict[str, Any]:
    sup = _require_supervisor()
    local = mcp._mcp_resources_list().get("resources", [])
    worker = sup.worker_resources("resources/list")
    return _jsonrpc_result(request_obj.get("id"), {"resources": local + worker})


def _handle_resource_templates_list(request_obj: dict[str, Any]) -> dict[str, Any]:
    sup = _require_supervisor()
    local = mcp._mcp_resource_templates_list().get("resourceTemplates", [])
    worker = sup.worker_resources("resources/templates/list")
    return _jsonrpc_result(request_obj.get("id"), {"resourceTemplates": local + worker})


def _handle_resources_read(request_obj: dict[str, Any]) -> dict[str, Any] | None:
    uri = (request_obj.get("params") or {}).get("uri", "")
    if uri == "ida://databases":
        return _original_dispatch(request_obj)
    return _jsonrpc_error(
        request_obj.get("id"),
        -32001,
        f"Resource '{uri}' is not routable from idalib-mcp. "
        "Use tools with an explicit database= argument instead.",
    )


def dispatch_supervisor(request: dict | str | bytes | bytearray) -> dict | None:
    if not isinstance(request, dict):
        try:
            request_obj = json.loads(request)
        except Exception:
            return _original_dispatch(request)
    else:
        request_obj = request

    method = request_obj.get("method", "")
    if method in {"initialize", "ping"} or method.startswith("notifications/"):
        return _original_dispatch(request)
    if method == "tools/list":
        return _handle_tools_list(request_obj)
    if method == "tools/call":
        return _handle_tools_call(request_obj)
    if method == "resources/list":
        return _handle_resources_list(request_obj)
    if method == "resources/templates/list":
        return _handle_resource_templates_list(request_obj)
    if method == "resources/read":
        return _handle_resources_read(request_obj)
    if method in {"prompts/list", "prompts/get"}:
        return _original_dispatch(request_obj)

    return _original_dispatch(request_obj)


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP supervisor for IDA Pro via idalib")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show debug messages")
    parser.add_argument("--stdio", action="store_true", help="Serve MCP over stdio instead of HTTP")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="HTTP host, default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=8745, help="HTTP port, default: 8745")
    parser.add_argument("--unsafe", action="store_true", help="Enable unsafe worker tools (DANGEROUS)")
    parser.add_argument(
        "--profile",
        type=Path,
        default=None,
        metavar="PATH",
        help="Restrict worker tools to names listed in a profile file.",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=_env_int("IDA_MCP_MAX_WORKERS", 4),
        help="Maximum simultaneous idalib worker databases (0 = unlimited, default: 4).",
    )
    parser.add_argument(
        "--search-root",
        action="append",
        default=[],
        metavar="DIR",
        help=(
            "Absolute directory to pre-scan at startup. Every PE image found is "
            "registered in the alias registry so clients can call idb_open(filename) "
            "without knowing the server-side absolute path. Repeatable."
        ),
    )
    parser.add_argument(
        "--search-root-recursive",
        action="store_true",
        help="Walk --search-root directories recursively. Off by default.",
    )
    parser.add_argument("input_path", type=Path, nargs="?", help="Optional binary to open on startup.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    worker_args: list[str] = []
    if args.verbose:
        worker_args.append("--verbose")
    if args.unsafe:
        worker_args.append("--unsafe")
    if args.profile is not None:
        worker_args.extend(["--profile", str(args.profile)])

    global supervisor
    supervisor = IdalibSupervisor(
        mcp,
        max_workers=args.max_workers,
        worker_args=worker_args,
    )
    mcp.registry.dispatch = dispatch_supervisor

    if args.search_root:
        summary = supervisor.paths.prepopulate_aliases(
            [str(r) for r in args.search_root],
            recursive=args.search_root_recursive,
        )
        for root, info in summary.items():
            if info.get("error"):
                logger.warning("--search-root %s skipped: %s", root, info["error"])
            else:
                logger.info("--search-root %s: registered %d PE image(s)", root, info["count"])

    if args.input_path is not None:
        try:
            supervisor.open_session(str(args.input_path))
        except Exception as e:
            raise SystemExit(f"Failed to open initial binary: {e}")

    def cleanup_and_exit(signum, frame):
        logger.info("Shutting down idalib supervisor...")
        if supervisor is not None:
            supervisor.shutdown()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    try:
        if args.stdio:
            mcp.stdio()
        else:
            # Threaded: a call to one busy worker must not block requests
            # aimed at a different, idle one.
            mcp.serve(host=args.host, port=args.port, background=False, threaded=True)
    finally:
        if supervisor is not None:
            supervisor.shutdown()


if __name__ == "__main__":
    main()
