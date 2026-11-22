"""idalib supervisor tests that do not require IDA/idalib."""

import sys
from pathlib import Path

import pytest

from ida_pro_mcp import idalib_supervisor as supmod


class _FakeProcess:
    pid = 12345
    returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


class _DeadProcess(_FakeProcess):
    returncode = 1


class _FakeSupervisor(supmod.IdalibSupervisor):
    def __init__(self):
        super().__init__(supmod.McpServer("test"), max_workers=4)
        self.forwarded: list[dict] = []
        self.opened: list[tuple[str, dict]] = []
        self.tool_calls: list[tuple[str, dict | None]] = []

    def _spawn_worker(self):
        return supmod.WorkerSession(
            session_id="__schema__",
            input_path="",
            filename="",
            host="127.0.0.1",
            port=1,
            process=_FakeProcess(),
        )

    def _worker_rpc(self, worker, payload, *, timeout=None):
        method = payload.get("method")
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "result": {
                    "tools": [
                        {
                            "name": "decompile",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"addr": {"type": "string"}},
                                "required": ["addr"],
                            },
                        },
                        {"name": "idb_open", "inputSchema": {"type": "object"}},
                    ]
                },
            }
        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"resources": []}}
        if method == "resources/templates/list":
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"resourceTemplates": []}}
        self.forwarded.append(payload)
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"ok": True}}

    def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
        self.tool_calls.append((name, arguments))
        if name == "idb_open":
            assert arguments is not None
            self.opened.append((name, arguments))
            warmup = None
            if arguments.get("build_caches") or arguments.get("init_hexrays"):
                warmup = {"ok": True, "steps": [], "health": {"status": "ok"}}
            return {
                "success": True,
                "session": {
                    "session_id": arguments["preferred_session_id"],
                    "input_path": arguments["input_path"],
                    "filename": Path(arguments["input_path"]).name,
                    "created_at": "now",
                    "last_accessed": "now",
                    "is_analyzing": False,
                    "metadata": {},
                },
                "warmup": warmup,
            }
        return {"ok": True, "error": None}

    def _session_is_reachable(self, session):
        return session.is_alive()

    def _probe_session_health(self, session, *, tcp_timeout=None, rpc_timeout=None):
        reachable = self._session_is_reachable(session)
        return {
            "backend": session.backend,
            "process_alive": session.is_alive(),
            "tcp_connect": reachable if session.backend == "worker" else None,
            "rpc_ping": reachable if session.backend == "worker" else None,
            "reachable": reachable,
            "state": "ok" if reachable else "dead",
            "failed_probe": None if reachable else "tcp_connect",
            "error": None if reachable else "unreachable",
        }


def _patch_discovery(*, instances, probe):
    old_discover = supmod._discovery.discover_instances
    old_probe = supmod._discovery.probe_instance
    supmod._discovery.discover_instances = lambda: instances
    supmod._discovery.probe_instance = lambda *_args, **_kwargs: probe

    def restore():
        supmod._discovery.discover_instances = old_discover
        supmod._discovery.probe_instance = old_probe

    return restore


def test_supervisor_import_does_not_import_ida_modules():
    assert "idapro" not in sys.modules
    assert "idaapi" not in sys.modules


def test_worker_rpc_default_has_no_socket_timeout(monkeypatch):
    class _FakeResponse:
        status = 200
        reason = "OK"

        def read(self):
            return b'{"jsonrpc":"2.0","result":{"ok":true},"id":1}'

    class _FakeConnection:
        instances = []

        def __init__(self, host, port, timeout=None):
            self.host = host
            self.port = port
            self.timeout = timeout
            type(self).instances.append(self)

        def request(self, method, path, body, headers):
            pass

        def getresponse(self):
            return _FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(supmod.http.client, "HTTPConnection", _FakeConnection)
    sup = supmod.IdalibSupervisor(supmod.McpServer("test"))
    worker = supmod.WorkerSession(
        session_id="worker",
        input_path="",
        filename="",
        host="127.0.0.1",
        port=12345,
        process=_FakeProcess(),
    )

    sup._worker_rpc(worker, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    sup._worker_rpc(worker, {"jsonrpc": "2.0", "id": 2, "method": "ping"}, timeout=2.0)

    assert _FakeConnection.instances[0].timeout is None
    assert _FakeConnection.instances[1].timeout == 2.0


def test_cleanup_partial_database_removes_only_new_parts(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    existing = Path(str(sample) + ".id0")
    existing.write_bytes(b"existing database state")
    packed = Path(str(sample) + ".i64")
    packed.write_bytes(b"packed database")

    preserved = supmod.IdalibSupervisor._existing_partial_database_parts(str(sample))
    new_id1 = Path(str(sample) + ".id1")
    new_id1.write_bytes(b"incomplete")
    new_nam = Path(str(sample) + ".nam")
    new_nam.write_bytes(b"incomplete")

    supmod.IdalibSupervisor._cleanup_partial_database(
        str(sample),
        preserve=preserved,
    )

    assert existing.read_bytes() == b"existing database state"
    assert not new_id1.exists()
    assert not new_nam.exists()
    assert packed.read_bytes() == b"packed database"


def test_open_session_cleans_new_parts_after_worker_failure(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    existing = Path(str(sample) + ".id0")
    existing.write_bytes(b"existing database state")
    packed = Path(str(sample) + ".i64")
    packed.write_bytes(b"packed database")

    class _FailingSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            assert arguments is not None
            Path(arguments["input_path"] + ".id1").write_bytes(b"incomplete")
            raise ConnectionResetError(10054, "worker reset")

    sup = _FailingSupervisor()
    with pytest.raises(ConnectionResetError):
        sup.open_session(
            str(sample),
            mode="force_headless",
            run_auto_analysis=False,
            build_caches=False,
            init_hexrays=False,
        )

    assert existing.read_bytes() == b"existing database state"
    assert not Path(str(sample) + ".id1").exists()
    assert packed.read_bytes() == b"packed database"


def test_failed_gui_fallback_cleans_new_parts_after_worker_failure(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    existing = Path(str(sample) + ".id0")
    existing.write_bytes(b"existing database state")

    class _FailingSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            assert arguments is not None
            Path(arguments["input_path"] + ".id1").write_bytes(b"incomplete")
            raise ConnectionResetError(10054, "worker reset")

    gui_session = supmod.WorkerSession(
        session_id="gui",
        input_path=str(sample),
        filename=sample.name,
        backend="gui",
        owned=False,
    )
    sup = _FailingSupervisor()
    with pytest.raises(ConnectionResetError):
        sup._reopen_gui_session_headless(gui_session)

    assert existing.read_bytes() == b"existing database state"
    assert not Path(str(sample) + ".id1").exists()


def test_worker_tools_inject_database_and_filter_management_tools():
    sup = _FakeSupervisor()
    tools = sup.worker_tools()
    names = [tool["name"] for tool in tools]
    assert names == ["decompile"]
    schema = tools[0]["inputSchema"]
    assert "database" in schema["properties"]
    assert "database" in schema.get("required", [])


def test_inject_database_arg_marks_required():
    sup = _FakeSupervisor()
    injected = sup._inject_database_arg(
        {
            "name": "decompile",
            "inputSchema": {
                "type": "object",
                "properties": {"addr": {"type": "string"}},
                "required": ["addr"],
            },
        }
    )
    schema = injected["inputSchema"]
    assert "database" in schema["properties"]
    assert "database" in schema["required"]


def test_inject_database_arg_is_idempotent_in_required_list():
    sup = _FakeSupervisor()
    injected = sup._inject_database_arg(
        {
            "name": "decompile",
            "inputSchema": {
                "type": "object",
                "properties": {"addr": {"type": "string"}},
                "required": ["addr", "database"],
            },
        }
    )
    required = injected["inputSchema"]["required"]
    assert required.count("database") == 1


def test_handle_tools_call_errors_when_database_missing():
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        result = supmod._handle_tools_call(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "decompile", "arguments": {"addr": "0x1000"}},
            }
        )
        assert result is not None
        assert result["result"]["isError"] is True
        text = result["result"]["content"][0]["text"]
        assert "database is required" in text
        assert not supmod.supervisor.forwarded
    finally:
        supmod.supervisor = old_supervisor


def test_handle_tools_call_errors_when_database_empty():
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        result = supmod._handle_tools_call(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "decompile",
                    "arguments": {"addr": "0x1000", "database": ""},
                },
            }
        )
        assert result is not None
        assert result["result"]["isError"] is True
        assert "database is required" in result["result"]["content"][0]["text"]
    finally:
        supmod.supervisor = old_supervisor


def test_open_session_rejects_unknown_mode(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    try:
        sup.open_session(str(sample), session_id="sample", mode="bogus")
    except ValueError as e:
        assert "Unknown mode" in str(e)
    else:
        raise AssertionError("expected ValueError for unknown mode")


def test_open_session_prefer_headless_skips_gui_discovery(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="sample", mode="prefer_headless")
        assert session.backend == "worker"
        assert sup.opened, "expected the worker to be invoked despite a running GUI"
    finally:
        restore()


def test_open_session_force_headless_ignores_running_gui(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="sample", mode="force_headless")
        assert session.backend == "worker"
    finally:
        restore()


def test_open_session_force_gui_launches_when_no_gui_found(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    restore = _patch_discovery(instances=[], probe=False)
    calls = []

    def fake_launch(file_path, **kwargs):
        calls.append(file_path)
        return {
            "success": True,
            "host": "127.0.0.1",
            "port": 31337,
            "pid": 4242,
            "binary": "sample.bin",
        }

    monkeypatch.setattr(supmod._discovery, "launch_gui_instance", fake_launch)
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="gui", mode="force_gui")
        assert session.backend == "gui"
        assert session.port == 31337
        assert calls == [str(sample.resolve())] or calls == [str(sample)]
    finally:
        restore()


def test_idb_list_includes_unadopted_gui_instances(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample")

    extra_idb = tmp_path / "other.bin.i64"
    extra_idb.write_bytes(b"idb")
    monkeypatch.setattr(
        supmod._discovery,
        "discover_instances",
        lambda: [
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 1234,
                "binary": "other.bin",
                "idb_path": str(extra_idb),
                "started_at": "now",
            }
        ],
    )
    monkeypatch.setattr(supmod._discovery, "probe_instance", lambda *_args, **_kwargs: True)

    listed = sup.list_sessions()
    by_id = {entry["session_id"]: entry for entry in listed}
    assert "sample" in by_id and by_id["sample"]["adopted"] is True
    unadopted = [entry for entry in listed if not entry["adopted"]]
    assert len(unadopted) == 1
    assert unadopted[0]["backend"] == "gui"
    assert unadopted[0]["input_path"] == str(extra_idb)
    assert unadopted[0]["pid"] == 1234


def test_idb_list_reports_unadopted_worker_instances_as_workers(tmp_path, monkeypatch):
    extra_idb = tmp_path / "worker.bin"
    extra_idb.write_bytes(b"idb")
    monkeypatch.setattr(
        supmod._discovery,
        "discover_instances",
        lambda: [
            {
                "host": "127.0.0.1",
                "port": 31338,
                "pid": 4321,
                "binary": "worker.bin",
                "idb_path": str(extra_idb),
                "started_at": "now",
                "backend": "worker",
            }
        ],
    )
    monkeypatch.setattr(supmod._discovery, "probe_instance", lambda *_args, **_kwargs: True)

    listed = _FakeSupervisor().list_sessions()

    assert len(listed) == 1
    assert listed[0]["backend"] == "worker"
    assert listed[0]["metadata"]["backend"] == "worker"
    assert listed[0]["worker_pid"] == 4321
    assert listed[0]["adopted"] is False


def test_prefer_headless_adopts_only_registered_worker_backend(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="sample", mode="prefer_headless")
        assert session.backend == "worker"
        assert session.owned is True
        assert sup.opened, "legacy GUI registration should not be adopted as a worker"
    finally:
        restore()


def test_idb_list_omits_unadopted_when_already_adopted(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    idb = tmp_path / "sample.bin.i64"
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 1234,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        sup.open_session(str(sample), session_id="gui", mode="prefer_gui")
        monkeypatch.setattr(supmod._discovery, "probe_instance", lambda *_args, **_kwargs: True)
        listed = sup.list_sessions()
        assert all(entry["adopted"] for entry in listed)
        assert len(listed) == 1
    finally:
        restore()


def test_open_session_forwards_warmup_flags_and_captures_result(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(
        str(sample),
        session_id="sample",
        run_auto_analysis=False,
        build_caches=True,
        init_hexrays=True,
    )
    args = sup.opened[0][1]
    assert args["build_caches"] is True
    assert args["init_hexrays"] is True
    assert args["run_auto_analysis"] is False
    assert session.last_warmup is not None
    assert session.last_warmup["ok"] is True


def test_open_session_forwards_idle_ttl_sec(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample", idle_ttl_sec=1800)
    args = sup.opened[0][1]
    assert args["idle_ttl_sec"] == 1800


def test_open_session_defaults_idle_ttl_sec_to_server_default(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample")
    assert sup.opened[0][1]["idle_ttl_sec"] == supmod.WORKER_IDLE_TTL_SEC
    assert supmod.WORKER_IDLE_TTL_SEC >= 3600  # agents go quiet for long stretches


def test_open_session_server_default_is_configurable(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    monkeypatch.setattr(supmod, "WORKER_IDLE_TTL_SEC", 0.0)
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample")
    assert sup.opened[0][1]["idle_ttl_sec"] == 0.0


def test_open_session_skips_warmup_when_flags_disabled(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(
        str(sample),
        session_id="sample",
        build_caches=False,
        init_hexrays=False,
    )
    args = sup.opened[0][1]
    assert args["build_caches"] is False
    assert args["init_hexrays"] is False
    assert session.last_warmup is None


def test_resolve_session_requires_database():
    sup = _FakeSupervisor()
    for value in (None, ""):
        try:
            sup.resolve_session(value)
        except RuntimeError as e:
            assert "database is required" in str(e)
        else:
            raise AssertionError(f"expected RuntimeError for database={value!r}")


def test_tool_error_result_omits_structured_content():
    result = supmod._call_tool_result({"error": "no database"}, is_error=True)
    assert result["isError"] is True
    assert "structuredContent" not in result


def test_open_session_reuses_schema_worker(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.worker_tools()  # creates the idle/schema worker
    session = sup.open_session(str(sample), session_id="sample")
    assert session.session_id == "sample"
    assert sup.opened[0][1]["preferred_session_id"] == "sample"


def test_resolve_session_only_accepts_session_id(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample")

    assert sup.resolve_session("sample").session_id == "sample"

    for selector in ("sample.bin", str(sample), str(sample.resolve())):
        try:
            sup.resolve_session(selector)
        except RuntimeError as e:
            assert "not found" in str(e)
        else:
            raise AssertionError(f"expected RuntimeError for selector={selector!r}")


def test_open_session_uses_matching_gui_instance(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="gui", mode="prefer_gui")
        assert session.backend == "gui"
        assert session.host == "127.0.0.1"
        assert session.port == 31337
        assert session.pid == 999
        assert sup.resolve_session("gui").session_id == "gui"
        assert sup.opened == []
    finally:
        restore()


def test_open_session_removes_stale_existing_mapping(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _FakeSupervisor()
        stale = supmod.WorkerSession(
            session_id="stale",
            input_path=str(sample.resolve()),
            filename="sample.bin",
            process=_DeadProcess(),
        )
        with sup._lock:
            sup._register_session_locked(stale, str(sample.resolve()))
        session = sup.open_session(str(sample), session_id="new")
        assert session.session_id == "new"
        assert "stale" not in sup.sessions
    finally:
        restore()


def test_open_session_ignores_dead_workers_for_max_worker_limit(tmp_path):
    stale_path = tmp_path / "stale.bin"
    new_path = tmp_path / "new.bin"
    stale_path.write_bytes(b"stale")
    new_path.write_bytes(b"new")
    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _FakeSupervisor()
        sup.max_workers = 1
        stale = supmod.WorkerSession(
            session_id="stale",
            input_path=str(stale_path.resolve()),
            filename="stale.bin",
            process=_DeadProcess(),
        )
        with sup._lock:
            sup._register_session_locked(stale, str(stale_path.resolve()))

        session = sup.open_session(str(new_path), session_id="new")

        assert session.session_id == "new"
        assert "stale" not in sup.sessions
    finally:
        restore()


def test_resolve_session_removes_unreachable_worker(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(str(sample), session_id="sample")
    unreachable = {session.session_id}

    def fake_reachable(candidate):
        if candidate.session_id in unreachable:
            return False
        return candidate.is_alive()

    sup._session_is_reachable = fake_reachable

    try:
        sup.resolve_session("sample")
    except RuntimeError as e:
        assert "not reachable" in str(e)
    else:
        raise AssertionError("expected RuntimeError")

    assert "sample" not in sup.sessions
    assert session.process.returncode == 0


def test_open_session_prunes_unreachable_existing_mapping(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _FakeSupervisor()
        stale = supmod.WorkerSession(
            session_id="stale",
            input_path=str(sample.resolve()),
            filename="sample.bin",
            process=_FakeProcess(),
        )
        with sup._lock:
            sup._register_session_locked(stale, str(sample.resolve()))

        sup._session_is_reachable = lambda session: session.session_id != "stale" and session.is_alive()

        session = sup.open_session(str(sample), session_id="new")

        assert session.session_id == "new"
        assert "stale" not in sup.sessions
    finally:
        restore()


def test_probe_session_health_reports_tcp_connect_failure(monkeypatch):
    sup = supmod.IdalibSupervisor(supmod.McpServer("test"))
    worker = supmod.WorkerSession(
        session_id="worker",
        input_path="sample.bin",
        filename="sample.bin",
        host="127.0.0.1",
        port=12345,
        process=_FakeProcess(),
    )

    def fail_connect(*_args, **_kwargs):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(supmod.socket, "create_connection", fail_connect)

    health = sup._probe_session_health(worker)

    assert health["reachable"] is False
    assert health["tcp_connect"] is False
    assert health["rpc_ping"] is None
    assert health["failed_probe"] == "tcp_connect"
    assert "refused" in health["error"]


def test_probe_session_health_reports_rpc_ping_failure(monkeypatch):
    sup = supmod.IdalibSupervisor(supmod.McpServer("test"))
    worker = supmod.WorkerSession(
        session_id="worker",
        input_path="sample.bin",
        filename="sample.bin",
        host="127.0.0.1",
        port=12345,
        process=_FakeProcess(),
    )

    class _FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(supmod.socket, "create_connection", lambda *_args, **_kwargs: _FakeSocket())
    sup._worker_rpc = lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("rpc timeout"))

    health = sup._probe_session_health(worker)

    assert health["reachable"] is False
    assert health["tcp_connect"] is True
    assert health["rpc_ping"] is False
    assert health["failed_probe"] == "rpc_ping"
    assert "rpc timeout" in health["error"]


def _silent_worker_supervisor(monkeypatch, *, process):
    """Supervisor whose worker accepts TCP but never answers ping."""
    sup = supmod.IdalibSupervisor(supmod.McpServer("test"))
    worker = supmod.WorkerSession(
        session_id="worker",
        input_path="sample.bin",
        filename="sample.bin",
        host="127.0.0.1",
        port=12345,
        process=process,
    )

    class _FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(
        supmod.socket, "create_connection", lambda *_a, **_k: _FakeSocket()
    )
    sup._worker_rpc = lambda *_a, **_k: (_ for _ in ()).throw(TimeoutError("busy"))
    monkeypatch.setattr(supmod, "WORKER_HEALTH_RETRIES", 1)
    return sup, worker


def test_probe_reports_live_but_silent_worker_as_busy(monkeypatch):
    sup, worker = _silent_worker_supervisor(monkeypatch, process=_FakeProcess())

    health = sup._probe_session_health(worker)

    assert health["state"] == "busy"
    assert health["reachable"] is False


def test_probe_reports_exited_worker_as_dead(monkeypatch):
    sup, worker = _silent_worker_supervisor(monkeypatch, process=_DeadProcess())

    health = sup._probe_session_health(worker)

    assert health["state"] == "dead"
    assert health["failed_probe"] == "process"


def test_resolve_session_keeps_busy_worker(monkeypatch):
    process = _FakeProcess()
    sup, worker = _silent_worker_supervisor(monkeypatch, process=process)
    with sup._lock:
        sup._register_session_locked(worker, worker.input_path)

    resolved = sup.resolve_session("worker")

    assert resolved is worker
    assert "worker" in sup.sessions
    assert process.returncode is None
    assert worker.unresponsive_since is not None


def test_resolve_session_does_not_retry_probe_on_busy_worker(monkeypatch):
    """Busy calls are forwarded, so extra probing is pure added latency."""
    sup, worker = _silent_worker_supervisor(monkeypatch, process=_FakeProcess())
    with sup._lock:
        sup._register_session_locked(worker, worker.input_path)
    monkeypatch.setattr(supmod, "WORKER_HEALTH_RETRIES", 5)
    probes = []
    original = sup._probe_session_health
    sup._probe_session_health = lambda *a, **kw: (
        probes.append(kw), original(*a, **kw)
    )[1]

    sup.resolve_session("worker")

    assert len(probes) == 1
    assert probes[0]["rpc_timeout"] == supmod.WORKER_QUICK_RPC_TIMEOUT_SEC


def test_resolve_session_reaps_worker_wedged_past_grace(monkeypatch):
    process = _FakeProcess()
    sup, worker = _silent_worker_supervisor(monkeypatch, process=process)
    with sup._lock:
        sup._register_session_locked(worker, worker.input_path)
    monkeypatch.setattr(supmod, "WORKER_WEDGED_GRACE_SEC", 60.0)
    worker.unresponsive_since = supmod.time.monotonic() - 120.0

    try:
        sup.resolve_session("worker")
    except RuntimeError as e:
        assert "not reachable" in str(e)
    else:
        raise AssertionError("expected RuntimeError")

    assert "worker" not in sup.sessions
    assert process.returncode == 0


def test_zero_wedged_grace_never_reaps_live_worker(monkeypatch):
    process = _FakeProcess()
    sup, worker = _silent_worker_supervisor(monkeypatch, process=process)
    with sup._lock:
        sup._register_session_locked(worker, worker.input_path)
    monkeypatch.setattr(supmod, "WORKER_WEDGED_GRACE_SEC", 0.0)
    worker.unresponsive_since = supmod.time.monotonic() - 10_000.0

    assert sup.resolve_session("worker") is worker
    assert process.returncode is None


def test_list_sessions_marks_busy_worker_active(monkeypatch):
    sup, worker = _silent_worker_supervisor(monkeypatch, process=_FakeProcess())
    with sup._lock:
        sup._register_session_locked(worker, worker.input_path)
    monkeypatch.setattr(supmod._discovery, "discover_instances", lambda: [])

    entry = sup.list_sessions()[0]

    assert entry["is_active"] is True
    assert entry["busy"] is True


def test_handle_tools_call_reports_busy_on_worker_timeout(monkeypatch, tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample")

    def timeout_rpc(*_a, **_k):
        raise supmod.socket.timeout("timed out")

    sup._worker_rpc = timeout_rpc
    old_supervisor = supmod.supervisor
    supmod.supervisor = sup
    try:
        result = supmod._handle_tools_call(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "decompile",
                    "arguments": {"addr": "0x1000", "database": "sample"},
                },
            }
        )
    finally:
        supmod.supervisor = old_supervisor

    assert result is not None
    assert result["result"]["isError"] is True
    assert "still busy" in result["result"]["content"][0]["text"]
    assert "sample" in sup.sessions


def test_list_sessions_reports_is_active_from_health_probe(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"1")
    second.write_bytes(b"2")
    sup = _FakeSupervisor()
    sup.open_session(str(first), session_id="first")
    sup.open_session(str(second), session_id="second")

    sup._session_is_reachable = lambda session: session.session_id == "first"
    supmod._discovery.discover_instances = lambda: []

    listed = {s["session_id"]: s["is_active"] for s in sup.list_sessions()}
    assert listed == {"first": True, "second": False}


def test_close_session_saves_and_terminates_owned_worker(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(str(sample), session_id="sample")

    result = sup.close_session("sample", save=True)

    assert result["success"] is True
    assert result["saved"] is True
    assert result["owned"] is True
    assert ("idb_save", None) in sup.tool_calls
    assert "sample" not in sup.sessions
    assert sup.path_to_session == {}
    assert session.process.returncode == 0


def test_close_session_without_save_skips_idb_save(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(str(sample), session_id="sample")

    result = sup.close_session("sample", save=False)

    assert result["saved"] is None
    assert all(name != "idb_save" for name, _ in sup.tool_calls)
    assert "sample" not in sup.sessions
    assert session.process.returncode == 0


def test_close_session_unknown_session_raises():
    sup = _FakeSupervisor()
    try:
        sup.close_session("nope")
    except RuntimeError as e:
        assert "not found" in str(e)
    else:
        raise AssertionError("expected RuntimeError for unknown session")


def test_close_session_requires_database():
    sup = _FakeSupervisor()
    try:
        sup.close_session("")
    except RuntimeError as e:
        assert "database is required" in str(e)
    else:
        raise AssertionError("expected RuntimeError for empty database")


def test_close_session_detaches_adopted_worker_without_killing(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    adopted = supmod.WorkerSession(
        session_id="adopted",
        input_path=str(sample.resolve()),
        filename="sample.bin",
        process=_FakeProcess(),
        owned=False,
    )
    with sup._lock:
        sup._register_session_locked(adopted, str(sample.resolve()))

    result = sup.close_session("adopted", save=False)

    assert result["owned"] is False
    assert "adopted" not in sup.sessions
    assert sup.path_to_session == {}
    assert adopted.process.returncode is None


def test_close_session_reports_save_failure_but_still_closes(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    class _SaveFailsSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            if name == "idb_save":
                self.tool_calls.append((name, arguments))
                return {"ok": False, "path": None, "error": "disk full"}
            return super().call_worker_tool(worker, name, arguments)

    sup = _SaveFailsSupervisor()
    session = sup.open_session(str(sample), session_id="sample")

    result = sup.close_session("sample", save=True)

    assert result["saved"] is False
    assert result["save_error"] == "disk full"
    assert "sample" not in sup.sessions
    assert session.process.returncode == 0


def test_close_session_frees_worker_slot(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"1")
    second.write_bytes(b"2")
    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _FakeSupervisor()
        sup.max_workers = 1
        sup.open_session(str(first), session_id="first")

        # A second open is blocked while the single slot is occupied.
        try:
            sup.open_session(str(second), session_id="second")
        except RuntimeError as e:
            assert "Maximum idalib worker count reached" in str(e)
        else:
            raise AssertionError("expected the worker limit to be reached")

        sup.close_session("first", save=False)

        reopened = sup.open_session(str(second), session_id="second")
        assert reopened.session_id == "second"
    finally:
        restore()


def test_close_session_skips_save_when_unreachable(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(str(sample), session_id="sample")
    sup._session_is_reachable = lambda candidate: False

    result = sup.close_session("sample", save=True)

    assert result["saved"] is None
    assert all(name != "idb_save" for name, _ in sup.tool_calls)
    assert "sample" not in sup.sessions
    assert session.process.returncode == 0


def test_idb_close_tool_returns_error_for_unknown_session():
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        result = supmod.idb_close("nope")
        assert "not found" in result["error"]
    finally:
        supmod.supervisor = old_supervisor


def test_idb_close_is_a_management_tool_symbol():
    assert "idb_close" in supmod.IDB_MANAGEMENT_TOOLS
    assert callable(supmod.idb_close)


def test_supervisor_uses_idb_prefixed_management_tools_only():
    """No legacy names should leak into IDB_MANAGEMENT_TOOLS or module symbols."""
    legacy = {
        "open_database",
        "idalib_close",
        "idalib_list",
        "idalib_save",
        "idalib_switch",
        "idalib_unbind",
        "idalib_current",
        "idalib_warmup",
        "idalib_health",
    }
    assert supmod.IDB_MANAGEMENT_TOOLS == {
        "idb_open",
        "idb_list",
        "idb_close",
        "idb_aliases",
        "idb_search_roots",
        "list_pe_images",
    }
    assert not any(name.startswith("idalib_") for name in supmod.IDB_MANAGEMENT_TOOLS)
    for name in legacy:
        assert not hasattr(supmod, name), f"{name} should have been deleted"
    for typename in ("IdalibWarmupResult", "IdalibHealthResult"):
        assert not hasattr(supmod, typename), f"{typename} should have been deleted"
    # --stdio-shared and its support code should be gone.
    for name in (
        "_stdio_proxy",
        "_open_stdio_initial_database",
        "_ensure_shared_http_supervisor",
        "_spawn_shared_http_supervisor",
        "_probe_http_supervisor",
        "_http_jsonrpc",
        "_stdio_shared_session_id",
    ):
        assert not hasattr(supmod, name), f"{name} should have been deleted"


def test_open_session_race_discards_losing_worker_for_existing_path(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    class _RaceSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idb_open":
                existing = supmod.WorkerSession(
                    session_id="winner",
                    input_path=str(sample.resolve()),
                    filename="sample.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(sample.resolve()))
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        session = sup.open_session(str(sample))
        assert session.session_id == "winner"
        assert set(sup.sessions) == {"winner"}
        assert sup.opened[0][1]["preferred_session_id"] != "winner"
    finally:
        restore()


def test_open_session_race_returns_existing_when_preferred_id_differs(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    class _RaceSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idb_open":
                existing = supmod.WorkerSession(
                    session_id="winner",
                    input_path=str(sample.resolve()),
                    filename="sample.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(sample.resolve()))
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        session = sup.open_session(str(sample), session_id="loser")
        assert session.session_id == "winner"
        assert set(sup.sessions) == {"winner"}
    finally:
        restore()


def test_open_session_returns_existing_session_when_path_already_open(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    first = sup.open_session(str(sample), session_id="alpha")
    again = sup.open_session(str(sample), session_id="beta")
    assert again is first
    assert again.session_id == "alpha"
    assert set(sup.sessions) == {"alpha"}


def test_open_session_race_rejects_duplicate_session_id_for_different_path(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"1")
    second.write_bytes(b"2")

    class _RaceSupervisor(_FakeSupervisor):
        def __init__(self):
            super().__init__()
            self.spawned = []

        def _spawn_worker(self):
            worker = super()._spawn_worker()
            self.spawned.append(worker)
            return worker

        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idb_open":
                existing = supmod.WorkerSession(
                    session_id=arguments["preferred_session_id"],
                    input_path=str(first.resolve()),
                    filename="first.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(first.resolve()))
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        try:
            sup.open_session(str(second), session_id="shared")
        except ValueError as e:
            assert "Session already exists: shared" in str(e)
        else:
            raise AssertionError("expected ValueError")

        assert set(sup.sessions) == {"shared"}
        assert sup.sessions["shared"].input_path == str(first.resolve())
        assert sup.path_to_session.get(sup._path_key(str(second.resolve()))) is None
        assert sup.spawned[0].process.returncode == 0
    finally:
        restore()


def test_closed_gui_session_reopens_headless(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="gui", mode="prefer_gui")
        assert session.backend == "gui"
        supmod._discovery.probe_instance = lambda *_args, **_kwargs: False
        reopened = sup.resolve_session("gui")
        assert reopened.backend == "worker"
        assert reopened.session_id == "gui"
        assert sup.opened[-1][1]["input_path"] == str(idb.resolve())
    finally:
        restore()


def test_closed_gui_session_falls_back_to_requested_binary_if_idb_is_stale(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="gui", mode="prefer_gui")
        assert session.backend == "gui"
        idb.unlink()
        supmod._discovery.probe_instance = lambda *_args, **_kwargs: False
        reopened = sup.resolve_session("gui")
        assert reopened.backend == "worker"
        assert reopened.session_id == "gui"
        assert sup.opened[-1][1]["input_path"] == str(sample.resolve())
    finally:
        restore()


def test_closed_gui_session_does_not_reappear_if_closed_during_headless_fallback(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")

    class _RaceSupervisor(_FakeSupervisor):
        def __init__(self):
            super().__init__()
            self.spawned = []

        def _spawn_worker(self):
            worker = super()._spawn_worker()
            self.spawned.append(worker)
            return worker

        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idb_open":
                # Simulate: the session disappears while the reopen worker
                # is doing the open. Drop it from the supervisor's registry
                # and tear down the spawning worker.
                sid = arguments["preferred_session_id"]
                with self._lock:
                    stale = self._unregister_session_locked(sid)
                if stale is not None:
                    self._terminate_worker(stale)
            return result

    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _RaceSupervisor()
        session = sup.open_session(str(sample), session_id="gui", mode="prefer_gui")
        assert session.backend == "gui"
        supmod._discovery.probe_instance = lambda *_args, **_kwargs: False

        try:
            sup.resolve_session("gui")
        except RuntimeError as e:
            assert "was closed or replaced" in str(e)
        else:
            raise AssertionError("expected RuntimeError")

        assert "gui" not in sup.sessions
        assert sup.spawned[-1].process.returncode == 0
    finally:
        restore()


def test_probe_reports_busy_adopted_worker_as_busy(monkeypatch):
    """No Popen handle, but a completed TCP handshake proves it is alive."""
    sup, worker = _silent_worker_supervisor(monkeypatch, process=None)
    worker.owned = False

    health = sup._probe_session_health(worker)

    assert health["tcp_connect"] is True
    assert health["state"] == "busy"


def test_probe_reports_adopted_worker_with_no_listener_as_dead(monkeypatch):
    sup, worker = _silent_worker_supervisor(monkeypatch, process=None)
    worker.owned = False
    monkeypatch.setattr(
        supmod.socket,
        "create_connection",
        lambda *_a, **_k: (_ for _ in ()).throw(ConnectionRefusedError("refused")),
    )

    health = sup._probe_session_health(worker)

    assert health["tcp_connect"] is False
    assert health["state"] == "dead"


def test_resolve_session_keeps_busy_adopted_worker(monkeypatch):
    sup, worker = _silent_worker_supervisor(monkeypatch, process=None)
    worker.owned = False
    with sup._lock:
        sup._register_session_locked(worker, worker.input_path)

    assert sup.resolve_session("worker") is worker
    assert "worker" in sup.sessions


def test_open_session_returns_winner_when_concurrent_open_fails(tmp_path):
    """The loser of a same-path race must get the winner, not a locked-DB error."""
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x00")
    resolved = str(binary.resolve())

    winner = supmod.WorkerSession(
        session_id="winner",
        input_path=resolved,
        filename=binary.name,
        host="127.0.0.1",
        port=12345,
        process=_FakeProcess(),
    )

    class _LosingSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            if name == "idb_open":
                # The winner registers while this open is in flight.
                with self._lock:
                    self._register_session_locked(winner, resolved)
                raise RuntimeError(f"Failed to open database: {resolved}")
            return super().call_worker_tool(worker, name, arguments, timeout=timeout)

    sup = _LosingSupervisor()
    cleaned: list = []
    sup._cleanup_partial_database = lambda *a, **k: cleaned.append(a)

    assert sup.open_session(resolved) is winner
    assert cleaned == [], "must not delete working files owned by the winner"


def test_open_session_still_raises_when_no_concurrent_winner(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x00")

    class _FailingOpen(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            if name == "idb_open":
                raise RuntimeError("Failed to open database")
            return super().call_worker_tool(worker, name, arguments, timeout=timeout)

    sup = _FailingOpen()
    with pytest.raises(RuntimeError, match="Failed to open database"):
        sup.open_session(str(binary.resolve()))


# ============================================================================
# Ported fork features: path resolution, aliases, search roots, list_pe_images
# ============================================================================


def _make_pe_blob(
    *,
    machine: int = 0x8664,
    characteristics: int = 0x0022,  # IMAGE_FILE_EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    opt_magic: int = 0x20B,
    body: bytes = b"PEDATA",
) -> bytes:
    """Build a minimal PE-shaped blob suitable for header parsing.

    Layout: 64-byte DOS header with e_lfanew=0x40, then ``PE\\0\\0``, then a
    20-byte IMAGE_FILE_HEADER with SizeOfOptionalHeader=2, then a 2-byte
    Optional Header Magic, then ``body`` to make the file non-trivial.
    """
    import struct

    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    file_header = struct.pack(
        "<HHIIIHH",
        machine,          # Machine
        0,                # NumberOfSections
        0,                # TimeDateStamp
        0,                # PointerToSymbolTable
        0,                # NumberOfSymbols
        2,                # SizeOfOptionalHeader
        characteristics,  # Characteristics
    )
    opt = struct.pack("<H", opt_magic)
    return bytes(dos) + b"PE\x00\x00" + file_header + opt + body


def test_list_pe_images_in_management_set():
    assert "list_pe_images" in supmod.IDB_MANAGEMENT_TOOLS


def test_list_pe_images_tools_list_visibility():
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        result = supmod._handle_tools_list({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = [t["name"] for t in result["result"]["tools"]]
        assert "list_pe_images" in names
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_routes_locally(tmp_path):
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        result = supmod._handle_tools_call(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "list_pe_images",
                    "arguments": {"directory": str(tmp_path)},
                },
            }
        )
        assert result is not None
        assert not supmod.supervisor.forwarded
        text = result["result"]["content"][0]["text"]
        import json as _json

        payload = _json.loads(text)
        assert payload["directory"] == str(tmp_path)
        assert payload["count"] == 0
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_requires_absolute_path(tmp_path):
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        result = supmod.list_pe_images("relative\\dir")
        assert "error" in result
        assert "absolute" in result["error"]
        assert result["images"] == []
        assert result["count"] == 0
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_nonexistent_directory(tmp_path):
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        missing = tmp_path / "missing"
        result = supmod.list_pe_images(str(missing))
        assert "error" in result
        assert "not found" in result["error"]
        assert result["images"] == []
        assert result["count"] == 0
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_omits_non_pe(tmp_path):
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        (tmp_path / "notes.txt").write_bytes(b"hello world")
        pe_blob = _make_pe_blob(machine=0x8664)
        (tmp_path / "hello.exe").write_bytes(pe_blob)

        # DLL with the DLL characteristics bit
        dll_blob = _make_pe_blob(machine=0x8664, characteristics=0x2022)
        (tmp_path / "lib.dll").write_bytes(dll_blob)

        result = supmod.list_pe_images(str(tmp_path))
        assert result["count"] == 2
        by_name = {img["filename"]: img for img in result["images"]}
        assert "notes.txt" not in by_name
        assert by_name["hello.exe"]["arch"] == "x64"
        assert by_name["hello.exe"]["bitness"] == 64
        assert by_name["hello.exe"]["is_executable_image"] is True
        assert by_name["hello.exe"]["is_dll"] is False
        assert by_name["lib.dll"]["is_dll"] is True
        assert by_name["lib.dll"]["is_executable_image"] is True
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_hashes(tmp_path):
    import hashlib
    import zlib

    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        pe_blob = _make_pe_blob(body=b"abc123" * 100)
        target = tmp_path / "sample.bin"
        target.write_bytes(pe_blob)

        result = supmod.list_pe_images(str(tmp_path))
        assert result["count"] == 1
        img = result["images"][0]
        assert img["sha1"] == hashlib.sha1(pe_blob).hexdigest()
        assert img["crc32"] == "0x%08x" % (zlib.crc32(pe_blob) & 0xFFFFFFFF)
        assert img["size"] == len(pe_blob)
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_loaded_session_marker(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        pe_one = tmp_path / "one.exe"
        pe_two = tmp_path / "two.exe"
        pe_one.write_bytes(_make_pe_blob(body=b"one"))
        pe_two.write_bytes(_make_pe_blob(body=b"two"))

        live_session = supmod.WorkerSession(
            session_id="sess-one",
            input_path=str(pe_one),
            filename=pe_one.name,
            host="127.0.0.1",
            port=4242,
            process=_FakeProcess(),
        )
        sup.sessions[live_session.session_id] = live_session
        sup.path_to_session[sup._path_key(str(pe_one))] = live_session.session_id

        result = supmod.list_pe_images(str(tmp_path))
        by_name = {img["filename"]: img for img in result["images"]}
        assert by_name["one.exe"]["loaded"] is True
        assert by_name["one.exe"]["session_id"] == "sess-one"
        assert by_name["two.exe"]["loaded"] is False
        assert by_name["two.exe"]["session_id"] is None
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_dead_sessions_are_not_marked_loaded(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        pe_path = tmp_path / "ghost.exe"
        pe_path.write_bytes(_make_pe_blob())
        dead_session = supmod.WorkerSession(
            session_id="dead",
            input_path=str(pe_path),
            filename=pe_path.name,
            host="127.0.0.1",
            port=4243,
            process=_DeadProcess(),
        )
        sup.sessions[dead_session.session_id] = dead_session

        result = supmod.list_pe_images(str(tmp_path))
        img = result["images"][0]
        assert img["loaded"] is False
        assert img["session_id"] is None
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_truncation(tmp_path):
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        for i in range(5):
            (tmp_path / f"bin{i}.exe").write_bytes(_make_pe_blob(body=b"x" * (i + 1)))
        result = supmod.list_pe_images(str(tmp_path), max_files=3)
        assert result["count"] == 3
        assert result.get("truncated") is True
        assert result.get("limit_hit") == "max_files"
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_recursive_dir_error(tmp_path, monkeypatch):
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        readable = tmp_path / "ok"
        readable.mkdir()
        (readable / "a.exe").write_bytes(_make_pe_blob())
        bad_dir_path = str(tmp_path / "denied")

        real_walk = supmod.os.walk

        def fake_walk(root, followlinks=False, onerror=None):
            # First yield real contents, then synthesize an onerror call for a bad subdir
            for triple in real_walk(root, followlinks=followlinks, onerror=onerror):
                yield triple
            if onerror is not None:
                err = OSError(13, "Permission denied")
                err.filename = bad_dir_path
                onerror(err)

        monkeypatch.setattr(supmod.os, "walk", fake_walk)

        result = supmod.list_pe_images(str(tmp_path), recursive=True)
        assert result["count"] == 1
        assert "errors" in result
        assert any(bad_dir_path in e["path"] for e in result["errors"])
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_arch_variants(tmp_path):
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        cases = [
            ("x86.exe",   0x014C, 0x10B, "x86",   32),
            ("x64.exe",   0x8664, 0x20B, "x64",   64),
            ("arm64.dll", 0xAA64, 0x20B, "arm64", 64),
            ("weird.bin", 0x9999, 0x20B, "unknown", 64),
        ]
        for name, machine, opt_magic, _arch, _bits in cases:
            (tmp_path / name).write_bytes(
                _make_pe_blob(machine=machine, opt_magic=opt_magic)
            )
        result = supmod.list_pe_images(str(tmp_path))
        by_name = {img["filename"]: img for img in result["images"]}
        for name, _machine, _magic, arch, bits in cases:
            assert by_name[name]["arch"] == arch
            assert by_name[name]["bitness"] == bits
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_path_is_relative_non_recursive(tmp_path):
    # Non-recursive: wire-format `path` must equal `filename`. Absolute server
    # paths (drive letters, leading slashes, the tmp_path prefix) must NEVER
    # appear in the response.
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        (tmp_path / "thing.exe").write_bytes(_make_pe_blob())
        result = supmod.list_pe_images(str(tmp_path))
        assert result["count"] == 1
        img = result["images"][0]
        assert img["path"] == "thing.exe"
        assert img["path"] == img["filename"]
        # No leaked absolute prefix anywhere
        assert str(tmp_path) not in img["path"]
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_path_is_posix_relative_recursive(tmp_path):
    # Recursive scan keeps locality info via forward-slash relative paths,
    # but still doesn't leak the absolute root prefix.
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        sub = tmp_path / "sub"
        sub.mkdir()
        nested = sub / "deeper"
        nested.mkdir()
        (tmp_path / "root.exe").write_bytes(_make_pe_blob(body=b"r"))
        (sub / "child.exe").write_bytes(_make_pe_blob(body=b"c"))
        (nested / "grand.exe").write_bytes(_make_pe_blob(body=b"g"))

        result = supmod.list_pe_images(str(tmp_path), recursive=True)
        assert result["count"] == 3
        paths = {img["path"] for img in result["images"]}
        assert paths == {"root.exe", "sub/child.exe", "sub/deeper/grand.exe"}
        for img in result["images"]:
            assert str(tmp_path) not in img["path"]
            # Forward slashes only -- no Windows backslashes leak into wire format
            assert "\\" not in img["path"]
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_registers_absolute_path_internally(tmp_path):
    # The wire response uses relative paths, but the alias registry must still
    # hold the absolute path -- otherwise idalib_open could not actually open
    # the file. This is the critical "leak nothing on the wire, keep absolute
    # paths internal" guarantee.
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        (tmp_path / "alpha.exe").write_bytes(_make_pe_blob(body=b"a"))
        result = supmod.list_pe_images(str(tmp_path))
        # Wire path is relative
        assert result["images"][0]["path"] == "alpha.exe"
        # But the registry has the absolute path
        registered = sup.paths.alias_registry["alpha.exe"]
        assert str(tmp_path / "alpha.exe") in registered
    finally:
        supmod.supervisor = old_supervisor


def test_idb_open_accepts_wire_path_from_list_pe_images(tmp_path):
    # End-to-end: take a `path` straight from a list_pe_images response and pass
    # it back to idalib_open. The basename fallback should resolve it via the
    # registry.
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        (tmp_path / "beta.exe").write_bytes(_make_pe_blob(body=b"b"))
        listing = supmod.list_pe_images(str(tmp_path))
        wire_path = listing["images"][0]["path"]
        assert wire_path == "beta.exe"  # sanity

        result = supmod.idb_open(input_path=wire_path)
        assert result.get("success") is True
        # open_session received the absolute path the registry resolved to
        assert sup.opened[0][1]["input_path"] == str(tmp_path / "beta.exe")
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_falls_back_to_search_roots(tmp_path):
    # Agent supplies a directory the server can't see; supervisor falls back
    # to its configured --search-root directory and returns those PE images
    # tagged with source_root so the agent knows what happened.
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        real_root = tmp_path / "real"
        real_root.mkdir()
        (real_root / "alpha.exe").write_bytes(_make_pe_blob(body=b"a"))
        (real_root / "beta.exe").write_bytes(_make_pe_blob(body=b"b"))
        sup.paths.prepopulate_aliases([str(real_root)])

        # Caller asks for a directory that doesn't exist on the server.
        bogus = str(tmp_path / "this_is_only_on_my_machine")
        result = supmod.list_pe_images(bogus)

        assert result["count"] == 2
        assert result.get("fallback_to_search_roots") is True
        assert result.get("searched_roots") == [str(real_root)]
        assert "notes" in result
        assert any("not found on server" in n for n in result["notes"])

        for img in result["images"]:
            assert img["source_root"] == str(real_root)
            # path stays relative to the source_root (no absolute leak)
            assert img["path"] in ("alpha.exe", "beta.exe")
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_no_fallback_when_no_search_roots(tmp_path):
    # Caller's directory missing AND no --search-root configured -> error
    # as before, with a hint pointing at idalib_search_roots so the operator
    # can confirm nothing was configured.
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        result = supmod.list_pe_images(str(tmp_path / "missing"))
        assert "error" in result
        assert "directory not found" in result["error"]
        assert "search-root" in result["error"].lower() or "search_root" in result["error"]
        assert "fallback_to_search_roots" not in result
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_no_fallback_when_directory_exists(tmp_path):
    # Happy path stays untouched -- when the requested directory IS reachable,
    # we never fall back even with search_roots configured. source_root is the
    # empty string in this mode.
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        other_root = tmp_path / "other"
        other_root.mkdir()
        (other_root / "other.exe").write_bytes(_make_pe_blob(body=b"o"))
        sup.paths.prepopulate_aliases([str(other_root)])

        target = tmp_path / "target"
        target.mkdir()
        (target / "hit.exe").write_bytes(_make_pe_blob(body=b"h"))

        result = supmod.list_pe_images(str(target))
        assert result["count"] == 1
        assert result["images"][0]["filename"] == "hit.exe"
        assert result["images"][0]["source_root"] == ""
        assert "fallback_to_search_roots" not in result
        assert "notes" not in result
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_fallback_aggregates_multiple_roots(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        root_a = tmp_path / "a"
        root_b = tmp_path / "b"
        root_a.mkdir()
        root_b.mkdir()
        (root_a / "from_a.exe").write_bytes(_make_pe_blob(body=b"a"))
        (root_b / "from_b.exe").write_bytes(_make_pe_blob(body=b"b"))
        sup.paths.prepopulate_aliases([str(root_a), str(root_b)])

        result = supmod.list_pe_images(str(tmp_path / "nope"))
        assert result.get("fallback_to_search_roots") is True
        assert set(result["searched_roots"]) == {str(root_a), str(root_b)}

        by_name = {img["filename"]: img for img in result["images"]}
        assert by_name["from_a.exe"]["source_root"] == str(root_a)
        assert by_name["from_b.exe"]["source_root"] == str(root_b)
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_fallback_skips_unreachable_roots(tmp_path):
    # If a search_root was recorded but is no longer reachable (e.g. unmounted
    # volume), the fallback skips it gracefully and uses the others.
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        real = tmp_path / "real"
        real.mkdir()
        (real / "x.exe").write_bytes(_make_pe_blob())
        # Manually populate search_roots with one good + one nonexistent.
        ghost = str(tmp_path / "this_was_unmounted")
        sup.paths.search_roots = [ghost, str(real)]

        result = supmod.list_pe_images(str(tmp_path / "missing"))
        assert result.get("fallback_to_search_roots") is True
        assert result["searched_roots"] == [str(real)]
        assert result["count"] == 1
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_fallback_errors_when_all_roots_unreachable(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        sup.paths.search_roots = [str(tmp_path / "gone"), str(tmp_path / "also_gone")]
        result = supmod.list_pe_images(str(tmp_path / "missing"))
        assert "error" in result
        assert "all unreachable" in result["error"]
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_fallback_honors_recursive(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        root = tmp_path / "root"
        root.mkdir()
        sub = root / "sub"
        sub.mkdir()
        (root / "top.exe").write_bytes(_make_pe_blob(body=b"t"))
        (sub / "deep.exe").write_bytes(_make_pe_blob(body=b"d"))
        sup.paths.search_roots = [str(root)]

        result = supmod.list_pe_images(str(tmp_path / "nope"), recursive=True)
        assert result.get("fallback_to_search_roots") is True
        by_name = {img["filename"]: img for img in result["images"]}
        assert "top.exe" in by_name
        assert "deep.exe" in by_name
        # Relative path in recursive mode preserves the subdirectory under the source_root
        assert by_name["deep.exe"]["path"] == "sub/deep.exe"
        assert by_name["top.exe"]["path"] == "top.exe"
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_fallback_registers_aliases_too(tmp_path):
    # End-to-end: agent's bogus directory triggers fallback, supervisor returns
    # PE images from the search_root, and the alias registry is populated so
    # the agent can immediately turn around and call idalib_open(filename).
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        real = tmp_path / "real"
        real.mkdir()
        sample = real / "thing.exe"
        sample.write_bytes(_make_pe_blob(body=b"x"))
        sup.paths.search_roots = [str(real)]

        # First call: bogus path, fallback fires, registry populated.
        listing = supmod.list_pe_images(str(tmp_path / "elsewhere"))
        assert listing.get("fallback_to_search_roots") is True
        assert "thing.exe" in sup.paths.alias_registry

        # Now an agent can open by bare filename.
        opened = supmod.idb_open(input_path="thing.exe")
        assert opened.get("success") is True
        assert sup.opened[0][1]["input_path"] == str(sample)
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_normal_path_has_empty_source_root(tmp_path):
    # Verify the new source_root field is always present (schema stability)
    # and is the empty string when no fallback happened.
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        (tmp_path / "x.exe").write_bytes(_make_pe_blob())
        result = supmod.list_pe_images(str(tmp_path))
        for img in result["images"]:
            assert "source_root" in img
            assert img["source_root"] == ""
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_skips_ida_artifacts(tmp_path):
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        (tmp_path / "sole_v1.05.exe").write_bytes(_make_pe_blob())
        # IDA artifacts that would otherwise either parse as non-PE (and be silently
        # dropped) or hit PermissionError on a locked database. They must not appear
        # in `images` and must not show up in `errors[]` either.
        for suffix in (".id0", ".id1", ".id2", ".nam", ".til", ".i64", ".idb"):
            (tmp_path / f"sole_v1.05.exe{suffix}").write_bytes(b"\x00" * 16)
        # And the uppercase variant — Windows is case-insensitive.
        (tmp_path / "OTHER.ID0").write_bytes(b"\x00" * 16)

        result = supmod.list_pe_images(str(tmp_path))
        names = {img["filename"] for img in result["images"]}
        assert names == {"sole_v1.05.exe"}
        assert "errors" not in result
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_hash_false_returns_empty_hash_fields(tmp_path):
    # sha1/crc32 stay in the schema (always present) but are empty strings when
    # hash=False, so the gateway's structured-content validator stays happy and
    # callers can branch on `if entry["sha1"]:` to detect the fast-discovery mode.
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        (tmp_path / "a.exe").write_bytes(_make_pe_blob(body=b"abc"))
        (tmp_path / "b.exe").write_bytes(_make_pe_blob(body=b"xyz"))
        result = supmod.list_pe_images(str(tmp_path), hash=False)
        assert result["count"] == 2
        for img in result["images"]:
            assert img["sha1"] == ""
            assert img["crc32"] == ""
            assert img["size"] > 0
            assert img["arch"] == "x64"
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_time_budget(tmp_path, monkeypatch):
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        for i in range(5):
            (tmp_path / f"bin{i}.exe").write_bytes(_make_pe_blob(body=bytes([i]) * 8))

        # Fake clock: each call advances by 1.0s. Budget=2.5s -> loop should
        # admit ~2 files then trip the deadline.
        ticks = {"t": 0.0}

        def fake_monotonic():
            ticks["t"] += 1.0
            return ticks["t"]

        monkeypatch.setattr(supmod.time, "monotonic", fake_monotonic)
        result = supmod.list_pe_images(str(tmp_path), time_budget_sec=2.5)
        assert result.get("truncated") is True
        assert result.get("limit_hit") == "time_budget"
        assert result["count"] < 5
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_time_budget_disabled(tmp_path, monkeypatch):
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        for i in range(3):
            (tmp_path / f"bin{i}.exe").write_bytes(_make_pe_blob(body=bytes([i])))

        # Even if the clock claims big jumps, time_budget_sec=0 disables the check.
        monkeypatch.setattr(supmod.time, "monotonic", lambda: 1e9)
        result = supmod.list_pe_images(str(tmp_path), time_budget_sec=0)
        assert result["count"] == 3
        assert "truncated" not in result
    finally:
        supmod.supervisor = old_supervisor


def test_list_pe_images_populates_alias_registry(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        (tmp_path / "alpha.exe").write_bytes(_make_pe_blob(body=b"a"))
        (tmp_path / "beta.exe").write_bytes(_make_pe_blob(body=b"b"))
        result = supmod.list_pe_images(str(tmp_path))
        assert result["count"] == 2
        assert "alpha.exe" in sup.paths.alias_registry
        assert "beta.exe" in sup.paths.alias_registry
        assert str(tmp_path / "alpha.exe") in sup.paths.alias_registry["alpha.exe"]
    finally:
        supmod.supervisor = old_supervisor


def test_resolve_alias_unique_match(tmp_path):
    sup = _FakeSupervisor()
    p = str(tmp_path / "only.exe")
    sup.paths.record_aliases({"only.exe": p})
    assert sup.paths.resolve_alias("only.exe") == p


def test_resolve_alias_missing_returns_none():
    sup = _FakeSupervisor()
    assert sup.paths.resolve_alias("never_seen.exe") is None


def test_resolve_alias_ambiguous_raises(tmp_path):
    sup = _FakeSupervisor()
    a = tmp_path / "dir1"
    b = tmp_path / "dir2"
    a.mkdir()
    b.mkdir()
    sup.paths.record_aliases({"shared.exe": str(a / "shared.exe")})
    sup.paths.record_aliases({"shared.exe": str(b / "shared.exe")})
    try:
        sup.paths.resolve_alias("shared.exe")
    except RuntimeError as e:
        assert "Ambiguous" in str(e)
        assert "directory=" in str(e)
    else:
        raise AssertionError("expected RuntimeError on ambiguous alias")


def test_resolve_alias_directory_hint_disambiguates(tmp_path):
    sup = _FakeSupervisor()
    a_dir = tmp_path / "dir1"
    b_dir = tmp_path / "dir2"
    a_dir.mkdir()
    b_dir.mkdir()
    pa = str(a_dir / "shared.exe")
    pb = str(b_dir / "shared.exe")
    sup.paths.record_aliases({"shared.exe": pa})
    sup.paths.record_aliases({"shared.exe": pb})
    assert sup.paths.resolve_alias("shared.exe", directory_hint=str(a_dir)) == pa
    assert sup.paths.resolve_alias("shared.exe", directory_hint=str(b_dir)) == pb


def test_resolve_alias_directory_hint_no_match_returns_none(tmp_path):
    sup = _FakeSupervisor()
    a_dir = tmp_path / "real"
    a_dir.mkdir()
    sup.paths.record_aliases({"x.exe": str(a_dir / "x.exe")})
    assert sup.paths.resolve_alias("x.exe", directory_hint=str(tmp_path / "wrong")) is None


def test_idb_open_resolves_bare_filename_via_registry(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        sample = tmp_path / "sole.exe"
        sample.write_bytes(b"x")  # any contents fine; _FakeSupervisor stubs IDA.
        sup.paths.record_aliases({"sole.exe": str(sample)})

        result = supmod.idb_open(input_path="sole.exe")
        assert result.get("success") is True
        # open_session was invoked with the resolved absolute path, not the bare name.
        assert sup.opened, "expected idalib_open to reach open_session"
        assert sup.opened[0][1]["input_path"] == str(sample)
    finally:
        supmod.supervisor = old_supervisor


def test_idb_open_ambiguous_alias_returns_error(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        d1 = tmp_path / "v1"
        d2 = tmp_path / "v2"
        d1.mkdir()
        d2.mkdir()
        sup.paths.record_aliases({"sole.exe": str(d1 / "sole.exe")})
        sup.paths.record_aliases({"sole.exe": str(d2 / "sole.exe")})
        result = supmod.idb_open(input_path="sole.exe")
        assert "error" in result
        assert "Ambiguous" in result["error"]
    finally:
        supmod.supervisor = old_supervisor


def test_idb_open_ambiguous_alias_directory_hint_resolves(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        d1 = tmp_path / "v1"
        d2 = tmp_path / "v2"
        d1.mkdir()
        d2.mkdir()
        sole_v1 = d1 / "sole.exe"
        sole_v2 = d2 / "sole.exe"
        sole_v1.write_bytes(b"x")
        sole_v2.write_bytes(b"x")
        sup.paths.record_aliases({"sole.exe": str(sole_v1)})
        sup.paths.record_aliases({"sole.exe": str(sole_v2)})

        result = supmod.idb_open(input_path="sole.exe", directory=str(d1))
        assert result.get("success") is True
        assert sup.opened[0][1]["input_path"] == str(sole_v1)
    finally:
        supmod.supervisor = old_supervisor


def test_idb_aliases_inspection_tool(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        p1 = str(tmp_path / "a.exe")
        p2 = str(tmp_path / "b.exe")
        sup.paths.record_aliases({"a.exe": p1, "b.exe": p2})

        # Full listing
        full = supmod.idb_aliases()
        assert full["count"] == 2
        assert full["aliases"]["a.exe"] == [p1]

        # Filtered lookup
        one = supmod.idb_aliases(filename="a.exe")
        assert one["paths"] == [p1]
        assert one["count"] == 1

        # Unknown filename
        miss = supmod.idb_aliases(filename="missing.exe")
        assert miss["paths"] == []
        assert miss["count"] == 0
    finally:
        supmod.supervisor = old_supervisor


def test_idb_aliases_in_management_set():
    assert "idb_aliases" in supmod.IDB_MANAGEMENT_TOOLS


def test_idb_open_falls_back_to_basename_when_absolute_path_missing(tmp_path):
    # An agent often guesses a plausible absolute layout for a file that actually
    # lives somewhere else. When that absolute path doesn't exist, the alias
    # registry should still match on basename so the open succeeds.
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        real_dir = tmp_path / "actual_location"
        real_dir.mkdir()
        real_file = real_dir / "thing.exe"
        real_file.write_bytes(b"x")
        sup.paths.record_aliases({"thing.exe": str(real_file)})

        guessed_path = str(tmp_path / "wrong" / "path" / "thing.exe")
        result = supmod.idb_open(input_path=guessed_path)

        assert result.get("success") is True, result
        assert sup.opened[0][1]["input_path"] == str(real_file)
        assert "notes" in result
        assert any("Resolved" in n and "unique filename" in n for n in result["notes"])
    finally:
        supmod.supervisor = old_supervisor


def test_idb_open_notes_when_absolute_missing_and_no_alias(tmp_path):
    # Path doesn't exist, alias registry doesn't know the basename either.
    # Should fail, but the error response should carry a note telling the agent
    # what to try next (list_pe_images on the parent folder).
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        guessed_path = str(tmp_path / "nowhere" / "missing.exe")
        result = supmod.idb_open(input_path=guessed_path)
        assert result.get("success") is False
        assert "error" in result
        assert "notes" in result
        assert any("list_pe_images" in n for n in result["notes"])
        assert any("missing.exe" in n for n in result["notes"])
    finally:
        supmod.supervisor = old_supervisor


def test_suggest_aliases_empty_registry_returns_empty():
    sup = _FakeSupervisor()
    assert sup.paths.suggest_aliases("anything.exe") == []


def test_suggest_aliases_close_match(tmp_path):
    sup = _FakeSupervisor()
    sup.paths.record_aliases({"sole_v1.05.exe": str(tmp_path / "sole_v1.05.exe")})
    sup.paths.record_aliases({"sole_v1.04.exe": str(tmp_path / "sole_v1.04.exe")})
    sup.paths.record_aliases({"unrelated.dll": str(tmp_path / "unrelated.dll")})

    suggestions = sup.paths.suggest_aliases("sole_v1.05_typo.exe")
    assert "sole_v1.05.exe" in suggestions
    assert "unrelated.dll" not in suggestions


def test_suggest_aliases_case_insensitive(tmp_path):
    sup = _FakeSupervisor()
    sup.paths.record_aliases({"sole_v1.05.exe": str(tmp_path / "sole_v1.05.exe")})
    # User typed uppercase / different casing
    suggestions = sup.paths.suggest_aliases("SOLE_V1.05.EXE")
    assert "sole_v1.05.exe" in suggestions


def test_suggest_aliases_substring_fallback(tmp_path):
    # User's literal example: SOLE_v_1.05_original.exe vs sole_v1.05.exe.
    # difflib ratio is borderline; the substring fallback must still surface it.
    sup = _FakeSupervisor()
    sup.paths.record_aliases({"sole_v1.05.exe": str(tmp_path / "sole_v1.05.exe")})
    sup.paths.record_aliases({"sole_v1.04.exe": str(tmp_path / "sole_v1.04.exe")})

    suggestions = sup.paths.suggest_aliases("SOLE_v_1.05_original.exe")
    # Both share the "sole_v1" prefix on lowercase; at least sole_v1.05.exe
    # must be suggested via either the difflib or substring pass.
    assert "sole_v1.05.exe" in suggestions


def test_suggest_aliases_respects_n_limit(tmp_path):
    sup = _FakeSupervisor()
    for i in range(10):
        name = f"foo_v{i}.exe"
        sup.paths.record_aliases({name: str(tmp_path / name)})
    suggestions = sup.paths.suggest_aliases("foo_v3.exe", n=2)
    assert len(suggestions) <= 2


def test_suggest_aliases_no_match_returns_empty(tmp_path):
    sup = _FakeSupervisor()
    sup.paths.record_aliases({"alpha.exe": str(tmp_path / "alpha.exe")})
    assert sup.paths.suggest_aliases("zzzzz_completely_different.dat") == []


def test_suggest_aliases_handles_empty_query():
    sup = _FakeSupervisor()
    sup.paths.record_aliases({"x.exe": "/tmp/x.exe"})
    assert sup.paths.suggest_aliases("") == []


def test_prepopulate_aliases_registers_pe_images(tmp_path):
    sup = _FakeSupervisor()
    (tmp_path / "a.exe").write_bytes(_make_pe_blob(body=b"a"))
    (tmp_path / "b.exe").write_bytes(_make_pe_blob(body=b"b"))
    (tmp_path / "notes.txt").write_bytes(b"not a PE")

    summary = sup.paths.prepopulate_aliases([str(tmp_path)])
    assert summary[str(tmp_path)]["count"] == 2
    assert summary[str(tmp_path)]["error"] is None
    assert "a.exe" in sup.paths.alias_registry
    assert "b.exe" in sup.paths.alias_registry
    assert str(tmp_path / "a.exe") in sup.paths.alias_registry["a.exe"]
    # search_roots is recorded for introspection regardless of outcome
    assert str(tmp_path) in sup.paths.search_roots


def test_prepopulate_aliases_recursive(tmp_path):
    sup = _FakeSupervisor()
    sub = tmp_path / "sub"
    sub.mkdir()
    (tmp_path / "top.exe").write_bytes(_make_pe_blob(body=b"t"))
    (sub / "deep.exe").write_bytes(_make_pe_blob(body=b"d"))

    # Default (non-recursive) only sees top.exe
    summary = sup.paths.prepopulate_aliases([str(tmp_path)], recursive=False)
    assert summary[str(tmp_path)]["count"] == 1
    assert "top.exe" in sup.paths.alias_registry
    assert "deep.exe" not in sup.paths.alias_registry

    # Recursive sees both
    sup2 = _FakeSupervisor()
    summary2 = sup2.paths.prepopulate_aliases([str(tmp_path)], recursive=True)
    assert summary2[str(tmp_path)]["count"] == 2
    assert "top.exe" in sup2.paths.alias_registry
    assert "deep.exe" in sup2.paths.alias_registry


def test_prepopulate_aliases_missing_root(tmp_path):
    sup = _FakeSupervisor()
    missing = str(tmp_path / "does_not_exist")
    summary = sup.paths.prepopulate_aliases([missing])
    assert summary[missing]["count"] == 0
    assert "not found" in summary[missing]["error"]
    # Recorded even on failure so the operator sees what was requested
    assert missing in sup.paths.search_roots


def test_prepopulate_aliases_relative_root_rejected(tmp_path):
    sup = _FakeSupervisor()
    summary = sup.paths.prepopulate_aliases(["relative/path"])
    assert summary["relative/path"]["count"] == 0
    assert "absolute" in summary["relative/path"]["error"]


def test_prepopulate_aliases_file_not_dir(tmp_path):
    sup = _FakeSupervisor()
    f = tmp_path / "im_a_file.exe"
    f.write_bytes(_make_pe_blob())
    summary = sup.paths.prepopulate_aliases([str(f)])
    assert summary[str(f)]["count"] == 0
    assert "not a directory" in summary[str(f)]["error"]


def test_prepopulate_aliases_one_bad_root_does_not_abort_others(tmp_path):
    sup = _FakeSupervisor()
    good = tmp_path / "good"
    good.mkdir()
    (good / "x.exe").write_bytes(_make_pe_blob())
    bad = str(tmp_path / "bad" / "missing")

    summary = sup.paths.prepopulate_aliases([bad, str(good)])
    assert summary[bad]["error"] is not None
    assert summary[str(good)]["count"] == 1
    assert "x.exe" in sup.paths.alias_registry


def test_prepopulate_aliases_dedupes_repeat_call(tmp_path):
    sup = _FakeSupervisor()
    (tmp_path / "x.exe").write_bytes(_make_pe_blob())
    sup.paths.prepopulate_aliases([str(tmp_path)])
    sup.paths.prepopulate_aliases([str(tmp_path)])
    # alias_registry uses a set so the second call is idempotent
    assert len(sup.paths.alias_registry["x.exe"]) == 1
    # search_roots also dedupes
    assert sup.paths.search_roots.count(str(tmp_path)) == 1


def test_idb_search_roots_in_management_set():
    assert "idb_search_roots" in supmod.IDB_MANAGEMENT_TOOLS


def test_idb_search_roots_returns_empty_when_unset():
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        result = supmod.idb_search_roots()
        assert result["roots"] == []
        assert result["count"] == 0
    finally:
        supmod.supervisor = old_supervisor


def test_idb_search_roots_returns_prepopulated(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        (tmp_path / "x.exe").write_bytes(_make_pe_blob())
        sup.paths.prepopulate_aliases([str(tmp_path)])
        result = supmod.idb_search_roots()
        assert result["count"] == 1
        assert result["roots"] == [str(tmp_path)]
    finally:
        supmod.supervisor = old_supervisor


def test_idb_open_emits_did_you_mean_for_absolute_miss(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        sup.paths.record_aliases({"sole_v1.05.exe": str(real_dir / "sole_v1.05.exe")})
        # Reproduces the literal failure: agent supplies absolute path with
        # a casing/format mismatch on the filename.
        bad = str(tmp_path / "fake" / "SOLE_v_1.05_original.exe")
        result = supmod.idb_open(input_path=bad)
        assert result.get("success") is False
        assert "notes" in result
        joined = " ".join(result["notes"])
        assert "Did you mean" in joined
        assert "sole_v1.05.exe" in joined
    finally:
        supmod.supervisor = old_supervisor


def test_idb_open_emits_did_you_mean_for_bare_filename_miss(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        sup.paths.record_aliases({"sole_v1.05.exe": str(tmp_path / "sole_v1.05.exe")})
        result = supmod.idb_open(input_path="sole_v1.05_TYPO.exe")
        assert result.get("success") is False
        assert "notes" in result
        joined = " ".join(result["notes"])
        assert "alias registry" in joined
        assert "idalib_aliases" in joined or "list_pe_images" in joined
        assert "Did you mean" in joined
        assert "sole_v1.05.exe" in joined
    finally:
        supmod.supervisor = old_supervisor


def test_idb_open_no_suggestion_when_registry_empty(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        # Empty registry -- no suggestions to make.
        result = supmod.idb_open(input_path="anything.exe")
        assert result.get("success") is False
        # The breadcrumb about idalib_aliases / list_pe_images should still
        # appear, but no "Did you mean" line since there's nothing to suggest.
        joined = " ".join(result.get("notes", []))
        assert "Did you mean" not in joined
    finally:
        supmod.supervisor = old_supervisor


def test_cli_accepts_search_root_repeatable(monkeypatch, tmp_path):
    # Exercise just the argparse layer: assert the parsed namespace has the
    # repeated --search-root values and the recursive flag wired through.
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--search-root", action="append", default=[])
    parser.add_argument("--search-root-recursive", action="store_true")
    args = parser.parse_args([
        "--search-root", str(tmp_path / "one"),
        "--search-root", str(tmp_path / "two"),
        "--search-root-recursive",
    ])
    assert args.search_root == [str(tmp_path / "one"), str(tmp_path / "two")]
    assert args.search_root_recursive is True


def test_search_root_not_forwarded_to_worker_args(monkeypatch, tmp_path):
    # Regression: worker subprocesses don't accept --search-root and exit with
    # code 2 if they receive it, which broke every worker spawn the first time
    # the flag shipped. Verify the supervisor's main() never injects
    # --search-root / --search-root-recursive into the worker_args sent down
    # to idalib_server worker subprocesses.
    captured: dict = {}

    class _FakeSup(supmod.IdalibSupervisor):
        def __init__(self, mcp, *, max_workers=4, worker_args=None):
            super().__init__(
                mcp,
                max_workers=max_workers,
                worker_args=worker_args,
            )
            captured["worker_args"] = list(worker_args or [])

        def shutdown(self):
            pass

    monkeypatch.setattr(supmod, "IdalibSupervisor", _FakeSup)

    # Prevent main() from actually serving / installing signal handlers.
    class _StopServe(Exception):
        pass

    def _no_serve(*args, **kwargs):
        raise _StopServe()

    monkeypatch.setattr(supmod.mcp, "serve", _no_serve)
    monkeypatch.setattr(supmod.signal, "signal", lambda *a, **k: None)

    monkeypatch.setattr(supmod.sys, "argv", [
        "idalib-mcp",
        "--host", "127.0.0.1",
        "--port", "0",
        "--search-root", str(tmp_path),
        "--search-root-recursive",
    ])

    try:
        supmod.main()
    except _StopServe:
        pass

    assert "--search-root" not in captured["worker_args"]
    assert "--search-root-recursive" not in captured["worker_args"]
    # Sanity: the supervisor itself did record + scan the root.
    assert str(tmp_path) in supmod.supervisor.paths.search_roots


def _make_lx_blob(sig: bytes = b"LX") -> bytes:
    """MZ stub whose e_lfanew points at an LE/LX signature (DOS extender image)."""
    import struct

    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    return bytes(dos) + sig + b"\x00" * 32


def test_list_pe_images_include_non_pe_surfaces_lx_and_raw(tmp_path):
    """include_non_pe=True lists the image classes the PE filter hides."""
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        (tmp_path / "hello.exe").write_bytes(_make_pe_blob(machine=0x14C, opt_magic=0x10B))
        (tmp_path / "wpp386.exe").write_bytes(_make_lx_blob(b"LX"))
        (tmp_path / "dos4gw.exe").write_bytes(_make_lx_blob(b"LE"))
        (tmp_path / "payload.bin").write_bytes(bytes((0xEB, 0xFE)) + bytes(64))

        # Default: PE only, and every entry says so.
        default = supmod.list_pe_images(str(tmp_path))
        assert [img["filename"] for img in default["images"]] == ["hello.exe"]
        assert default["images"][0]["format"] == "PE"

        wide = supmod.list_pe_images(str(tmp_path), include_non_pe=True)
        by_name = {img["filename"]: img for img in wide["images"]}
        assert set(by_name) == {"hello.exe", "wpp386.exe", "dos4gw.exe", "payload.bin"}
        assert by_name["hello.exe"]["format"] == "PE"
        assert by_name["wpp386.exe"]["format"] == "LX"
        assert by_name["wpp386.exe"]["bitness"] == 32
        assert by_name["dos4gw.exe"]["format"] == "LE"
        assert by_name["payload.bin"]["format"] == "RAW"
        assert by_name["payload.bin"]["bitness"] is None
        # Non-PE entries are addressable by idalib_open afterwards.
        assert "payload.bin" in supmod.supervisor.paths.alias_registry
    finally:
        supmod.supervisor = old_supervisor


def test_sniff_binary_header_classifies_formats(tmp_path):
    """The sniffer recognizes ELF and bare LX images, not just MZ-wrapped ones."""
    import io
    import struct

    elf = bytearray(0x40)
    elf[:4] = bytes((0x7F, 0x45, 0x4C, 0x46))
    elf[4] = 2  # ELFCLASS64
    struct.pack_into("<H", elf, 0x10, 3)  # ET_DYN
    struct.pack_into("<H", elf, 0x12, 0x3E)  # EM_X86_64
    header = supmod._paths._sniff_binary_header(io.BytesIO(bytes(elf)), len(elf))
    assert header["format"] == "ELF"
    assert header["bitness"] == 64
    assert header["arch"] == "x86_64"
    assert header["is_dll"] is True

    bare_lx = b"LX" + bytes(0x40)
    header = supmod._paths._sniff_binary_header(io.BytesIO(bare_lx), len(bare_lx))
    assert header["format"] == "LX"
    assert header["bitness"] == 32

    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    header = supmod._paths._sniff_binary_header(io.BytesIO(bytes(dos)), len(dos))
    assert header["format"] == "MZ"
    assert header["bitness"] == 16

    header = supmod._paths._sniff_binary_header(io.BytesIO(b"xx"), 2)
    assert header["format"] == "RAW"
    assert header["bitness"] is None


def _open_with_fake_supervisor(sample, **kwargs):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    restore = _patch_discovery(instances=[], probe=False)
    try:
        return sup, supmod.idb_open(input_path=str(sample), **kwargs)
    finally:
        restore()
        supmod.supervisor = old_supervisor


def test_idb_open_quarantines_orphaned_components(tmp_path):
    """Unpacked components with no live owner (a worker killed before saving)
    are moved aside so the reopen doesn't attach to half-written state."""
    sample = tmp_path / "GAME.EXE"
    sample.write_bytes(b"MZ")
    for suffix in (".id0", ".id1", ".nam", ".til", ".$$$"):
        (tmp_path / f"GAME.EXE{suffix}").write_bytes(b"x")
    (tmp_path / "GAME.EXE.i64").write_bytes(b"saved")

    sup, result = _open_with_fake_supervisor(sample)

    assert result["success"] is True, result
    assert not list(tmp_path.glob("GAME.EXE.id*")), "components left in place"
    assert (tmp_path / "GAME.EXE.i64").exists(), "saved database must be kept"
    moved = list((tmp_path / ".ida_stale").glob("GAME.EXE-*/*"))
    assert sorted(p.name for p in moved) == sorted(
        f"GAME.EXE{s}" for s in (".id0", ".id1", ".nam", ".til", ".$$$")
    )
    assert any(".ida_stale" in n for n in result["notes"]), result["notes"]
    assert sup.opened, "binary was not opened after quarantine"


def test_idb_open_never_quarantines_locked_components(tmp_path, monkeypatch):
    """Components held open by an unregistered IDA must stay put."""
    sample = tmp_path / "GAME.EXE"
    sample.write_bytes(b"MZ")
    (tmp_path / "GAME.EXE.id0").write_bytes(b"x")
    monkeypatch.setattr(supmod._paths, "components_lock_state", lambda comps: "locked")

    _sup, result = _open_with_fake_supervisor(sample)

    assert (tmp_path / "GAME.EXE.id0").exists()
    assert not (tmp_path / ".ida_stale").exists()


def test_components_lock_state_classifies(tmp_path):
    from ida_pro_mcp import idalib_paths as paths

    assert paths.components_lock_state([]) == "none"
    comp = tmp_path / "x.id0"
    comp.write_bytes(b"x")
    state = paths.components_lock_state([comp])
    # Unlocked on Windows -> stale; on POSIX a just-written file is "possibly_open".
    assert state in ("stale", "possibly_open")


def test_idb_open_enables_idle_autosave_by_default(tmp_path):
    sample = tmp_path / "a.exe"
    sample.write_bytes(b"MZ")
    sup, result = _open_with_fake_supervisor(sample)
    assert result["success"] is True, result
    calls = [args for name, args in sup.tool_calls if name == "idb_autosave"]
    assert calls == [{"enabled": True, "idle_sec": 60.0}]
    assert "autosave" in result


def test_idb_open_can_disable_idle_autosave(tmp_path):
    sample = tmp_path / "a.exe"
    sample.write_bytes(b"MZ")
    sup, result = _open_with_fake_supervisor(sample, autosave=False, autosave_idle_sec=15)
    assert result["success"] is True, result
    calls = [args for name, args in sup.tool_calls if name == "idb_autosave"]
    assert calls == [{"enabled": False, "idle_sec": 15}]


# ============================================================================
# Item 1/2: attach to a running GUI, conflict detection on open
# ============================================================================


def _gui_instance(idb_path, port=31337, pid=999):
    return {
        "host": "127.0.0.1",
        "port": port,
        "pid": pid,
        "binary": Path(idb_path).name,
        "idb_path": str(idb_path),
        "started_at": "now",
    }


def _with_sup(tmp_path, instances, probe=True):
    old = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    restore = _patch_discovery(instances=instances, probe=probe)

    def done():
        restore()
        supmod.supervisor = old

    return sup, done


def test_candidate_paths_cover_splitext_and_i64_forms(tmp_path):
    sup = _FakeSupervisor()
    exe = tmp_path / "GAME.EXE"
    keys = sup._candidate_idb_paths(str(exe))
    assert sup._path_key(str(tmp_path / "GAME.i64")) in keys
    assert sup._path_key(str(tmp_path / "GAME.EXE.i64")) in keys
    keys = sup._candidate_idb_paths(str(tmp_path / "GAME.i64"))
    assert sup._path_key(str(tmp_path / "GAME")) in keys


def test_idb_open_reports_gui_conflict_with_options(tmp_path):
    sample = tmp_path / "GAME.EXE"
    sample.write_bytes(b"MZ")
    sup, done = _with_sup(tmp_path, [_gui_instance(tmp_path / "GAME.i64")])
    try:
        result = supmod.idb_open(input_path=str(sample))
        assert result["success"] is False
        assert result["conflict"]["state"] == "gui"
        assert result["conflict"]["holder"]["pid"] == 999
        assert [o["on_conflict"] for o in result["options"]] == ["use_gui", "read_only", "copy"]
        assert sup.opened == [], "must not open a second writer"
    finally:
        done()


def test_idb_open_use_gui_attaches_to_the_gui(tmp_path):
    sample = tmp_path / "GAME.EXE"
    sample.write_bytes(b"MZ")
    sup, done = _with_sup(tmp_path, [_gui_instance(tmp_path / "GAME.i64")])
    try:
        result = supmod.idb_open(input_path=str(sample), on_conflict="use_gui")
        assert result["success"] is True, result
        session = sup.sessions[result["session"]["session_id"]]
        assert session.backend == "gui" and session.port == 31337
        assert sup.opened == []
    finally:
        done()


def test_idb_open_locked_components_offer_copy_not_gui(tmp_path, monkeypatch):
    sample = tmp_path / "GAME.EXE"
    sample.write_bytes(b"MZ")
    (tmp_path / "GAME.EXE.id0").write_bytes(b"x")
    monkeypatch.setattr(supmod._paths, "components_lock_state", lambda comps: "locked")
    sup, done = _with_sup(tmp_path, [])
    try:
        result = supmod.idb_open(input_path=str(sample))
        assert result["conflict"]["state"] == "locked"
        assert "use_gui" not in [o["on_conflict"] for o in result["options"]]
        refused = supmod.idb_open(input_path=str(sample), on_conflict="use_gui")
        assert refused["success"] is False and "no MCP plugin" in refused["error"]
        assert (tmp_path / "GAME.EXE.id0").exists(), "locked files must not be touched"
    finally:
        done()


def test_idb_open_copy_opens_private_copy_of_saved_database(tmp_path, monkeypatch):
    sample = tmp_path / "GAME.EXE"
    sample.write_bytes(b"MZ")
    (tmp_path / "GAME.EXE.i64").write_bytes(b"saved-db")
    monkeypatch.setattr(supmod._paths, "components_lock_state", lambda comps: "locked")
    (tmp_path / "GAME.EXE.id0").write_bytes(b"x")
    sup, done = _with_sup(tmp_path, [])
    try:
        result = supmod.idb_open(input_path=str(sample), on_conflict="copy")
        assert result["success"] is True, result
        opened = Path(sup.opened[0][1]["input_path"])
        assert opened.name == "GAME.EXE.i64"
        assert opened.parent != tmp_path
        assert opened.read_bytes() == b"saved-db"
        session = sup.sessions[result["session"]["session_id"]]
        assert session.copy_of == str(sample) and session.read_only is False
        assert any("private" in n for n in result["notes"])
    finally:
        done()


def test_idb_open_read_only_blocks_saves(tmp_path, monkeypatch):
    sample = tmp_path / "GAME.EXE"
    sample.write_bytes(b"MZ")
    (tmp_path / "GAME.EXE.i64").write_bytes(b"saved-db")
    monkeypatch.setattr(supmod._paths, "components_lock_state", lambda comps: "locked")
    (tmp_path / "GAME.EXE.id0").write_bytes(b"x")
    sup, done = _with_sup(tmp_path, [])
    try:
        result = supmod.idb_open(input_path=str(sample), on_conflict="read_only")
        sid = result["session"]["session_id"]
        assert sup.sessions[sid].read_only is True
        autosave_calls = [a for n, a in sup.tool_calls if n == "idb_autosave"]
        assert autosave_calls and autosave_calls[-1]["enabled"] is False

        resp = supmod._handle_tools_call(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "idb_save", "arguments": {"database": sid}},
            }
        )
        assert resp["result"]["isError"] is True
        assert "read-only" in resp["result"]["content"][0]["text"]
        assert not sup.forwarded, "idb_save must not reach the worker"

        sup.tool_calls.clear()
        closed = sup.close_session(sid, save=True)
        assert closed["saved"] is None
        assert ("idb_save", None) not in sup.tool_calls
    finally:
        done()


def test_idb_open_attaches_gui_by_port_or_pid(tmp_path):
    idb = tmp_path / "fw.bin.i64"
    sup, done = _with_sup(tmp_path, [_gui_instance(idb, port=40001, pid=4242)])
    try:
        by_port = supmod.idb_open(instance="40001")
        assert by_port["success"] is True, by_port
        session = sup.sessions[by_port["session"]["session_id"]]
        assert session.backend == "gui" and session.port == 40001
        by_pid = supmod.idb_open(instance="4242")
        assert by_pid["session"]["session_id"] == session.session_id, "reuses the attachment"
        missing = supmod.idb_open(instance="1")
        assert missing["success"] is False and "port 40001" in missing["error"]
    finally:
        done()


def test_idb_open_requires_path_or_instance():
    result = supmod.idb_open()
    assert result["success"] is False and "input_path or instance" in result["error"]
    bad = supmod.idb_open(input_path="x", on_conflict="nope")
    assert "on_conflict" in bad["error"]
