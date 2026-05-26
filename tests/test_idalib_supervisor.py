"""idalib supervisor tests that do not require IDA/idalib."""

import sys
from pathlib import Path

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
                        {"name": "idalib_open", "inputSchema": {"type": "object"}},
                        {"name": "list_instances", "inputSchema": {"type": "object"}},
                        {"name": "select_instance", "inputSchema": {"type": "object"}},
                    ]
                },
            }
        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"resources": []}}
        if method == "resources/templates/list":
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"resourceTemplates": []}}
        self.forwarded.append(payload)
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"ok": True}}

    def call_worker_tool(self, worker, name, arguments=None):
        if name == "idalib_open":
            assert arguments is not None
            self.opened.append((name, arguments))
            return {
                "success": True,
                "session": {
                    "session_id": arguments["session_id"],
                    "input_path": arguments["input_path"],
                    "filename": Path(arguments["input_path"]).name,
                    "created_at": "now",
                    "last_accessed": "now",
                    "is_analyzing": False,
                    "metadata": {},
                },
            }
        return {"ok": True, "error": None}


class _TransportMcp:
    def __init__(self, session_id="stdio:default"):
        self.session_id = session_id

    def get_current_transport_session_id(self):
        return self.session_id


class _MainExit(Exception):
    pass


class _FakeInputBuffer:
    def __init__(self, lines):
        self.lines = list(lines)

    def readline(self):
        if not self.lines:
            return b""
        return self.lines.pop(0)


class _FakeStdin:
    def __init__(self, lines):
        self.buffer = _FakeInputBuffer(lines)


class _RecordingOutputBuffer:
    def __init__(self):
        self.writes = []

    def write(self, data):
        self.writes.append(data)

    def flush(self):
        pass


class _FakeStdout:
    def __init__(self):
        self.buffer = _RecordingOutputBuffer()


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


def test_stdio_shared_supervisor_spawn_uses_http_daemon_command(monkeypatch, tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    captured = {}

    class _FakePopen:
        returncode = None

        def __init__(self, cmd, **kwargs):
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs

        def poll(self):
            return None

    monkeypatch.setattr(supmod.subprocess, "Popen", _FakePopen)

    proc = supmod._spawn_shared_http_supervisor(
        host="127.0.0.1",
        port=9876,
        worker_args=["--unsafe", "--max-workers", "8"],
    )

    assert isinstance(proc, _FakePopen)
    assert captured["cmd"][:3] == [
        sys.executable,
        "-m",
        "ida_pro_mcp.idalib_supervisor",
    ]
    assert "--stdio" not in captured["cmd"]
    assert "--stdio-shared" not in captured["cmd"]
    assert "--unsafe" in captured["cmd"]
    assert "--max-workers" in captured["cmd"]
    assert str(sample) not in captured["cmd"]
    assert captured["kwargs"]["stdin"] is supmod.subprocess.DEVNULL
    assert captured["kwargs"]["stdout"] is supmod.subprocess.DEVNULL
    assert captured["kwargs"]["stderr"] is supmod.subprocess.DEVNULL
    assert "start_new_session" in captured["kwargs"]


def test_open_stdio_initial_database_forwards_transport_session(monkeypatch, tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    captured = {}

    def fake_http_jsonrpc(**kwargs):
        captured.update(kwargs)
        return (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [],
                    "structuredContent": {
                        "success": True,
                        "session": {"session_id": "sample"},
                    },
                },
            },
            kwargs["session_id"],
        )

    monkeypatch.setattr(supmod, "_http_jsonrpc", fake_http_jsonrpc)

    supmod._open_stdio_initial_database(
        host="127.0.0.1",
        port=9876,
        input_path=sample,
        session_id="http-session",
    )

    assert captured["session_id"] == "http-session"
    payload = supmod.json.loads(captured["body"])
    assert payload["params"]["name"] == "idalib_open"
    assert payload["params"]["arguments"]["input_path"] == str(sample)


def test_probe_http_supervisor_uses_stable_session_header(monkeypatch):
    captured = {}

    def fake_http_jsonrpc(**kwargs):
        captured.update(kwargs)
        return (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"serverInfo": {"name": supmod.mcp.name}},
            },
            kwargs["session_id"],
        )

    monkeypatch.setattr(supmod, "_http_jsonrpc", fake_http_jsonrpc)

    assert supmod._probe_http_supervisor("127.0.0.1", 9876) is True
    assert captured["session_id"] == supmod.STDIO_PROXY_PROBE_SESSION_ID
    assert supmod.json.loads(captured["body"])["method"] == "initialize"


def test_probe_http_supervisor_rejects_unexpected_server(monkeypatch):
    def fake_http_jsonrpc(**kwargs):
        return (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"serverInfo": {"name": "other-server"}},
            },
            kwargs["session_id"],
        )

    monkeypatch.setattr(supmod, "_http_jsonrpc", fake_http_jsonrpc)

    assert supmod._probe_http_supervisor("127.0.0.1", 9876) is False


def test_stdio_proxy_opens_initial_database_after_initialize(monkeypatch, tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    forwarded = []
    opened = []

    def fake_http_jsonrpc(**kwargs):
        forwarded.append(kwargs)
        return ({"jsonrpc": "2.0", "id": 1, "result": {}}, "http-session")

    monkeypatch.setattr(supmod, "_http_jsonrpc", fake_http_jsonrpc)
    monkeypatch.setattr(
        supmod,
        "_open_stdio_initial_database",
        lambda **kwargs: opened.append(kwargs),
    )
    monkeypatch.setattr(
        supmod.sys,
        "stdin",
        _FakeStdin(
            [
                b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n',
                b"",
            ]
        ),
    )
    stdout = _FakeStdout()
    monkeypatch.setattr(supmod.sys, "stdout", stdout)

    supmod._stdio_proxy("127.0.0.1", 9876, input_path=sample)

    assert forwarded[0]["session_id"] is None
    assert opened == [
        {
            "host": "127.0.0.1",
            "port": 9876,
            "input_path": sample,
            "session_id": "http-session",
        }
    ]
    assert stdout.buffer.writes


def test_stdio_proxy_does_not_open_initial_database_when_initialize_fails(
    monkeypatch, tmp_path
):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    opened = []

    def fake_http_jsonrpc(**_kwargs):
        return ({"jsonrpc": "2.0", "id": 1, "error": {"message": "bad"}}, None)

    monkeypatch.setattr(supmod, "_http_jsonrpc", fake_http_jsonrpc)
    monkeypatch.setattr(
        supmod,
        "_open_stdio_initial_database",
        lambda **kwargs: opened.append(kwargs),
    )
    monkeypatch.setattr(
        supmod.sys,
        "stdin",
        _FakeStdin(
            [
                b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n',
                b"",
            ]
        ),
    )
    monkeypatch.setattr(supmod.sys, "stdout", _FakeStdout())

    supmod._stdio_proxy("127.0.0.1", 9876, input_path=sample)

    assert opened == []


def test_jsonrpc_proxy_error_omits_notification_response():
    result = supmod._jsonrpc_proxy_error(
        b'{"jsonrpc":"2.0","method":"notifications/initialized"}',
        "boom",
    )

    assert result is None


def test_stdio_flag_uses_direct_stdio_not_shared_proxy(monkeypatch):
    calls = []
    old_supervisor = supmod.supervisor
    old_dispatch = supmod.mcp.registry.dispatch
    old_require_session = supmod.mcp.require_streamable_http_session

    monkeypatch.setattr(supmod.sys, "argv", ["idalib-mcp", "--stdio"])
    monkeypatch.setattr(
        supmod,
        "_ensure_shared_http_supervisor",
        lambda **_kwargs: calls.append("shared"),
    )
    monkeypatch.setattr(supmod.signal, "signal", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(supmod.mcp, "stdio", lambda: (_ for _ in ()).throw(_MainExit))

    try:
        try:
            supmod.main()
        except _MainExit:
            pass
        else:
            raise AssertionError("expected direct stdio path")
    finally:
        supmod.supervisor = old_supervisor
        supmod.mcp.registry.dispatch = old_dispatch
        supmod.mcp.require_streamable_http_session = old_require_session

    assert calls == []


def test_stdio_shared_flag_uses_shared_proxy(monkeypatch):
    calls = []

    monkeypatch.setattr(supmod.sys, "argv", ["idalib-mcp", "--stdio-shared"])
    monkeypatch.setattr(
        supmod,
        "_ensure_shared_http_supervisor",
        lambda **kwargs: calls.append(("ensure", kwargs)),
    )
    monkeypatch.setattr(
        supmod,
        "_stdio_proxy",
        lambda host, port, input_path=None: calls.append(
            ("proxy", host, port, input_path)
        ),
    )

    supmod.main()

    assert calls[0][0] == "ensure"
    assert calls[1] == ("proxy", "127.0.0.1", 8745, None)


def test_stdio_flags_are_mutually_exclusive(monkeypatch):
    monkeypatch.setattr(
        supmod.sys,
        "argv",
        ["idalib-mcp", "--stdio", "--stdio-shared"],
    )

    try:
        supmod.main()
    except SystemExit as e:
        assert e.code == 2
    else:
        raise AssertionError("expected argparse conflict")


def test_worker_tools_inject_database_and_filter_management_tools():
    sup = _FakeSupervisor()
    tools = sup.worker_tools()
    names = [tool["name"] for tool in tools]
    assert names == ["decompile"]
    schema = tools[0]["inputSchema"]
    assert "database" in schema["properties"]
    assert "database" not in schema.get("required", [])


def test_tool_error_result_omits_structured_content():
    result = supmod._call_tool_result({"error": "no database"}, is_error=True)
    assert result["isError"] is True
    assert "structuredContent" not in result


def test_supervisor_blocks_gui_plugin_routing_tools():
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        result = supmod._handle_tools_call(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "select_instance", "arguments": {"port": 13337}},
            }
        )
        assert result is not None
        assert result["result"]["isError"] is True
        text = result["result"]["content"][0]["text"]
        assert "GUI-plugin routing tool" in text
        assert not supmod.supervisor.forwarded
    finally:
        supmod.supervisor = old_supervisor


def test_open_session_reuses_schema_worker_and_binds_context(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.worker_tools()  # creates the idle/schema worker
    session = sup.open_session(str(sample), session_id="sample", context_id="ctx")
    assert session.session_id == "sample"
    assert sup.context_bindings["ctx"] == "sample"
    assert sup.opened[0][1]["session_id"] == "sample"


def test_resolve_session_accepts_session_id_filename_and_context(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample", context_id="ctx")
    sup.mcp = _TransportMcp()
    sup.context_bindings[supmod.SHARED_FALLBACK_CONTEXT_ID] = "sample"

    assert sup.resolve_session("sample").session_id == "sample"
    assert sup.resolve_session("sample.bin").session_id == "sample"
    assert sup.resolve_session(None).session_id == "sample"


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
        session = sup.open_session(str(sample), session_id="gui", context_id="ctx")
        assert session.backend == "gui"
        assert session.host == "127.0.0.1"
        assert session.port == 31337
        assert session.pid == 999
        assert sup.resolve_session(str(sample)).session_id == "gui"
        assert sup.resolve_session(str(idb)).session_id == "gui"
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
            sup._register_session_locked(stale, str(sample.resolve()), "ctx")
        session = sup.open_session(str(sample), session_id="new", context_id="ctx")
        assert session.session_id == "new"
        assert "stale" not in sup.sessions
        assert sup.context_bindings["ctx"] == "new"
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
            sup._register_session_locked(stale, str(stale_path.resolve()), "ctx")

        session = sup.open_session(str(new_path), session_id="new", context_id="ctx")

        assert session.session_id == "new"
        assert "stale" not in sup.sessions
        assert sup.context_bindings["ctx"] == "new"
    finally:
        restore()


def test_open_session_race_discards_losing_worker_for_existing_path(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    class _RaceSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idalib_open":
                existing = supmod.WorkerSession(
                    session_id="winner",
                    input_path=str(sample.resolve()),
                    filename="sample.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(sample.resolve()), None)
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        session = sup.open_session(str(sample))
        assert session.session_id == "winner"
        assert set(sup.sessions) == {"winner"}
        assert sup.opened[0][1]["session_id"] != "winner"
    finally:
        restore()


def test_open_session_race_rejects_different_requested_session_id(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    class _RaceSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idalib_open":
                existing = supmod.WorkerSession(
                    session_id="winner",
                    input_path=str(sample.resolve()),
                    filename="sample.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(sample.resolve()), None)
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        try:
            sup.open_session(str(sample), session_id="loser")
        except ValueError as e:
            assert "already open as session 'winner'" in str(e)
        else:
            raise AssertionError("expected ValueError")
        assert set(sup.sessions) == {"winner"}
    finally:
        restore()


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

        def call_worker_tool(self, worker, name, arguments=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idalib_open":
                existing = supmod.WorkerSession(
                    session_id=arguments["session_id"],
                    input_path=str(first.resolve()),
                    filename="first.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(first.resolve()), None)
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
        session = sup.open_session(str(sample), session_id="gui", context_id="ctx")
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
        session = sup.open_session(str(sample), session_id="gui", context_id="ctx")
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

        def call_worker_tool(self, worker, name, arguments=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idalib_open":
                self.close_session(arguments["session_id"])
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
        session = sup.open_session(str(sample), session_id="gui", context_id="ctx")
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


# ---------------------------------------------------------------------------
# list_pe_images
# ---------------------------------------------------------------------------


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
    assert "list_pe_images" in supmod.IDALIB_MANAGEMENT_TOOLS


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
        registered = sup.alias_registry["alpha.exe"]
        assert str(tmp_path / "alpha.exe") in registered
    finally:
        supmod.supervisor = old_supervisor


def test_idalib_open_accepts_wire_path_from_list_pe_images(tmp_path):
    # End-to-end: take a `path` straight from a list_pe_images response and pass
    # it back to idalib_open. The basename fallback should resolve it via the
    # registry.
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    sup.mcp = _TransportMcp(session_id="ctx-A")
    try:
        (tmp_path / "beta.exe").write_bytes(_make_pe_blob(body=b"b"))
        listing = supmod.list_pe_images(str(tmp_path))
        wire_path = listing["images"][0]["path"]
        assert wire_path == "beta.exe"  # sanity

        result = supmod.idalib_open(input_path=wire_path)
        assert result.get("success") is True
        # open_session received the absolute path the registry resolved to
        assert sup.opened[0][1]["input_path"] == str(tmp_path / "beta.exe")
    finally:
        supmod.supervisor = old_supervisor


# ---------------------------------------------------------------------------
# list_pe_images search-root fallback
# ---------------------------------------------------------------------------


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
        sup.prepopulate_aliases([str(real_root)])

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
        sup.prepopulate_aliases([str(other_root)])

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
        sup.prepopulate_aliases([str(root_a), str(root_b)])

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
        sup.search_roots = [ghost, str(real)]

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
        sup.search_roots = [str(tmp_path / "gone"), str(tmp_path / "also_gone")]
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
        sup.search_roots = [str(root)]

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
    sup.mcp = _TransportMcp(session_id="ctx-A")
    try:
        real = tmp_path / "real"
        real.mkdir()
        sample = real / "thing.exe"
        sample.write_bytes(_make_pe_blob(body=b"x"))
        sup.search_roots = [str(real)]

        # First call: bogus path, fallback fires, registry populated.
        listing = supmod.list_pe_images(str(tmp_path / "elsewhere"))
        assert listing.get("fallback_to_search_roots") is True
        assert "thing.exe" in sup.alias_registry

        # Now an agent can open by bare filename.
        opened = supmod.idalib_open(input_path="thing.exe")
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


# ---------------------------------------------------------------------------
# auto-rebind heuristic in resolve_session (isolated-contexts mode)
# ---------------------------------------------------------------------------


def _make_live_worker_session(session_id: str, input_path: str) -> supmod.WorkerSession:
    return supmod.WorkerSession(
        session_id=session_id,
        input_path=input_path,
        filename=Path(input_path).name,
        host="127.0.0.1",
        port=4242,
        process=_FakeProcess(),
    )


def test_resolve_session_auto_rebinds_when_single_live_session_isolated(tmp_path):
    sup = _FakeSupervisor()
    sup.isolated_contexts = True
    sup.mcp = _TransportMcp(session_id="agent-A")

    sample = tmp_path / "only.exe"
    sample.write_bytes(b"x")
    only_session = _make_live_worker_session("sole", str(sample))
    sup.sessions[only_session.session_id] = only_session

    assert "agent-A" not in sup.context_bindings
    resolved = sup.resolve_session()
    assert resolved.session_id == "sole"
    # Binding now persists for this context, so a second call is a plain lookup.
    assert sup.context_bindings["agent-A"] == "sole"


def test_resolve_session_does_not_auto_rebind_with_multiple_live_sessions(tmp_path):
    sup = _FakeSupervisor()
    sup.isolated_contexts = True
    sup.mcp = _TransportMcp(session_id="agent-A")

    a = tmp_path / "a.exe"
    b = tmp_path / "b.exe"
    a.write_bytes(b"x")
    b.write_bytes(b"x")
    sup.sessions["a"] = _make_live_worker_session("a", str(a))
    sup.sessions["b"] = _make_live_worker_session("b", str(b))

    try:
        sup.resolve_session()
    except RuntimeError as e:
        assert "No database bound" in str(e)
    else:
        raise AssertionError("expected RuntimeError when ambiguous")
    assert "agent-A" not in sup.context_bindings


def test_resolve_session_does_not_auto_rebind_when_only_session_is_dead(tmp_path):
    sup = _FakeSupervisor()
    sup.isolated_contexts = True
    sup.mcp = _TransportMcp(session_id="agent-A")

    dead = tmp_path / "dead.exe"
    dead.write_bytes(b"x")
    dead_session = supmod.WorkerSession(
        session_id="dead",
        input_path=str(dead),
        filename=dead.name,
        host="127.0.0.1",
        port=4242,
        process=_DeadProcess(),
    )
    sup.sessions[dead_session.session_id] = dead_session

    try:
        sup.resolve_session()
    except RuntimeError as e:
        assert "No database bound" in str(e)
    else:
        raise AssertionError("expected RuntimeError when no live sessions")
    assert "agent-A" not in sup.context_bindings


def test_resolve_session_shared_mode_still_uses_fallback(tmp_path):
    # In non-isolated mode, the existing fallback to SHARED_FALLBACK_CONTEXT_ID
    # must still win before the auto-rebind path is even considered.
    sup = _FakeSupervisor()
    sup.isolated_contexts = False
    sup.mcp = _TransportMcp(session_id="agent-A")

    sample = tmp_path / "only.exe"
    sample.write_bytes(b"x")
    only_session = _make_live_worker_session("sole", str(sample))
    sup.sessions["sole"] = only_session
    sup.context_bindings[supmod.SHARED_FALLBACK_CONTEXT_ID] = "sole"

    resolved = sup.resolve_session()
    assert resolved.session_id == "sole"
    # We did NOT touch the per-transport context binding; the shared fallback resolved it.
    assert "agent-A" not in sup.context_bindings


# ---------------------------------------------------------------------------
# alias registry (bare-filename resolution for upstream path-stripped clients)
# ---------------------------------------------------------------------------


def test_list_pe_images_populates_alias_registry(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        (tmp_path / "alpha.exe").write_bytes(_make_pe_blob(body=b"a"))
        (tmp_path / "beta.exe").write_bytes(_make_pe_blob(body=b"b"))
        result = supmod.list_pe_images(str(tmp_path))
        assert result["count"] == 2
        assert "alpha.exe" in sup.alias_registry
        assert "beta.exe" in sup.alias_registry
        assert str(tmp_path / "alpha.exe") in sup.alias_registry["alpha.exe"]
    finally:
        supmod.supervisor = old_supervisor


def test_resolve_alias_unique_match(tmp_path):
    sup = _FakeSupervisor()
    p = str(tmp_path / "only.exe")
    sup.record_aliases({"only.exe": p})
    assert sup.resolve_alias("only.exe") == p


def test_resolve_alias_missing_returns_none():
    sup = _FakeSupervisor()
    assert sup.resolve_alias("never_seen.exe") is None


def test_resolve_alias_ambiguous_raises(tmp_path):
    sup = _FakeSupervisor()
    a = tmp_path / "dir1"
    b = tmp_path / "dir2"
    a.mkdir()
    b.mkdir()
    sup.record_aliases({"shared.exe": str(a / "shared.exe")})
    sup.record_aliases({"shared.exe": str(b / "shared.exe")})
    try:
        sup.resolve_alias("shared.exe")
    except RuntimeError as e:
        assert "Ambiguous alias" in str(e)
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
    sup.record_aliases({"shared.exe": pa})
    sup.record_aliases({"shared.exe": pb})
    assert sup.resolve_alias("shared.exe", directory_hint=str(a_dir)) == pa
    assert sup.resolve_alias("shared.exe", directory_hint=str(b_dir)) == pb


def test_resolve_alias_directory_hint_no_match_returns_none(tmp_path):
    sup = _FakeSupervisor()
    a_dir = tmp_path / "real"
    a_dir.mkdir()
    sup.record_aliases({"x.exe": str(a_dir / "x.exe")})
    assert sup.resolve_alias("x.exe", directory_hint=str(tmp_path / "wrong")) is None


def test_idalib_open_resolves_bare_filename_via_registry(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    sup.mcp = _TransportMcp(session_id="ctx-A")
    try:
        sample = tmp_path / "sole.exe"
        sample.write_bytes(b"x")  # any contents fine; _FakeSupervisor stubs IDA.
        sup.record_aliases({"sole.exe": str(sample)})

        result = supmod.idalib_open(input_path="sole.exe")
        assert result.get("success") is True
        # open_session was invoked with the resolved absolute path, not the bare name.
        assert sup.opened, "expected idalib_open to reach open_session"
        assert sup.opened[0][1]["input_path"] == str(sample)
    finally:
        supmod.supervisor = old_supervisor


def test_idalib_open_bare_filename_unknown_yields_clear_error(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    sup.mcp = _TransportMcp(session_id="ctx-A")
    try:
        result = supmod.idalib_open(input_path="nope.exe")
        # No registry entry, no real file -> open_session will raise FileNotFoundError.
        assert "error" in result
        assert "nope.exe" in result["error"]
    finally:
        supmod.supervisor = old_supervisor


def test_idalib_open_ambiguous_alias_returns_error(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    sup.mcp = _TransportMcp(session_id="ctx-A")
    try:
        d1 = tmp_path / "v1"
        d2 = tmp_path / "v2"
        d1.mkdir()
        d2.mkdir()
        sup.record_aliases({"sole.exe": str(d1 / "sole.exe")})
        sup.record_aliases({"sole.exe": str(d2 / "sole.exe")})
        result = supmod.idalib_open(input_path="sole.exe")
        assert "error" in result
        assert "Ambiguous alias" in result["error"]
    finally:
        supmod.supervisor = old_supervisor


def test_idalib_open_ambiguous_alias_directory_hint_resolves(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    sup.mcp = _TransportMcp(session_id="ctx-A")
    try:
        d1 = tmp_path / "v1"
        d2 = tmp_path / "v2"
        d1.mkdir()
        d2.mkdir()
        sole_v1 = d1 / "sole.exe"
        sole_v2 = d2 / "sole.exe"
        sole_v1.write_bytes(b"x")
        sole_v2.write_bytes(b"x")
        sup.record_aliases({"sole.exe": str(sole_v1)})
        sup.record_aliases({"sole.exe": str(sole_v2)})

        result = supmod.idalib_open(input_path="sole.exe", directory=str(d1))
        assert result.get("success") is True
        assert sup.opened[0][1]["input_path"] == str(sole_v1)
    finally:
        supmod.supervisor = old_supervisor


def test_idalib_aliases_inspection_tool(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        p1 = str(tmp_path / "a.exe")
        p2 = str(tmp_path / "b.exe")
        sup.record_aliases({"a.exe": p1, "b.exe": p2})

        # Full listing
        full = supmod.idalib_aliases()
        assert full["count"] == 2
        assert full["aliases"]["a.exe"] == [p1]

        # Filtered lookup
        one = supmod.idalib_aliases(filename="a.exe")
        assert one["paths"] == [p1]
        assert one["count"] == 1

        # Unknown filename
        miss = supmod.idalib_aliases(filename="missing.exe")
        assert miss["paths"] == []
        assert miss["count"] == 0
    finally:
        supmod.supervisor = old_supervisor


def test_idalib_aliases_in_management_set():
    assert "idalib_aliases" in supmod.IDALIB_MANAGEMENT_TOOLS


def test_idalib_open_falls_back_to_basename_when_absolute_path_missing(tmp_path):
    # An agent often guesses a plausible absolute layout for a file that actually
    # lives somewhere else. When that absolute path doesn't exist, the alias
    # registry should still match on basename so the open succeeds.
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    sup.mcp = _TransportMcp(session_id="ctx-A")
    try:
        real_dir = tmp_path / "actual_location"
        real_dir.mkdir()
        real_file = real_dir / "thing.exe"
        real_file.write_bytes(b"x")
        sup.record_aliases({"thing.exe": str(real_file)})

        guessed_path = str(tmp_path / "wrong" / "path" / "thing.exe")
        result = supmod.idalib_open(input_path=guessed_path)

        assert result.get("success") is True, result
        assert sup.opened[0][1]["input_path"] == str(real_file)
        assert "notes" in result
        assert any("alias registry by basename" in n for n in result["notes"])
    finally:
        supmod.supervisor = old_supervisor


def test_idalib_open_notes_when_absolute_missing_and_no_alias(tmp_path):
    # Path doesn't exist, alias registry doesn't know the basename either.
    # Should fail, but the error response should carry a note telling the agent
    # what to try next (list_pe_images on the parent folder).
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    sup.mcp = _TransportMcp(session_id="ctx-A")
    try:
        guessed_path = str(tmp_path / "nowhere" / "missing.exe")
        result = supmod.idalib_open(input_path=guessed_path)
        assert result.get("success") is False
        assert "error" in result
        assert "notes" in result
        assert any("list_pe_images" in n for n in result["notes"])
        assert any("missing.exe" in n for n in result["notes"])
    finally:
        supmod.supervisor = old_supervisor


def test_idalib_open_bare_filename_success_carries_note(tmp_path):
    # The plain bare-filename happy path: alias registry matches on the very
    # first lookup key, so the note should mention alias resolution but NOT
    # mention basename fallback (since the input WAS the basename already).
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    sup.mcp = _TransportMcp(session_id="ctx-A")
    try:
        sample = tmp_path / "thing.exe"
        sample.write_bytes(b"x")
        sup.record_aliases({"thing.exe": str(sample)})

        result = supmod.idalib_open(input_path="thing.exe")
        assert result.get("success") is True
        assert "notes" in result
        joined = " ".join(result["notes"])
        assert "alias registry" in joined
        assert "by basename" not in joined  # the input IS the basename here
    finally:
        supmod.supervisor = old_supervisor


def test_idalib_open_absolute_existing_path_emits_no_notes(tmp_path):
    # When the supplied absolute path exists, no alias lookup happens, and no
    # notes should be emitted -- the happy path stays quiet.
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    sup.mcp = _TransportMcp(session_id="ctx-A")
    try:
        sample = tmp_path / "happy.exe"
        sample.write_bytes(b"x")
        result = supmod.idalib_open(input_path=str(sample))
        assert result.get("success") is True
        assert "notes" not in result
    finally:
        supmod.supervisor = old_supervisor


# ---------------------------------------------------------------------------
# suggest_aliases: fuzzy "did you mean" matching
# ---------------------------------------------------------------------------


def test_suggest_aliases_empty_registry_returns_empty():
    sup = _FakeSupervisor()
    assert sup.suggest_aliases("anything.exe") == []


def test_suggest_aliases_close_match(tmp_path):
    sup = _FakeSupervisor()
    sup.record_aliases({"sole_v1.05.exe": str(tmp_path / "sole_v1.05.exe")})
    sup.record_aliases({"sole_v1.04.exe": str(tmp_path / "sole_v1.04.exe")})
    sup.record_aliases({"unrelated.dll": str(tmp_path / "unrelated.dll")})

    suggestions = sup.suggest_aliases("sole_v1.05_typo.exe")
    assert "sole_v1.05.exe" in suggestions
    assert "unrelated.dll" not in suggestions


def test_suggest_aliases_case_insensitive(tmp_path):
    sup = _FakeSupervisor()
    sup.record_aliases({"sole_v1.05.exe": str(tmp_path / "sole_v1.05.exe")})
    # User typed uppercase / different casing
    suggestions = sup.suggest_aliases("SOLE_V1.05.EXE")
    assert "sole_v1.05.exe" in suggestions


def test_suggest_aliases_substring_fallback(tmp_path):
    # User's literal example: SOLE_v_1.05_original.exe vs sole_v1.05.exe.
    # difflib ratio is borderline; the substring fallback must still surface it.
    sup = _FakeSupervisor()
    sup.record_aliases({"sole_v1.05.exe": str(tmp_path / "sole_v1.05.exe")})
    sup.record_aliases({"sole_v1.04.exe": str(tmp_path / "sole_v1.04.exe")})

    suggestions = sup.suggest_aliases("SOLE_v_1.05_original.exe")
    # Both share the "sole_v1" prefix on lowercase; at least sole_v1.05.exe
    # must be suggested via either the difflib or substring pass.
    assert "sole_v1.05.exe" in suggestions


def test_suggest_aliases_respects_n_limit(tmp_path):
    sup = _FakeSupervisor()
    for i in range(10):
        name = f"foo_v{i}.exe"
        sup.record_aliases({name: str(tmp_path / name)})
    suggestions = sup.suggest_aliases("foo_v3.exe", n=2)
    assert len(suggestions) <= 2


def test_suggest_aliases_no_match_returns_empty(tmp_path):
    sup = _FakeSupervisor()
    sup.record_aliases({"alpha.exe": str(tmp_path / "alpha.exe")})
    assert sup.suggest_aliases("zzzzz_completely_different.dat") == []


def test_suggest_aliases_handles_empty_query():
    sup = _FakeSupervisor()
    sup.record_aliases({"x.exe": "/tmp/x.exe"})
    assert sup.suggest_aliases("") == []


# ---------------------------------------------------------------------------
# prepopulate_aliases: --search-root pre-scan at startup
# ---------------------------------------------------------------------------


def test_prepopulate_aliases_registers_pe_images(tmp_path):
    sup = _FakeSupervisor()
    (tmp_path / "a.exe").write_bytes(_make_pe_blob(body=b"a"))
    (tmp_path / "b.exe").write_bytes(_make_pe_blob(body=b"b"))
    (tmp_path / "notes.txt").write_bytes(b"not a PE")

    summary = sup.prepopulate_aliases([str(tmp_path)])
    assert summary[str(tmp_path)]["count"] == 2
    assert summary[str(tmp_path)]["error"] is None
    assert "a.exe" in sup.alias_registry
    assert "b.exe" in sup.alias_registry
    assert str(tmp_path / "a.exe") in sup.alias_registry["a.exe"]
    # search_roots is recorded for introspection regardless of outcome
    assert str(tmp_path) in sup.search_roots


def test_prepopulate_aliases_recursive(tmp_path):
    sup = _FakeSupervisor()
    sub = tmp_path / "sub"
    sub.mkdir()
    (tmp_path / "top.exe").write_bytes(_make_pe_blob(body=b"t"))
    (sub / "deep.exe").write_bytes(_make_pe_blob(body=b"d"))

    # Default (non-recursive) only sees top.exe
    summary = sup.prepopulate_aliases([str(tmp_path)], recursive=False)
    assert summary[str(tmp_path)]["count"] == 1
    assert "top.exe" in sup.alias_registry
    assert "deep.exe" not in sup.alias_registry

    # Recursive sees both
    sup2 = _FakeSupervisor()
    summary2 = sup2.prepopulate_aliases([str(tmp_path)], recursive=True)
    assert summary2[str(tmp_path)]["count"] == 2
    assert "top.exe" in sup2.alias_registry
    assert "deep.exe" in sup2.alias_registry


def test_prepopulate_aliases_missing_root(tmp_path):
    sup = _FakeSupervisor()
    missing = str(tmp_path / "does_not_exist")
    summary = sup.prepopulate_aliases([missing])
    assert summary[missing]["count"] == 0
    assert "not found" in summary[missing]["error"]
    # Recorded even on failure so the operator sees what was requested
    assert missing in sup.search_roots


def test_prepopulate_aliases_relative_root_rejected(tmp_path):
    sup = _FakeSupervisor()
    summary = sup.prepopulate_aliases(["relative/path"])
    assert summary["relative/path"]["count"] == 0
    assert "absolute" in summary["relative/path"]["error"]


def test_prepopulate_aliases_file_not_dir(tmp_path):
    sup = _FakeSupervisor()
    f = tmp_path / "im_a_file.exe"
    f.write_bytes(_make_pe_blob())
    summary = sup.prepopulate_aliases([str(f)])
    assert summary[str(f)]["count"] == 0
    assert "not a directory" in summary[str(f)]["error"]


def test_prepopulate_aliases_one_bad_root_does_not_abort_others(tmp_path):
    sup = _FakeSupervisor()
    good = tmp_path / "good"
    good.mkdir()
    (good / "x.exe").write_bytes(_make_pe_blob())
    bad = str(tmp_path / "bad" / "missing")

    summary = sup.prepopulate_aliases([bad, str(good)])
    assert summary[bad]["error"] is not None
    assert summary[str(good)]["count"] == 1
    assert "x.exe" in sup.alias_registry


def test_prepopulate_aliases_dedupes_repeat_call(tmp_path):
    sup = _FakeSupervisor()
    (tmp_path / "x.exe").write_bytes(_make_pe_blob())
    sup.prepopulate_aliases([str(tmp_path)])
    sup.prepopulate_aliases([str(tmp_path)])
    # alias_registry uses a set so the second call is idempotent
    assert len(sup.alias_registry["x.exe"]) == 1
    # search_roots also dedupes
    assert sup.search_roots.count(str(tmp_path)) == 1


# ---------------------------------------------------------------------------
# idalib_search_roots tool
# ---------------------------------------------------------------------------


def test_idalib_search_roots_in_management_set():
    assert "idalib_search_roots" in supmod.IDALIB_MANAGEMENT_TOOLS


def test_idalib_search_roots_returns_empty_when_unset():
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        result = supmod.idalib_search_roots()
        assert result["roots"] == []
        assert result["count"] == 0
    finally:
        supmod.supervisor = old_supervisor


def test_idalib_search_roots_returns_prepopulated(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    try:
        (tmp_path / "x.exe").write_bytes(_make_pe_blob())
        sup.prepopulate_aliases([str(tmp_path)])
        result = supmod.idalib_search_roots()
        assert result["count"] == 1
        assert result["roots"] == [str(tmp_path)]
    finally:
        supmod.supervisor = old_supervisor


# ---------------------------------------------------------------------------
# idalib_open: "did you mean" suggestions wired into notes
# ---------------------------------------------------------------------------


def test_idalib_open_emits_did_you_mean_for_absolute_miss(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    sup.mcp = _TransportMcp(session_id="ctx-A")
    try:
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        sup.record_aliases({"sole_v1.05.exe": str(real_dir / "sole_v1.05.exe")})
        # Reproduces the literal failure: agent supplies absolute path with
        # a casing/format mismatch on the filename.
        bad = str(tmp_path / "fake" / "SOLE_v_1.05_original.exe")
        result = supmod.idalib_open(input_path=bad)
        assert result.get("success") is False
        assert "notes" in result
        joined = " ".join(result["notes"])
        assert "Did you mean" in joined
        assert "sole_v1.05.exe" in joined
    finally:
        supmod.supervisor = old_supervisor


def test_idalib_open_emits_did_you_mean_for_bare_filename_miss(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    sup.mcp = _TransportMcp(session_id="ctx-A")
    try:
        sup.record_aliases({"sole_v1.05.exe": str(tmp_path / "sole_v1.05.exe")})
        result = supmod.idalib_open(input_path="sole_v1.05_TYPO.exe")
        assert result.get("success") is False
        assert "notes" in result
        joined = " ".join(result["notes"])
        assert "alias registry" in joined
        assert "idalib_aliases" in joined or "list_pe_images" in joined
        assert "Did you mean" in joined
        assert "sole_v1.05.exe" in joined
    finally:
        supmod.supervisor = old_supervisor


def test_idalib_open_no_suggestion_when_registry_empty(tmp_path):
    old_supervisor = supmod.supervisor
    sup = _FakeSupervisor()
    supmod.supervisor = sup
    sup.mcp = _TransportMcp(session_id="ctx-A")
    try:
        # Empty registry -- no suggestions to make.
        result = supmod.idalib_open(input_path="anything.exe")
        assert result.get("success") is False
        # The breadcrumb about idalib_aliases / list_pe_images should still
        # appear, but no "Did you mean" line since there's nothing to suggest.
        joined = " ".join(result.get("notes", []))
        assert "Did you mean" not in joined
    finally:
        supmod.supervisor = old_supervisor


# ---------------------------------------------------------------------------
# CLI flag parsing for --search-root / --search-root-recursive
# ---------------------------------------------------------------------------


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
        def __init__(self, mcp, *, isolated_contexts=False, max_workers=4, worker_args=None):
            super().__init__(
                mcp,
                isolated_contexts=isolated_contexts,
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
    assert str(tmp_path) in supmod.supervisor.search_roots


def test_resolve_session_isolated_reinit_simulates_user_scenario(tmp_path):
    # Reproduces the reported scenario:
    # 1. agent-A opens "only.exe" (binds context agent-A -> sole)
    # 2. agent-A's transport drops; client re-initializes as agent-B
    # 3. agent-B calls a tool with no database arg -> would have failed pre-fix
    #    Now: auto-rebind finds the lone live session and binds context agent-B -> sole.
    sup = _FakeSupervisor()
    sup.isolated_contexts = True

    sample = tmp_path / "only.exe"
    sample.write_bytes(b"x")
    only_session = _make_live_worker_session("sole", str(sample))
    sup.sessions["sole"] = only_session
    sup.context_bindings["agent-A"] = "sole"  # left over from prior connection

    sup.mcp = _TransportMcp(session_id="agent-B")
    resolved = sup.resolve_session()
    assert resolved.session_id == "sole"
    assert sup.context_bindings["agent-B"] == "sole"
    # The stale binding from the previous transport is left alone — explicit cleanup
    # only happens via idalib_close/idalib_unbind.
    assert sup.context_bindings["agent-A"] == "sole"
