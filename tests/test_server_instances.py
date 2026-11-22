"""GUI-proxy instance tools (list_instances / select_instance) without IDA."""

import json

from ida_pro_mcp import server


def _instances():
    return [
        {"host": "127.0.0.1", "port": 13337, "pid": 1, "binary": "a.exe", "idb_path": "C:/a.exe.i64"},
        {"host": "127.0.0.1", "port": 13338, "pid": 2, "binary": "b.dll", "idb_path": "C:/b.dll.i64"},
    ]


def _call(name, arguments=None):
    resp = server.dispatch_proxy(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )
    result = resp["result"]
    if "structuredContent" in result:
        return result["structuredContent"]
    return json.loads(result["content"][0]["text"])


def test_list_instances_is_answered_locally(monkeypatch):
    monkeypatch.setattr(server, "discover_instances", _instances)
    monkeypatch.setattr(server, "_proxy_to_ida", lambda *_: (_ for _ in ()).throw(AssertionError("proxied")))
    out = _call("list_instances")
    assert out["count"] == 2
    assert [i["binary"] for i in out["instances"]] == ["a.exe", "b.dll"]


def test_select_instance_routes_this_session(monkeypatch):
    monkeypatch.setattr(server, "discover_instances", _instances)
    monkeypatch.setattr(server, "probe_instance", lambda host, port, timeout=2.0: port == 13338)
    monkeypatch.setattr(server.mcp, "get_current_transport_session_id", lambda: "http:abc")
    monkeypatch.setattr(server, "_session_targets", {})
    try:
        out = _call("select_instance", {"port": 13338})
        assert out["success"] is True and out["binary"] == "b.dll"
        assert server._current_target() == ("127.0.0.1", 13338)
        # Another session keeps the default target.
        monkeypatch.setattr(server.mcp, "get_current_transport_session_id", lambda: "http:other")
        assert server._current_target() == (server.IDA_HOST, server.IDA_PORT)
    finally:
        server._session_targets.clear()


def test_select_instance_rejects_dead_port(monkeypatch):
    monkeypatch.setattr(server, "probe_instance", lambda host, port, timeout=2.0: False)
    out = _call("select_instance", {"port": 9})
    assert out["success"] is False
    assert "No IDA instance" in out["error"]


def test_tools_list_merges_local_tools(monkeypatch):
    def fake_proxy(_payload):
        return {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "decompile"}]}}

    monkeypatch.setattr(server, "_proxy_to_ida", fake_proxy)
    resp = server.dispatch_proxy({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    names = [t["name"] for t in resp["result"]["tools"]]
    assert "decompile" in names
    assert "list_instances" in names and "select_instance" in names
