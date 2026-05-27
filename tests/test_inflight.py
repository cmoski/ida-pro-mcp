"""Tests for the inflight tracker.

inflight.py is pure stdlib (no idaapi), so we load it standalone via importlib
to avoid triggering ida_mcp/__init__.py (which imports idaapi). This mirrors how
idalib_supervisor.py loads vendored modules in isolation, and keeps the
"no idaapi in this process" invariant the supervisor tests rely on.
"""

import importlib.util
from pathlib import Path

_INFLIGHT_PATH = (
    Path(__file__).resolve().parent.parent
    / "src" / "ida_pro_mcp" / "ida_mcp" / "inflight.py"
)


def _load_inflight():
    spec = importlib.util.spec_from_file_location("ida_mcp_inflight_under_test", _INFLIGHT_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_inflight_empty_snapshot():
    m = _load_inflight()
    snap = m.inflight_snapshot()
    assert snap == {"depth": 0, "tool": None, "inflight_seconds": 0.0}


def test_inflight_enter_exit_roundtrip():
    m = _load_inflight()
    token = m.inflight_enter("decompile")
    snap = m.inflight_snapshot()
    assert snap["depth"] == 1
    assert snap["tool"] == "decompile"
    assert snap["inflight_seconds"] >= 0.0
    m.inflight_exit(token)
    assert m.inflight_snapshot()["depth"] == 0


def test_inflight_exit_is_idempotent():
    m = _load_inflight()
    token = m.inflight_enter("x")
    m.inflight_exit(token)
    m.inflight_exit(token)  # no error, no negative depth
    assert m.inflight_snapshot()["depth"] == 0


def test_inflight_depth_counts_concurrent_calls():
    m = _load_inflight()
    t1 = m.inflight_enter("a")
    t2 = m.inflight_enter("b")
    t3 = m.inflight_enter("c")
    assert m.inflight_snapshot()["depth"] == 3
    m.inflight_exit(t2)
    assert m.inflight_snapshot()["depth"] == 2
    m.inflight_exit(t1)
    m.inflight_exit(t3)
    assert m.inflight_snapshot()["depth"] == 0


def test_inflight_reports_oldest_call(monkeypatch):
    m = _load_inflight()
    # Fake a monotonic clock so we can control which call is "oldest".
    clock = {"t": 1000.0}
    monkeypatch.setattr(m.time, "monotonic", lambda: clock["t"])

    clock["t"] = 1000.0
    t_old = m.inflight_enter("slow_decompile")
    clock["t"] = 1005.0
    t_new = m.inflight_enter("fast_get_int")

    clock["t"] = 1010.0
    snap = m.inflight_snapshot()
    # Oldest entry (started at 1000) should be reported, with elapsed 10s.
    assert snap["tool"] == "slow_decompile"
    assert snap["inflight_seconds"] == 10.0
    assert snap["depth"] == 2

    m.inflight_exit(t_old)
    m.inflight_exit(t_new)
