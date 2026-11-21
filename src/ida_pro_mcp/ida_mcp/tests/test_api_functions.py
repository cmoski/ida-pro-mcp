"""Tests for api_functions: function flags (and, later, list export/import)."""

import ida_bytes
import ida_funcs
import ida_ua
import idautils
import ida_xref

from ..framework import test, assert_has_keys, get_any_function, skip_test
from ..api_functions import get_func_flags, set_func_flags


def _call_site_with_fallthrough():
    """(callee, call_ea, next_ea) where the call is followed by code in the caller."""
    for callee_ea in idautils.Functions():
        callee = ida_funcs.get_func(callee_ea)
        if callee is None or callee.flags & (
            ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK | ida_funcs.FUNC_NORET
        ):
            continue
        for xref in idautils.XrefsTo(callee_ea):
            if xref.type not in (ida_xref.fl_CN, ida_xref.fl_CF):
                continue
            caller = ida_funcs.get_func(xref.frm)
            if caller is None or caller.start_ea == callee.start_ea:
                continue
            insn = ida_ua.insn_t()
            size = ida_ua.decode_insn(insn, xref.frm)
            if size <= 0:
                continue
            next_ea = xref.frm + size
            if next_ea >= caller.end_ea:
                continue
            if ida_bytes.is_flow(ida_bytes.get_flags(next_ea)):
                return callee, xref.frm, next_ea
    return None


@test()
def test_get_func_flags_reports_named_flags():
    addr = get_any_function()
    if addr is None:
        skip_test("no functions")
    [info] = get_func_flags(addr)
    assert_has_keys(info, "start", "end", "flags", "raw")
    fn = ida_funcs.get_func(int(addr, 16))
    assert info["start"] == hex(fn.start_ea)
    assert int(info["raw"], 16) == int(fn.flags)
    assert info["flags"]["noreturn"] == bool(fn.flags & ida_funcs.FUNC_NORET)
    assert info["flags"]["lib"] == bool(fn.flags & ida_funcs.FUNC_LIB)


@test()
def test_get_func_flags_batch_reports_per_item_errors():
    addr = get_any_function()
    if addr is None:
        skip_test("no functions")
    results = get_func_flags([addr, "0xdeadbeefdead"])
    assert len(results) == 2
    assert "error" not in results[0]
    assert "error" in results[1]


@test()
def test_set_func_flags_lib_roundtrip():
    addr = get_any_function()
    if addr is None:
        skip_test("no functions")
    fn = ida_funcs.get_func(int(addr, 16))
    original = bool(fn.flags & ida_funcs.FUNC_LIB)
    try:
        [res] = set_func_flags({"addr": addr, "lib": not original})
        assert "error" not in res, res
        assert res["changed"] == ["lib"]
        assert res["before"]["lib"] is original
        assert res["after"]["lib"] is (not original)
        assert bool(ida_funcs.get_func(fn.start_ea).flags & ida_funcs.FUNC_LIB) is (not original)
        # Setting it to the same value again is a no-op.
        [again] = set_func_flags({"addr": addr, "lib": not original})
        assert again["changed"] == []
    finally:
        set_func_flags({"addr": addr, "lib": original})
    assert bool(ida_funcs.get_func(fn.start_ea).flags & ida_funcs.FUNC_LIB) is original


@test()
def test_set_func_flags_rejects_unknown_and_readonly_flags():
    addr = get_any_function()
    if addr is None:
        skip_test("no functions")
    [bad] = set_func_flags({"addr": addr, "bogus": True})
    assert "Unknown flag" in bad["error"]
    [ro] = set_func_flags({"addr": addr, "frame": True})
    assert "can't be set" in ro["error"]
    [missing] = set_func_flags({"noreturn": True})
    assert "addr" in missing["error"]


@test()
def test_set_func_flags_noreturn_rebuilds_caller_flow():
    """Marking a callee no-return must cut flow after its call sites; clearing restores it."""
    site = _call_site_with_fallthrough()
    if site is None:
        skip_test("no call site followed by code")
    callee, call_ea, next_ea = site
    addr = hex(callee.start_ea)
    try:
        [res] = set_func_flags({"addr": addr, "noreturn": True})
        assert "error" not in res, res
        assert res["changed"] == ["noreturn"]
        assert res["after"]["noreturn"] is True
        assert res["callers_reanalyzed"] >= 1
        assert not ida_bytes.is_flow(ida_bytes.get_flags(next_ea)), (
            f"code after the call at {call_ea:#x} still has flow-in"
        )

        [res] = set_func_flags({"addr": addr, "noreturn": False})
        assert res["after"]["noreturn"] is False
        assert ida_bytes.is_flow(ida_bytes.get_flags(next_ea)), (
            f"flow after the call at {call_ea:#x} was not restored"
        )
    finally:
        fn = ida_funcs.get_func(callee.start_ea)
        if fn is not None and fn.flags & ida_funcs.FUNC_NORET:
            set_func_flags({"addr": addr, "noreturn": False})


@test()
def test_func_query_reports_and_filters_flags():
    from ..api_core import func_query

    addr = get_any_function()
    if addr is None:
        skip_test("no functions")
    fn = ida_funcs.get_func(int(addr, 16))
    original = bool(fn.flags & ida_funcs.FUNC_NORET)
    try:
        set_func_flags({"addr": addr, "noreturn": True, }, reanalyze_callers=False)
        [page] = func_query({"noreturn": True, "count": 0})
        addrs = {row["addr"] for row in page["data"]}
        assert hex(fn.start_ea) in addrs
        assert all(row["noreturn"] is True for row in page["data"])
        [page] = func_query({"noreturn": False, "count": 0})
        assert hex(fn.start_ea) not in {row["addr"] for row in page["data"]}
    finally:
        set_func_flags({"addr": addr, "noreturn": original}, reanalyze_callers=False)
