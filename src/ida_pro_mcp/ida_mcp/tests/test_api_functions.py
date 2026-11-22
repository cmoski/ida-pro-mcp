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


# ---------------------------------------------------------------------------
# export_func_list / import_func_list
# ---------------------------------------------------------------------------


def _plain_function():
    """A non-thunk, non-library function that is safe to rename/comment."""
    for ea in idautils.Functions():
        fn = ida_funcs.get_func(ea)
        if fn is not None and not fn.flags & (ida_funcs.FUNC_THUNK | ida_funcs.FUNC_LIB):
            return fn
    return None


class _FuncState:
    """Snapshot/restore a function's name and comments."""

    def __init__(self, fn):
        self.ea = fn.start_ea
        self.name = ida_funcs.get_func_name(fn.start_ea)
        self.user = bool(ida_bytes.has_user_name(ida_bytes.get_flags(fn.start_ea)))
        self.cmt = ida_funcs.get_func_cmt(fn, False) or ""
        self.rcmt = ida_funcs.get_func_cmt(fn, True) or ""

    def restore(self):
        import ida_name

        fn = ida_funcs.get_func(self.ea)
        if fn is None:
            return
        ida_name.set_name(self.ea, self.name if self.user else "", ida_name.SN_NOWARN)
        ida_funcs.set_func_cmt(fn, self.cmt, False)
        ida_funcs.set_func_cmt(fn, self.rcmt, True)


def _single_entry_doc(fn, **overrides):
    from ..api_functions import export_func_list

    doc = export_func_list(ranges=f"{fn.start_ea:#x}-{fn.start_ea + 1:#x}")
    assert doc["count"] == 1, doc
    entry = dict(doc["functions"][0])
    entry.update(overrides)
    doc = dict(doc)
    doc["functions"] = [entry]
    return doc


@test()
def test_export_func_list_pages_every_function():
    from ..api_functions import export_func_list

    total = ida_funcs.get_func_qty()
    if total == 0:
        skip_test("no functions")
    seen = []
    offset = 0
    while True:
        page = export_func_list(offset=offset)
        assert page["format"] == "ida-mcp-funcs" and page["version"] == 1
        assert page["total"] == total
        seen.extend(e["start"] for e in page["functions"])
        if page["next_offset"] is None:
            break
        offset = page["next_offset"]
    assert len(seen) == total
    assert len(set(seen)) == total
    first = ida_funcs.getn_func(0)
    entry = next(e for e in export_func_list()["functions"] if e["start"] == hex(first.start_ea))
    assert entry["end"] == hex(first.end_ea)
    assert set(entry["flags"]) == {"noreturn", "thunk", "lib"}


@test()
def test_export_func_list_to_file_writes_full_document():
    import json
    import os
    import tempfile
    from ..api_functions import export_func_list

    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        summary = export_func_list(path=path)
        assert "functions" not in summary
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        assert doc["count"] == summary["count"] == ida_funcs.get_func_qty()
        assert len(doc["functions"]) == doc["count"]
    finally:
        os.unlink(path)


@test()
def test_import_func_list_roundtrip_restores_name_and_comment():
    from ..api_functions import import_func_list

    fn = _plain_function()
    if fn is None:
        skip_test("no plain function")
    state = _FuncState(fn)
    try:
        doc = _single_entry_doc(
            fn, name="mcp_sync_probe", user_name=True, comment="synced from ghidra"
        )
        result = import_func_list(data=doc, overwrite_names=True, overwrite_comments=True)
        assert result["failed"] == 0, result
        assert result["renamed"] == 1 and result["commented"] == 1, result
        assert ida_funcs.get_func_name(fn.start_ea) == "mcp_sync_probe"
        assert ida_funcs.get_func_cmt(ida_funcs.get_func(fn.start_ea), False) == "synced from ghidra"
        # Re-importing the same document changes nothing.
        again = import_func_list(data=doc)
        assert again["renamed"] == 0 and again["commented"] == 0, again
    finally:
        state.restore()


@test()
def test_import_func_list_dry_run_changes_nothing():
    from ..api_functions import import_func_list

    fn = _plain_function()
    if fn is None:
        skip_test("no plain function")
    state = _FuncState(fn)
    try:
        doc = _single_entry_doc(fn, name="mcp_dry_run_probe", user_name=True)
        result = import_func_list(data=doc, overwrite_names=True, dry_run=True)
        assert result["dry_run"] is True
        assert result["renamed"] == 1
        assert ida_funcs.get_func_name(fn.start_ea) == state.name
    finally:
        state.restore()


@test()
def test_import_func_list_keeps_user_names_unless_overwrite():
    import ida_name
    from ..api_functions import import_func_list

    fn = _plain_function()
    if fn is None:
        skip_test("no plain function")
    state = _FuncState(fn)
    try:
        assert ida_name.set_name(fn.start_ea, "mcp_user_named", ida_name.SN_NOWARN)
        doc = _single_entry_doc(fn, name="mcp_incoming_name", user_name=True)
        result = import_func_list(data=doc)
        assert result["renamed"] == 0 and result["skipped"] >= 1, result
        assert ida_funcs.get_func_name(fn.start_ea) == "mcp_user_named"
    finally:
        state.restore()


@test()
def test_import_func_list_recreates_deleted_function():
    from ..api_functions import import_func_list

    fn = _plain_function()
    if fn is None:
        skip_test("no plain function")
    start, end = fn.start_ea, fn.end_ea
    doc = _single_entry_doc(fn)
    try:
        assert ida_funcs.del_func(start)
        result = import_func_list(data=doc)
        assert result["created"] == 1, result
        again = ida_funcs.get_func(start)
        assert again is not None and again.start_ea == start and again.end_ea == end
    finally:
        if ida_funcs.get_func(start) is None:
            ida_funcs.add_func(start, end)


@test()
def test_import_func_list_rebases_by_image_base():
    from ..api_functions import import_func_list

    fn = _plain_function()
    if fn is None:
        skip_test("no plain function")
    state = _FuncState(fn)
    try:
        doc = _single_entry_doc(fn, name="mcp_rebased_probe", user_name=True)
        shift = 0x100000
        doc["image_base"] = hex(int(doc["image_base"], 16) + shift)
        entry = doc["functions"][0]
        entry["start"] = hex(int(entry["start"], 16) + shift)
        entry["end"] = hex(int(entry["end"], 16) + shift)
        result = import_func_list(data=doc, overwrite_names=True)
        assert result["delta"] == hex(-shift), result
        assert result["renamed"] == 1, result
        assert ida_funcs.get_func_name(fn.start_ea) == "mcp_rebased_probe"
    finally:
        state.restore()


@test()
def test_import_func_list_reports_errors_per_entry():
    from ..api_functions import import_func_list
    from ..sync import IDAError

    fn = _plain_function()
    if fn is None or fn.end_ea - fn.start_ea < 4:
        skip_test("no plain function")
    inside = hex(fn.start_ea + 1)
    result = import_func_list(
        data={
            "format": "ida-mcp-funcs",
            "version": 1,
            "functions": [{"start": inside}, {"end": "0x10"}],
        }
    )
    assert result["failed"] == 2, result
    assert "inside" in result["errors"][0]["error"]
    assert "start" in result["errors"][1]["error"]
    try:
        import_func_list(data={"format": "something-else", "functions": []})
        assert False, "wrong format must raise"
    except IDAError as e:
        assert "Unsupported format" in str(e)


@test(binary="thumb_fixture.elf")
def test_func_list_carries_thumb_mode():
    from ..api_functions import export_func_list, import_func_list
    from ..api_load import get_sreg, set_sreg_range

    start = 0x8010
    fn = ida_funcs.get_func(start)
    if fn is not None:
        ida_funcs.del_func(start)
    ida_bytes.del_items(start, ida_bytes.DELIT_SIMPLE, 8)
    set_sreg_range(start, 0x8018, "T", 0)
    try:
        doc = {
            "format": "ida-mcp-funcs",
            "version": 1,
            "functions": [{"start": hex(start), "end": hex(start + 4), "thumb": True}],
        }
        result = import_func_list(data=doc, rebase="none")
        assert result["failed"] == 0 and result["created"] == 1, result
        assert result["thumb_set"] == 1
        [val] = get_sreg(hex(start))
        assert val["value"] == 1
        assert ida_bytes.get_item_size(start) == 2, "not decoded as Thumb"
        exported = export_func_list(ranges=f"{start:#x}-{start + 1:#x}")
        assert exported["functions"][0]["thumb"] is True
    finally:
        if ida_funcs.get_func(start) is not None:
            ida_funcs.del_func(start)
        ida_bytes.del_items(start, ida_bytes.DELIT_SIMPLE, 8)
        set_sreg_range(start, 0x8018, "T", 0)
