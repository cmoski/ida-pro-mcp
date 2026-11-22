"""Tests for api_load: segment bitness, raw blob mapping, segment creation.

These run against a shared database, so every test that mutates layout works on
a scratch segment it creates high above the image and removes again -- the
fixture's own segments are only ever read, or re-set to the width they already
have.
"""

import os
import tempfile

import idaapi
import ida_segment

from ..framework import (
    test,
    assert_has_keys,
    assert_is_list,
    assert_valid_address,
    get_first_segment,
    skip_test,
)
from ..api_load import (
    create_segment,
    load_raw_file,
    rebase,
    set_bitness,
    _parse_bitness,
)
from ..api_memory import get_bytes
from ..sync import IDAError
from ..utils import segment_bitness

# Far above any fixture image, so scratch segments never collide with real ones.
SCRATCH_BASE = 0x7A000000
SCRATCH_BLOB = bytes((0x53, 0x66, 0x8B, 0x58, 0x2A)) + bytes(0x1B)


def _drop_segment(start_ea: int) -> None:
    seg = idaapi.getseg(start_ea)
    if seg is not None:
        ida_segment.del_segm(start_ea, ida_segment.SEGMOD_KILL)


@test()
def test_parse_bitness_accepts_loose_forms():
    """Bitness parsing takes ints and loose strings, and rejects everything else."""
    assert _parse_bitness(32) == 32
    assert _parse_bitness("32") == 32
    assert _parse_bitness("32-bit") == 32
    assert _parse_bitness(16) == 16
    assert _parse_bitness(64) == 64
    for bad in ("", "abc", 8, 128, True):
        try:
            _parse_bitness(bad)
            assert False, f"expected _parse_bitness({bad!r}) to fail"
        except IDAError as e:
            assert "bitness" in str(e).lower()


@test()
def test_set_bitness_requires_something_to_do():
    """set_bitness with neither bitness nor processor is an error, not a no-op."""
    try:
        set_bitness()
        assert False, "expected set_bitness() to fail"
    except IDAError as e:
        assert "bitness" in str(e).lower()


@test()
def test_set_bitness_to_current_width_is_a_no_op():
    """Re-setting a segment to the width it already has changes and destroys nothing."""
    seg_start, _ = get_first_segment()
    seg = idaapi.getseg(int(seg_start, 16))
    current = segment_bitness(seg)

    result = set_bitness(current, segments=seg_start)
    assert_has_keys(result, "bitness", "segments", "reanalyzed")
    assert result["bitness"] == current
    assert_is_list(result["segments"], min_length=1)
    entry = result["segments"][0]
    assert entry["changed"] is False
    assert entry["bitness"] == current
    assert entry["previous_bitness"] == current
    # Nothing changed, so nothing may have been undefined or re-analyzed.
    assert result["undefined_bytes"] == 0
    assert result["reanalyzed"] is False
    assert any("already" in note for note in result.get("notes", []))
    # The segment really is untouched.
    assert segment_bitness(idaapi.getseg(int(seg_start, 16))) == current


@test()
def test_set_bitness_reports_unresolved_segments():
    """An unknown segment token is reported per-entry, not raised."""
    result = set_bitness(32, segments="no_such_segment_xyz")
    entries = result["segments"]
    assert_is_list(entries, min_length=1)
    assert entries[0]["name"] == "no_such_segment_xyz"
    assert "No segment matches" in entries[0]["error"]
    assert result["reanalyzed"] is False


@test()
def test_create_segment_round_trip():
    """create_segment makes a BSS range with the requested width and permissions."""
    _drop_segment(SCRATCH_BASE)
    try:
        result = create_segment(
            start=hex(SCRATCH_BASE),
            size=0x1000,
            name="mcp_scratch_bss",
            sclass="BSS",
            bitness=32,
            permissions="rw",
        )
        assert_valid_address(result["start"])
        assert result["size"] == 0x1000
        assert result["end"] == hex(SCRATCH_BASE + 0x1000)

        seg = idaapi.getseg(SCRATCH_BASE)
        assert seg is not None, "segment was not created"
        assert ida_segment.get_segm_name(seg) == "mcp_scratch_bss"
        assert segment_bitness(seg) == 32
        assert seg.perm & idaapi.SEGPERM_READ
        assert seg.perm & idaapi.SEGPERM_WRITE
        assert not seg.perm & idaapi.SEGPERM_EXEC

        # A second segment over the same range is refused rather than silently
        # truncating the first (add_segm would happily do that).
        try:
            create_segment(start=hex(SCRATCH_BASE + 0x800), size=0x100)
            assert False, "expected overlapping create_segment to fail"
        except IDAError as e:
            assert "overlap" in str(e).lower()
    finally:
        _drop_segment(SCRATCH_BASE)
    assert idaapi.getseg(SCRATCH_BASE) is None


@test()
def test_set_bitness_flips_a_scratch_segment():
    """Bitness really changes, both directions, on a segment we own."""
    _drop_segment(SCRATCH_BASE)
    try:
        create_segment(
            start=hex(SCRATCH_BASE), size=0x1000, name="mcp_scratch_bits", bitness=32
        )
        assert segment_bitness(idaapi.getseg(SCRATCH_BASE)) == 32

        up = set_bitness(
            64, segments="mcp_scratch_bits", undefine=False, reanalyze=False
        )
        entry = up["segments"][0]
        assert entry["previous_bitness"] == 32
        assert entry["bitness"] == 64
        assert entry["changed"] is True
        assert segment_bitness(idaapi.getseg(SCRATCH_BASE)) == 64

        down = set_bitness(
            16, segments=hex(SCRATCH_BASE), undefine=False, reanalyze=False
        )
        assert down["segments"][0]["bitness"] == 16
        assert segment_bitness(idaapi.getseg(SCRATCH_BASE)) == 16
        # A scoped call must not touch the database-wide bitness.
        assert "app_bitness" not in down
    finally:
        _drop_segment(SCRATCH_BASE)


@test()
def test_load_raw_file_maps_bytes_at_base():
    """A headerless blob maps at the requested base and reads back byte for byte."""
    _drop_segment(SCRATCH_BASE)
    fd, blob_path = tempfile.mkstemp(suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(SCRATCH_BLOB)

        result = load_raw_file(
            path=blob_path,
            base=hex(SCRATCH_BASE),
            bitness=32,
            segment_name="mcp_scratch_raw",
            reanalyze=False,
        )
        assert result["size"] == len(SCRATCH_BLOB)
        assert result["base"] == hex(SCRATCH_BASE)
        assert_is_list(result["segments"], min_length=1)
        assert result["segments"][0]["name"] == "mcp_scratch_raw"
        assert result["segments"][0]["bitness"] == 32

        read = get_bytes({"addr": hex(SCRATCH_BASE), "size": 5})
        assert read[0]["data"] == "0x53 0x66 0x8b 0x58 0x2a"

        # Mapping over an existing segment is refused.
        try:
            load_raw_file(path=blob_path, base=hex(SCRATCH_BASE), reanalyze=False)
            assert False, "expected overlapping load_raw_file to fail"
        except IDAError as e:
            assert "overlap" in str(e).lower()

        # A file_offset past the end of the file is refused too.
        try:
            load_raw_file(
                path=blob_path,
                base=hex(SCRATCH_BASE + 0x10000),
                file_offset=len(SCRATCH_BLOB) + 1,
                reanalyze=False,
            )
            assert False, "expected out-of-range file_offset to fail"
        except IDAError as e:
            assert "file_offset" in str(e)
    finally:
        _drop_segment(SCRATCH_BASE)
        os.unlink(blob_path)


@test()
def test_load_raw_file_rejects_missing_path():
    """A path that isn't there fails before IDA is asked to do anything."""
    try:
        load_raw_file(path="no_such_blob_xyz.bin", base=hex(SCRATCH_BASE))
        assert False, "expected load_raw_file to fail on a missing file"
    except IDAError as e:
        assert "not found" in str(e).lower()


@test()
def test_rebase_round_trip():
    """rebase moves every segment by the delta and back again, bytes following."""
    original = ida_segment.getnseg(0).start_ea
    probe_offset = 0x40
    before = get_bytes({"addr": hex(original + probe_offset), "size": 8})[0]["data"]

    moved = rebase(delta=0x100000)
    try:
        assert moved["delta"] == 0x100000
        assert moved["image_base"] == hex(original + 0x100000)
        assert ida_segment.getnseg(0).start_ea == original + 0x100000
        after = get_bytes(
            {"addr": hex(original + 0x100000 + probe_offset), "size": 8}
        )[0]["data"]
        assert after == before, "bytes did not move with the segment"
    finally:
        back = rebase(new_base=hex(original))
        assert back["image_base"] == hex(original)
        assert ida_segment.getnseg(0).start_ea == original

    noop = rebase(new_base=hex(original))
    assert noop["delta"] == 0
    assert any("Already at that base" in note for note in noop.get("notes", []))

    try:
        rebase()
        assert False, "expected rebase() with no target to fail"
    except IDAError as e:
        assert "new_base" in str(e)


@test()
def test_segment_views_report_bitness():
    """The segment resource and survey both expose the width set_bitness changes."""
    from ..api_resources import idb_segments_resource
    from ..api_survey import _build_segments

    for entry in idb_segments_resource():
        assert entry["bitness"] in (16, 32, 64)
    for entry in _build_segments():
        assert entry["bitness"] in (16, 32, 64)


@test()
def test_survey_binary_output_is_schema_valid():
    """Regression: survey segments carry ``bitness``, so the published
    outputSchema must allow it (it once rejected it as an additional property)."""
    try:
        from jsonschema import Draft202012Validator
    except Exception:
        skip_test("jsonschema not installed")
    from ..rpc import MCP_SERVER
    from ..api_survey import survey_binary

    schema = MCP_SERVER._generate_tool_schema(
        "survey_binary", MCP_SERVER.tools.methods["survey_binary"]
    ).get("outputSchema")
    assert schema is not None, "survey_binary has no outputSchema"
    Draft202012Validator(schema).validate(survey_binary(detail_level="minimal"))


@test()
def test_decompile_explains_16bit_failure():
    """Hex-Rays can't decompile real-mode code; the error must say why instead of
    a bare 'Decompilation failed'."""
    import ida_bytes
    import ida_funcs
    import ida_idp
    from ..api_analysis import decompile

    if ida_idp.ph_get_id() != ida_idp.PLFM_386:
        skip_test("real-mode scratch code is x86-specific")
    _drop_segment(SCRATCH_BASE)
    try:
        create_segment(
            start=hex(SCRATCH_BASE), size=0x100, name="mcp_scratch_16", bitness=16
        )
        ida_bytes.patch_bytes(SCRATCH_BASE, bytes((0x55, 0x8B, 0xEC, 0x5D, 0xC3)))
        idaapi.create_insn(SCRATCH_BASE)
        assert ida_funcs.add_func(SCRATCH_BASE), "could not create scratch function"

        [result] = decompile(hex(SCRATCH_BASE))
        assert result["code"] is None
        assert "16-bit" in result["error"], result
        assert "disassemble_function" in result["error"]
    finally:
        _drop_segment(SCRATCH_BASE)


# ---------------------------------------------------------------------------
# analyze / plan_and_wait
# ---------------------------------------------------------------------------


def _called_function():
    """(callee_func, caller_func) for some direct call inside the image, or None."""
    import ida_funcs
    import idautils
    import ida_xref

    for callee_ea in idautils.Functions():
        callee = ida_funcs.get_func(callee_ea)
        if callee is None or callee.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK):
            continue
        for xref in idautils.XrefsTo(callee_ea):
            if xref.type not in (ida_xref.fl_CN, ida_xref.fl_CF):
                continue
            caller = ida_funcs.get_func(xref.frm)
            if caller is not None and caller.start_ea != callee.start_ea:
                return callee, caller
    return None


@test()
def test_analyze_wait_mode_is_a_quiet_no_op():
    from ..api_load import analyze

    result = analyze(mode="wait")
    assert_has_keys(result, "ms", "funcs_before", "funcs_after", "auto_is_ok", "cancelled")
    assert result["queued_ranges"] == []
    assert result["cancelled"] is False
    assert result["auto_is_ok"] is True
    assert result["funcs_after"] == result["funcs_before"]


@test()
def test_analyze_rejects_bad_input():
    from ..api_load import analyze

    try:
        analyze(mode="nope")
        assert False, "invalid mode must raise"
    except IDAError as e:
        assert "mode" in str(e)
    try:
        analyze(ranges="0x2000-0x1000")
        assert False, "inverted range must raise"
    except IDAError as e:
        assert "inverted" in str(e).lower()


@test()
def test_analyze_parses_size_ranges():
    from ..api_load import _parse_range_token

    assert _parse_range_token("0x1000:0x20") == (0x1000, 0x1020)
    assert _parse_range_token("0x1000-0x1020") == (0x1000, 0x1020)
    assert _parse_range_token(".text") is None


@test()
def test_analyze_runs_even_when_auto_analysis_is_disabled():
    """The 1 ms warmup bug: with analysis off, a bare auto_wait did nothing.

    Delete a called function, disable auto-analysis, then analyze the caller:
    re-planning the call site must recreate the callee, and the previous
    (disabled) analyzer state must be restored afterwards.
    """
    import ida_auto
    import ida_funcs
    from ..api_load import analyze

    pair = _called_function()
    if pair is None:
        skip_test("no direct call between two functions in this binary")
    callee, caller = pair
    start, end = callee.start_ea, callee.end_ea
    caller_range = f"{caller.start_ea:#x}-{caller.end_ea:#x}"

    was_enabled = ida_auto.is_auto_enabled()
    try:
        assert ida_funcs.del_func(start)
        assert ida_funcs.get_func(start) is None
        ida_auto.enable_auto(False)

        result = analyze(ranges=caller_range)

        assert result["auto_was_enabled"] is False
        assert any("disabled" in n for n in result.get("notes", []))
        assert ida_auto.is_auto_enabled() is False, "previous state not restored"
        assert result["cancelled"] is False
        recreated = ida_funcs.get_func(start)
        assert recreated is not None, "callee was not recreated by analysis"
        assert recreated.start_ea == start
        assert result["funcs_after"] == result["funcs_before"] + 1
    finally:
        ida_auto.enable_auto(was_enabled)
        if ida_funcs.get_func(start) is None:
            ida_funcs.add_func(start, end)


@test()
def test_server_warmup_reports_skipped_wait_when_auto_disabled():
    import ida_auto
    from ..api_core import server_warmup

    was_enabled = ida_auto.is_auto_enabled()
    try:
        ida_auto.enable_auto(False)
        result = server_warmup(wait_auto_analysis=True, build_caches=False, init_hexrays=False)
        step = next(s for s in result["steps"] if s["step"] == "auto_wait")
        assert "disabled" in step.get("skipped", ""), step
    finally:
        ida_auto.enable_auto(was_enabled)


# ---------------------------------------------------------------------------
# Segment registers / Thumb (semantic checks need tests/thumb_fixture.elf)
# ---------------------------------------------------------------------------

THUMB_START = 0x8010  # movs r0,#1 / bx lr / nop / nop
THUMB_END = 0x8018  # ARM code resumes here


def _reset_thumb_region():
    import ida_bytes
    import ida_funcs
    from ..api_load import set_sreg_range

    fn = ida_funcs.get_func(THUMB_START)
    if fn is not None:
        ida_funcs.del_func(fn.start_ea)
    ida_bytes.del_items(THUMB_START, ida_bytes.DELIT_SIMPLE, THUMB_END - THUMB_START)
    set_sreg_range(THUMB_START, THUMB_END, "T", 0)


@test()
def test_set_sreg_thumb_rejected_off_arm():
    import ida_idp
    from ..api_load import set_sreg

    if ida_idp.ph_get_id() == ida_idp.PLFM_ARM:
        skip_test("ARM database")
    seg = get_first_segment()
    if seg is None:
        skip_test("no segments")
    [res] = set_sreg({"start": seg[0], "size": 4, "reg": "T", "value": 1}, reanalyze=False)
    assert "32-bit ARM" in res["error"], res


@test()
def test_get_sreg_unknown_register_reports_error():
    from ..api_load import get_sreg

    addr = get_first_segment()
    if addr is None:
        skip_test("no segments")
    [res] = get_sreg(addr[0], reg="NOSUCHREG")
    assert "no segment register" in res["error"]


@test(binary="thumb_fixture.elf")
def test_set_sreg_switches_decoding_between_arm_and_thumb():
    import ida_bytes
    import idc
    from ..api_load import get_sreg, set_sreg

    span = {"start": hex(THUMB_START), "end": hex(THUMB_END)}
    try:
        [arm] = set_sreg({**span, "value": 0}, undefine=True)
        assert "error" not in arm, arm
        assert ida_bytes.get_item_size(THUMB_START) == 4, (
            f"ARM mode should give a 4-byte insn: {idc.GetDisasm(THUMB_START)!r}"
        )

        [thumb] = set_sreg({**span, "value": 1}, undefine=True)
        assert "error" not in thumb, thumb
        assert thumb["previous"] == 0
        values = {r["addr"]: r["value"] for r in get_sreg([hex(THUMB_START), hex(THUMB_END)])}
        assert values[hex(THUMB_START)] == 1
        assert values[hex(THUMB_END)] == 0, "Thumb leaked past the range end"
        assert ida_bytes.get_item_size(THUMB_START) == 2, (
            f"Thumb mode should give a 2-byte insn: {idc.GetDisasm(THUMB_START)!r}"
        )
        assert "BX" in idc.GetDisasm(THUMB_START + 2).upper(), idc.GetDisasm(THUMB_START + 2)
        assert "MOVS" in thumb["insn"].upper(), thumb["insn"]
    finally:
        _reset_thumb_region()


@test(binary="thumb_fixture.elf")
def test_define_func_thumb_infers_bounds_in_thumb_mode():
    import ida_funcs
    from ..api_load import get_sreg
    from ..api_modify import define_func

    _reset_thumb_region()
    try:
        [res] = define_func({"addr": hex(THUMB_START), "thumb": True})
        assert "error" not in res, res
        fn = ida_funcs.get_func(THUMB_START)
        assert fn is not None
        # movs r0,#1 ; bx lr -> the function ends right after the 2-byte bx lr.
        assert fn.end_ea == THUMB_START + 4, hex(fn.end_ea)
        values = {r["addr"]: r["value"] for r in get_sreg([hex(THUMB_START), hex(fn.end_ea)])}
        assert values[hex(THUMB_START)] == 1
        assert values[hex(fn.end_ea)] == 0, "Thumb mode leaked past the function"
    finally:
        _reset_thumb_region()
