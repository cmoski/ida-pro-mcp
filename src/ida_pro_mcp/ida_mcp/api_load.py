"""Load-layout controls: segment bitness, processor type, raw blob mapping.

IDA decides addressing width and processor module when the input file is loaded,
and idalib gives us no usable way to influence that: ``idapro.open_database()``
accepts an ``args`` string documented to take IDA command-line switches, but any
non-empty value aborts the process with IDA internal error 30602 (tested on IDA
9.1). So load options have to be repaired after the database is open, which is
what :func:`set_bitness` does — a headerless blob that the binary loader mapped
as flat 64-bit becomes a 32-bit image in one call.

:func:`load_raw_file` covers the other half of the problem: mapping a headerless
``.bin`` (an extracted overlay, a dumped image, an extender payload) at a chosen
base into the database that is already open. IDA picks its loader from file
content, so a blob whose header it recognizes cannot be forced to load raw at
open time; mapping it explicitly here is the way around that.

:func:`create_segment` and :func:`rebase` cover the remaining load-time
decisions -- a range the input file has no bytes for, and the address the image
was loaded at.
"""

import os
import time

from typing import Annotated, NotRequired, TypedDict

import idaapi
import idautils
import ida_auto
import ida_bytes
import ida_diskio
import ida_funcs
import ida_ida
import ida_kernwin
import ida_idp
import ida_loader
import ida_segment
import ida_segregs
import idc

from .rpc import tool
from .sync import idasync, tool_timeout, IDAError
from .utils import (
    BITNESS_CODE as _BITNESS_CODE,
    normalize_list_input,
    parse_address,
    segment_bitness,
)


class SegmentBitness(TypedDict):
    name: str
    start: NotRequired[str]
    end: NotRequired[str]
    bitness: NotRequired[int]
    previous_bitness: NotRequired[int]
    changed: NotRequired[bool]
    error: NotRequired[str]


class SetBitnessResult(TypedDict):
    # None when only a processor switch was requested.
    bitness: int | None
    segments: list[SegmentBitness]
    app_bitness: NotRequired[int]
    processor: NotRequired[str]
    undefined_bytes: NotRequired[int]
    reanalyzed: bool
    notes: NotRequired[list[str]]


class LoadRawResult(TypedDict):
    path: str
    base: str
    size: int
    segments: list[SegmentBitness]
    reanalyzed: bool
    notes: NotRequired[list[str]]


class CreateSegmentResult(TypedDict):
    start: str
    end: str
    size: int
    segments: list[SegmentBitness]
    notes: NotRequired[list[str]]


def _parse_bitness(value: int | str) -> int:
    """Accept 16/32/64 as int or in loose string forms ("32", "32-bit", "b64")."""
    if isinstance(value, bool):
        raise IDAError(f"Invalid bitness: {value!r} (expected 16, 32 or 64)")
    if isinstance(value, int):
        bits = value
    else:
        digits = "".join(ch for ch in str(value) if ch.isdigit())
        if not digits:
            raise IDAError(f"Invalid bitness: {value!r} (expected 16, 32 or 64)")
        bits = int(digits)
    if bits not in _BITNESS_CODE:
        raise IDAError(f"Invalid bitness: {value!r} (expected 16, 32 or 64)")
    return bits


def _segment_state(seg) -> SegmentBitness:
    return {
        "name": ida_segment.get_segm_name(seg),
        "start": hex(seg.start_ea),
        "end": hex(seg.end_ea),
        "bitness": segment_bitness(seg),
    }


def _resolve_segments(
    spec: str | list[str] | None,
) -> tuple[list, list[SegmentBitness]]:
    """Resolve a segment spec to segment objects, reporting unresolved tokens.

    ``None`` means every segment. Tokens are matched as segment names first, then
    as addresses, so both "seg000" and "0x401000" select a segment.
    """
    if spec is None:
        return [idaapi.getseg(ea) for ea in idautils.Segments()], []

    segments: list = []
    errors: list[SegmentBitness] = []
    seen: set[int] = set()
    for token in normalize_list_input(spec):
        text = str(token)
        seg = ida_segment.get_segm_by_name(text)
        if seg is None:
            try:
                seg = idaapi.getseg(parse_address(text))
            except Exception:
                seg = None
        if seg is None:
            errors.append({"name": text, "error": f"No segment matches: {text}"})
            continue
        if seg.start_ea in seen:
            continue
        seen.add(seg.start_ea)
        segments.append(seg)
    return segments, errors


def _all_segments() -> list:
    return [idaapi.getseg(ea) for ea in idautils.Segments()]


def _has_code(start_ea: int, end_ea: int) -> bool:
    """True if any item in [start_ea, end_ea) is decoded as code."""
    found = ida_bytes.next_that(start_ea - 1, end_ea, lambda flags: ida_bytes.is_code(flags))
    return found != idaapi.BADADDR and found < end_ea


def _set_app_bitness(bits: int) -> bool:
    """Set the database-wide application bitness, if this IDA exposes a setter."""
    setter = getattr(ida_ida, "inf_set_app_bitness", None) or getattr(
        idaapi, "inf_set_app_bitness", None
    )
    if setter is None:
        return False
    setter(bits)
    return True


def _apply_addressing(segments: list, bits: int) -> list[SegmentBitness]:
    code = _BITNESS_CODE[bits]
    results: list[SegmentBitness] = []
    for seg in segments:
        entry = _segment_state(seg)
        previous = entry["bitness"]
        entry["previous_bitness"] = previous
        if previous == bits:
            entry["changed"] = False
            results.append(entry)
            continue
        if not ida_segment.set_segm_addressing(seg, code):
            entry["changed"] = False
            entry["error"] = f"set_segm_addressing({bits}) failed"
            results.append(entry)
            continue
        refreshed = idaapi.getseg(seg.start_ea) or seg
        entry["bitness"] = segment_bitness(refreshed)
        entry["changed"] = entry["bitness"] == bits
        if not entry["changed"]:
            entry["error"] = (
                f"segment stayed at {entry['bitness']}-bit after set_segm_addressing"
            )
        results.append(entry)
    return results


class AnalyzeRange(TypedDict):
    start: str
    end: str
    name: NotRequired[str]


class AnalyzeResult(TypedDict):
    mode: str
    ms: float
    queued_ranges: list[AnalyzeRange]
    auto_was_enabled: bool
    auto_is_ok: bool
    cancelled: bool
    funcs_before: int
    funcs_after: int
    errors: NotRequired[list[str]]
    notes: NotRequired[list[str]]


def plan_and_wait(ranges: list[tuple[int, int]]) -> dict:
    """Queue ``ranges`` for re-analysis and block until the auto-analyzer is idle.

    ``ida_auto.auto_wait()`` alone only drains work that is already queued, and
    returns at once when auto-analysis is disabled (idalib opened with
    run_auto_analysis=False) -- which is why a bare wait could "finish" in 1 ms
    having analyzed nothing. This enables the analyzer for the duration, queues
    each range with ``plan_range``, waits, then restores the previous enabled
    state. Shared by analyze, set_bitness, load_raw_file and function import.
    """
    was_enabled = bool(ida_auto.is_auto_enabled())
    ida_auto.enable_auto(True)
    funcs_before = ida_funcs.get_func_qty()
    t0 = time.perf_counter()
    completed = None
    try:
        for start, end in ranges:
            if end > start:
                ida_auto.plan_range(start, end)
        completed = ida_auto.auto_wait()
    finally:
        if not was_enabled:
            ida_auto.enable_auto(False)
    cancelled = (completed is False) or bool(ida_kernwin.user_cancelled())
    return {
        "ms": round((time.perf_counter() - t0) * 1000, 2),
        "auto_was_enabled": was_enabled,
        "auto_is_ok": bool(ida_auto.auto_is_ok()),
        "cancelled": cancelled,
        "funcs_before": funcs_before,
        "funcs_after": ida_funcs.get_func_qty(),
    }


def _parse_range_token(token: str) -> tuple[int, int] | None:
    """Parse 'start-end' or 'start:size' (hex/dec/symbols). None if not a range."""
    text = token.strip()
    for sep, is_size in (("-", False), (":", True)):
        if sep in text[1:]:
            left, right = text.split(sep, 1)
            try:
                start = parse_address(left.strip())
                rhs = parse_address(right.strip())
            except Exception:
                continue
            end = start + rhs if is_size else rhs
            if end <= start:
                raise IDAError(f"Empty or inverted range: {token}")
            return start, end
    return None


def _segment_span(seg) -> AnalyzeRange:
    return {
        "start": hex(seg.start_ea),
        "end": hex(seg.end_ea),
        "name": ida_segment.get_segm_name(seg),
    }


@tool
@idasync
@tool_timeout(600.0)
def analyze(
    ranges: Annotated[
        list[str] | str | None,
        "What to (re)analyze: 'start-end', 'start:size', segment names or "
        "addresses (selects their segment). Omit for every segment.",
    ] = None,
    mode: Annotated[
        str,
        "'plan' (default): queue the ranges, then wait. 'wait': queue nothing, "
        "just drain pending analysis.",
    ] = "plan",
) -> AnalyzeResult:
    """Run auto-analysis and block until it finishes, even if analysis was off.

    Reports elapsed ms, function counts before/after, and whether the wait was
    cancelled by the tool deadline. For whole-database runs on large binaries,
    wrap in submit_job to avoid client timeouts.
    """
    mode = (mode or "plan").lower()
    if mode not in ("plan", "wait"):
        raise IDAError(f"mode must be 'plan' or 'wait', got {mode!r}")

    queued: list[AnalyzeRange] = []
    spans: list[tuple[int, int]] = []
    errors: list[str] = []
    if mode == "plan":
        if ranges is None:
            for seg in _all_segments():
                spans.append((seg.start_ea, seg.end_ea))
                queued.append(_segment_span(seg))
        else:
            for token in normalize_list_input(ranges):
                text = str(token)
                try:
                    span = _parse_range_token(text)
                except IDAError as e:
                    errors.append(str(e))
                    continue
                if span is not None:
                    spans.append(span)
                    queued.append({"start": hex(span[0]), "end": hex(span[1])})
                    continue
                segs, seg_errors = _resolve_segments(text)
                errors.extend(e["error"] for e in seg_errors if "error" in e)
                for seg in segs:
                    spans.append((seg.start_ea, seg.end_ea))
                    queued.append(_segment_span(seg))
        if not spans:
            raise IDAError("Nothing to analyze: " + ("; ".join(errors) or "no ranges"))

    stats = plan_and_wait(spans)
    result: AnalyzeResult = {"mode": mode, "queued_ranges": queued, **stats}
    notes: list[str] = []
    if not stats["auto_was_enabled"]:
        notes.append(
            "Auto-analysis was disabled (database opened without analysis); it was "
            "enabled for this call and disabled again afterwards."
        )
    if stats["cancelled"]:
        notes.append(
            "Analysis was interrupted (tool deadline or cancel) and may be "
            "incomplete; call analyze(mode='wait') to finish, or run via submit_job."
        )
    if errors:
        result["errors"] = errors
    if notes:
        result["notes"] = notes
    return result


def _load_fixup(
    bits: int | None,
    segments: str | list[str] | None,
    processor: str | None,
    undefine: bool,
    reanalyze: bool,
) -> SetBitnessResult:
    """Apply a bitness and/or processor correction to an already-open database.

    ``bits`` of None leaves segment addressing alone, which is how a
    processor-only fixup is expressed.
    """
    targets, errors = _resolve_segments(segments)
    notes: list[str] = []

    processor_applied = False
    if processor:
        # Non-fatal mode matters: SETPROC_LOADER on an unknown processor name is
        # a fatal error inside IDA, which would take the whole worker down.
        mode = getattr(
            ida_idp, "SETPROC_LOADER_NON_FATAL", getattr(ida_idp, "SETPROC_LOADER", 0)
        )
        try:
            processor_applied = bool(ida_idp.set_processor_type(processor, mode))
            if not processor_applied:
                notes.append(f"set_processor_type({processor!r}) was rejected")
        except Exception as e:
            notes.append(f"set_processor_type({processor!r}) failed: {e}")

    if bits is None:
        applied = [_segment_state(seg) for seg in targets]
        # A processor switch needs the same undefine/re-analyze treatment as a
        # width change for the new module's decoder to be used.
        changed = list(targets) if processor_applied else []
    else:
        applied = _apply_addressing(targets, bits)
        changed = [seg for seg, entry in zip(targets, applied) if entry.get("changed")]
        if processor_applied:
            changed = list(targets)
    results = applied + errors

    undefined_bytes = 0
    if undefine and changed:
        for seg in changed:
            size = seg.end_ea - seg.start_ea
            if ida_bytes.del_items(seg.start_ea, ida_bytes.DELIT_EXPAND, size):
                undefined_bytes += size

    reanalyzed = False
    if reanalyze and changed:
        plan_and_wait([(seg.start_ea, seg.end_ea) for seg in changed])
        reanalyzed = True
        # Re-read state after analysis so the caller sees the settled bitness.
        for entry in results:
            start = entry.get("start")
            if not start:
                continue
            seg = idaapi.getseg(int(start, 16))
            if seg is not None:
                entry["bitness"] = segment_bitness(seg)
        # Only worth saying for segments that could hold code: a data or BSS
        # segment having no code after the change is not news.
        data_types = {
            getattr(idaapi, name)
            for name in ("SEG_DATA", "SEG_BSS", "SEG_XTRN", "SEG_NULL")
            if hasattr(idaapi, name)
        }
        codeless = [
            ida_segment.get_segm_name(seg)
            for seg in changed
            if seg.type not in data_types and not _has_code(seg.start_ea, seg.end_ea)
        ]
        if codeless:
            notes.append(
                f"No code in {', '.join(codeless)} after re-analysis. That is "
                f"expected for a raw image: with the old instructions undefined "
                f"there are no references for auto-analysis to follow. Call "
                f"define_code or define_func at a known entry point to seed it."
            )

    result: SetBitnessResult = {
        "bitness": bits,
        "segments": results,
        "reanalyzed": reanalyzed,
    }
    if undefine:
        result["undefined_bytes"] = undefined_bytes
    if processor:
        result["processor"] = processor
    if bits is not None and segments is None:
        if _set_app_bitness(bits):
            result["app_bitness"] = bits
        else:
            notes.append(
                "This IDA build exposes no inf_set_app_bitness; segment "
                "addressing was changed but the database-wide bitness was not."
            )
    if bits is not None and not changed and not errors:
        notes.append(f"All targeted segments were already {bits}-bit.")
    if notes:
        result["notes"] = notes
    return result


@tool
@idasync
@tool_timeout(240.0)
def set_bitness(
    bitness: Annotated[
        int | str | None,
        "Target addressing width: 16, 32 or 64. Omit to leave the width alone "
        "and only switch processor.",
    ] = None,
    segments: Annotated[
        str | list[str] | None,
        "Segments to change: names (seg000) or addresses (0x401000), "
        "comma-separated string or list. Omit to change every segment and the "
        "database-wide application bitness.",
    ] = None,
    processor: Annotated[
        str | None,
        "Optional processor module to switch to (metapc, arm, mips, ...). "
        "Applied non-fatally: an unknown name is reported, not fatal.",
    ] = None,
    undefine: Annotated[
        bool,
        "Undefine existing items in the affected segments first. Required for "
        "code decoded at the old width to be re-decoded, and destroys "
        "instruction-level analysis in those segments.",
    ] = True,
    reanalyze: Annotated[
        bool, "Queue the affected segments for auto-analysis and wait for it"
    ] = True,
) -> SetBitnessResult:
    """Change the addressing width (16/32/64-bit) of segments already loaded.

    IDA fixes bitness at load time and idalib cannot pass load options, so this
    is how a mis-detected image gets corrected — e.g. a raw 32-bit protected
    mode blob that the binary loader mapped as flat 64-bit. By default every
    segment is changed, existing items in them are undefined, and the ranges are
    re-analyzed, so one call leaves a correctly disassembled database.
    """
    if bitness is None and not processor:
        raise IDAError("set_bitness needs a bitness, a processor, or both")
    bits = _parse_bitness(bitness) if bitness is not None else None
    return _load_fixup(bits, segments, processor, undefine, reanalyze)


@tool
@idasync
@tool_timeout(240.0)
def load_raw_file(
    path: Annotated[str, "Path to the raw binary blob to map into the database"],
    base: Annotated[str | int, "Load address for the blob (e.g. 0x500000)"],
    bitness: Annotated[
        int | str | None,
        "Addressing width for the created segment(s): 16, 32 or 64. "
        "Omit to keep whatever IDA assigns.",
    ] = None,
    file_offset: Annotated[str | int, "Offset within the file to start reading"] = 0,
    size: Annotated[
        str | int, "Number of bytes to load; 0 means to the end of the file"
    ] = 0,
    segment_name: Annotated[
        str | None, "Rename the created segment to this name"
    ] = None,
    as_code: Annotated[bool, "Create the segment as a code segment"] = False,
    reanalyze: Annotated[
        bool, "Queue the mapped range for auto-analysis and wait for it"
    ] = True,
) -> LoadRawResult:
    """Map a headerless binary blob into the open database at a chosen address.

    Use this for content IDA will not load raw on its own: an extracted overlay,
    a dumped image, or a second blob that belongs beside the main input. The blob
    is mapped as a new segment; existing segments are never overwritten (an
    overlapping base is rejected).
    """
    file_path = os.path.abspath(os.path.expanduser(str(path)))
    if not os.path.isfile(file_path):
        raise IDAError(f"File not found: {file_path}")

    base_ea = parse_address(base) if isinstance(base, str) else int(base)
    offset = parse_address(file_offset) if isinstance(file_offset, str) else int(file_offset)
    nbytes = parse_address(size) if isinstance(size, str) else int(size)

    file_size = os.path.getsize(file_path)
    if offset < 0 or offset >= file_size:
        raise IDAError(
            f"file_offset {offset:#x} is outside {os.path.basename(file_path)} "
            f"(size {file_size:#x})"
        )
    available = file_size - offset
    if nbytes <= 0:
        nbytes = available
    elif nbytes > available:
        raise IDAError(
            f"size {nbytes:#x} exceeds the {available:#x} bytes available at "
            f"file_offset {offset:#x}"
        )

    end_ea = base_ea + nbytes
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg is None:
            continue
        if base_ea < seg.end_ea and seg.start_ea < end_ea:
            raise IDAError(
                f"Target range {base_ea:#x}-{end_ea:#x} overlaps existing segment "
                f"{ida_segment.get_segm_name(seg)} "
                f"({seg.start_ea:#x}-{seg.end_ea:#x})"
            )

    before = {seg_ea for seg_ea in idautils.Segments()}
    flags = ida_loader.NEF_SEGS
    if as_code:
        flags |= ida_loader.NEF_CODE
    if not before:
        # An empty database means this blob is the primary input.
        flags |= ida_loader.NEF_FIRST

    li = ida_diskio.open_linput(file_path, False)
    if not li:
        raise IDAError(f"Could not open {file_path} as loader input")
    try:
        ok = ida_loader.load_binary_file(
            file_path, li, flags, offset, base_ea >> 4, base_ea & 0xF, nbytes
        )
    finally:
        ida_diskio.close_linput(li)
    if not ok:
        raise IDAError(f"load_binary_file failed for {file_path}")

    created = [
        idaapi.getseg(seg_ea)
        for seg_ea in idautils.Segments()
        if seg_ea not in before
    ]
    created = [seg for seg in created if seg is not None]
    notes: list[str] = []

    if segment_name:
        if len(created) == 1:
            if not ida_segment.set_segm_name(created[0], segment_name):
                notes.append(f"Could not rename segment to {segment_name!r}")
        elif created:
            notes.append(
                f"{len(created)} segments were created; segment_name was ignored."
            )

    if bitness is not None and created:
        segment_states = _apply_addressing(created, _parse_bitness(bitness))
    else:
        segment_states = [_segment_state(seg) for seg in created]

    reanalyzed = False
    if reanalyze and created:
        plan_and_wait([(seg.start_ea, seg.end_ea) for seg in created])
        reanalyzed = True

    if not created:
        notes.append(
            "load_binary_file reported success but created no new segment; the "
            "bytes may have been merged into an existing one."
        )

    result: LoadRawResult = {
        "path": file_path,
        "base": hex(base_ea),
        "size": nbytes,
        "segments": segment_states,
        "reanalyzed": reanalyzed,
    }
    if notes:
        result["notes"] = notes
    return result
_SEGMENT_CLASSES = ("CODE", "DATA", "BSS", "CONST", "STACK", "XTRN")


@tool
@idasync
def create_segment(
    start: Annotated[str | int, "Start address of the new segment (0x600000)"],
    end: Annotated[
        str | int | None, "End address (exclusive). Give this or size."
    ] = None,
    size: Annotated[str | int | None, "Size in bytes. Give this or end."] = None,
    name: Annotated[str | None, "Segment name (defaults to IDA's seg### naming)"] = None,
    sclass: Annotated[
        str,
        "Segment class: BSS, DATA, CODE, CONST, STACK or XTRN. BSS is the right "
        "one for a zero-initialized range that has no bytes in the file.",
    ] = "BSS",
    bitness: Annotated[
        int | str | None,
        "Addressing width for the segment: 16, 32 or 64. Defaults to the "
        "database default.",
    ] = None,
    permissions: Annotated[
        str | None, "Permission string such as 'rw' or 'rx'; omit to leave unset"
    ] = None,
) -> CreateSegmentResult:
    """Create an empty segment, e.g. a BSS range the input file does not contain.

    Real uninitialized ranges (BSS, heap windows, a bank IDA never mapped) are
    better modelled as a segment than as zero padding appended to the input
    file: cross-references and data definitions land in the right place and the
    bytes stay marked uninitialized.
    """
    start_ea = parse_address(start) if isinstance(start, str) else int(start)
    if end is not None:
        end_ea = parse_address(end) if isinstance(end, str) else int(end)
    elif size is not None:
        nbytes = parse_address(size) if isinstance(size, str) else int(size)
        end_ea = start_ea + nbytes
    else:
        raise IDAError("create_segment needs either end or size")
    if end_ea <= start_ea:
        raise IDAError(f"Empty range: {start_ea:#x}-{end_ea:#x}")

    seg_class = str(sclass).upper()
    if seg_class not in _SEGMENT_CLASSES:
        raise IDAError(
            f"Unknown segment class {sclass!r}; expected one of "
            f"{', '.join(_SEGMENT_CLASSES)}"
        )

    for seg_ea in idautils.Segments():
        existing = idaapi.getseg(seg_ea)
        if existing is None:
            continue
        if start_ea < existing.end_ea and existing.start_ea < end_ea:
            raise IDAError(
                f"Range {start_ea:#x}-{end_ea:#x} overlaps existing segment "
                f"{ida_segment.get_segm_name(existing)} "
                f"({existing.start_ea:#x}-{existing.end_ea:#x})"
            )

    if not ida_segment.add_segm(
        start_ea >> 4, start_ea, end_ea, name or "", seg_class
    ):
        raise IDAError(f"add_segm failed for {start_ea:#x}-{end_ea:#x}")

    seg = idaapi.getseg(start_ea)
    if seg is None:
        raise IDAError(f"Segment at {start_ea:#x} vanished after add_segm")

    notes: list[str] = []
    if permissions:
        perm = 0
        for ch in str(permissions).lower():
            if ch == "r":
                perm |= ida_segment.SEGPERM_READ
            elif ch == "w":
                perm |= ida_segment.SEGPERM_WRITE
            elif ch in ("x", "e"):
                perm |= ida_segment.SEGPERM_EXEC
            else:
                notes.append(f"Ignored unknown permission character {ch!r}")
        seg.perm = perm
        if not seg.update():
            notes.append("Could not store segment permissions")

    if bitness is not None:
        states = _apply_addressing([seg], _parse_bitness(bitness))
    else:
        states = [_segment_state(seg)]

    result: CreateSegmentResult = {
        "start": hex(start_ea),
        "end": hex(end_ea),
        "size": end_ea - start_ea,
        "segments": states,
    }
    if notes:
        result["notes"] = notes
    return result
class RebaseResult(TypedDict):
    delta: int
    image_base: str
    segments: list[SegmentBitness]
    notes: NotRequired[list[str]]


@tool
@idasync
def rebase(
    new_base: Annotated[
        str | int | None,
        "New load address of the first segment (0x10000). Give this or delta.",
    ] = None,
    delta: Annotated[
        str | int | None,
        "Signed number of bytes to move the whole program. Give this or new_base.",
    ] = None,
) -> RebaseResult:
    """Move the whole program to a different load address.

    The load base is another load-time decision idalib cannot be told about, so
    an image that belongs at its real base (an extender image, a dumped module)
    lands at whatever the loader chose. This moves every segment and lets the
    loader fix up the addresses it stored in the database, which is why it is
    preferable to recreating the database at a different base.
    """
    first = ida_segment.getnseg(0)
    if first is None:
        raise IDAError("Database has no segments to rebase")

    if delta is not None:
        move_by = parse_address(delta) if isinstance(delta, str) else int(delta)
    elif new_base is not None:
        target = parse_address(new_base) if isinstance(new_base, str) else int(new_base)
        move_by = target - first.start_ea
    else:
        raise IDAError("rebase needs either new_base or delta")

    if move_by == 0:
        return {
            "delta": 0,
            "image_base": hex(first.start_ea),
            "segments": [_segment_state(seg) for seg in _all_segments()],
            "notes": ["Already at that base; nothing moved."],
        }

    code = ida_segment.rebase_program(move_by, idaapi.MSF_FIXONCE)
    if code != idaapi.MOVE_SEGM_OK:
        raise IDAError(
            f"rebase_program({move_by:#x}) failed with move_segm code {code}"
        )

    segments = _all_segments()
    base = segments[0].start_ea if segments else 0
    return {
        "delta": move_by,
        "image_base": hex(base),
        "segments": [_segment_state(seg) for seg in segments],
    }


# ---------------------------------------------------------------------------
# Segment registers (ARM Thumb "T", MIPS16, PPC VLE, x86 DS, ...)
# ---------------------------------------------------------------------------


class SregOp(TypedDict, total=False):
    start: str
    end: str
    size: str
    reg: str
    value: int


class SregChange(TypedDict):
    start: str
    end: NotRequired[str]
    reg: NotRequired[str]
    value: NotRequired[int]
    previous: NotRequired[int]
    insn: NotRequired[str]
    error: NotRequired[str]
    notes: NotRequired[list[str]]


class SregValue(TypedDict):
    addr: str
    reg: NotRequired[str]
    value: NotRequired[int | None]
    error: NotRequired[str]


def _reg_index(reg: str) -> int:
    idx = ida_idp.str2reg(reg)
    if idx is None or idx < 0:
        raise IDAError(
            f"Processor {ida_idp.get_idp_name() or '?'} has no segment register {reg!r}"
        )
    return idx


def _check_thumb_allowed() -> None:
    if ida_idp.ph_get_id() != ida_idp.PLFM_ARM or ida_ida.inf_is_64bit():
        raise IDAError(
            "Thumb mode (T register) exists only on 32-bit ARM; this database is "
            f"{ida_idp.get_idp_name() or '?'} "
            f"{'64' if ida_ida.inf_is_64bit() else '32'}-bit"
        )


def _get_sreg_value(ea: int, reg_idx: int) -> int | None:
    value = ida_segregs.get_sreg(ea, reg_idx)
    if value is None or value == idaapi.BADSEL or value < 0:
        return None
    return int(value)


def get_sreg_value(ea: int, reg: str) -> int | None:
    """Value of segment register ``reg`` at ``ea`` (None if unset)."""
    return _get_sreg_value(ea, _reg_index(reg))


def set_sreg_range(
    start: int,
    end: int | None,
    reg: str,
    value: int,
    *,
    restore_value: int | None = None,
) -> int | None:
    """Set ``reg`` to ``value`` over [start, end), restoring the old value at end.

    ``split_sreg_range`` changes the value from ``start`` up to the next change
    point, so to bound the change we re-assert the value that was in effect at
    ``end`` (or ``restore_value`` when the caller captured it earlier). ``end``
    of None leaves the change open-ended. Returns the previous value at
    ``start`` (None if unset).
    """
    if reg.upper() == "T":
        _check_thumb_allowed()
    reg_idx = _reg_index(reg)
    previous = _get_sreg_value(start, reg_idx)
    prev_at_end = _get_sreg_value(end, reg_idx) if end is not None else None
    if restore_value is not None:
        prev_at_end = restore_value
    if not ida_segregs.split_sreg_range(start, reg_idx, int(value), ida_segregs.SR_user):
        raise IDAError(f"split_sreg_range failed at {start:#x}")
    if end is not None and idaapi.getseg(end) is not None:
        restore = prev_at_end if prev_at_end is not None else 0
        if restore != int(value):
            ida_segregs.split_sreg_range(end, reg_idx, restore, ida_segregs.SR_user)
    return previous


@tool
@idasync
@tool_timeout(240.0)
def set_sreg(
    items: Annotated[
        list[SregOp] | SregOp,
        "{start, end|size, reg='T', value=1}; omit end/size to set from start "
        "to the next change point",
    ],
    undefine: Annotated[
        bool, "Undefine the range first so existing code re-decodes (default false)"
    ] = False,
    reanalyze: Annotated[bool, "Decode from start and re-analyze the range"] = True,
) -> list[SregChange]:
    """Set a segment register over address ranges, e.g. mark Thumb code on ARM.

    reg 'T' value 1 = Thumb, 0 = ARM (32-bit ARM only). Code already decoded in
    the other mode stays until re-decoded: pass undefine=true to redo it.
    """
    if isinstance(items, dict):
        items = [items]
    results: list[SregChange] = []
    spans: list[tuple[int, int]] = []
    for item in items:
        start_s = str(item.get("start", ""))
        reg = str(item.get("reg") or "T")
        try:
            if not start_s:
                raise IDAError("item is missing 'start'")
            start = parse_address(start_s)
            end: int | None = None
            if item.get("end"):
                end = parse_address(str(item["end"]))
            elif item.get("size"):
                size = item["size"]
                end = start + (parse_address(size) if isinstance(size, str) else int(size))
            if end is not None and end <= start:
                raise IDAError(f"Empty or inverted range at {start_s}")
            value = int(item.get("value", 1))

            notes: list[str] = []
            span_end = end if end is not None else (idaapi.getseg(start).end_ea if idaapi.getseg(start) else start)
            if undefine and span_end > start:
                ida_bytes.del_items(start, ida_bytes.DELIT_SIMPLE, span_end - start)
            elif _has_code(start, span_end):
                notes.append(
                    "Range already holds code decoded in the previous mode; pass "
                    "undefine=true to re-decode it."
                )
            previous = set_sreg_range(start, end, reg, value)
            if reanalyze:
                ida_auto.auto_make_code(start)
                if span_end > start:
                    spans.append((start, span_end))
            if end is None:
                notes.append("Open-ended: applies until the next change point.")
            entry: SregChange = {
                "start": hex(start),
                "reg": reg,
                "value": value,
                "previous": previous if previous is not None else -1,
            }
            if end is not None:
                entry["end"] = hex(end)
            if notes:
                entry["notes"] = notes
            results.append(entry)
        except Exception as e:
            results.append({"start": start_s, "error": str(e)})

    if reanalyze:
        plan_and_wait(spans)
        for entry in results:
            if "error" not in entry:
                entry["insn"] = idc.GetDisasm(int(entry["start"], 16))
    return results


@tool
@idasync
def get_sreg(
    addrs: Annotated[list[str] | str, "Addresses (list or comma-separated)"],
    reg: Annotated[str, "Segment register name (default 'T' = ARM Thumb)"] = "T",
) -> list[SregValue]:
    """Read a segment register's value at addresses (T: 1 = Thumb, 0 = ARM)."""
    results: list[SregValue] = []
    try:
        reg_idx = _reg_index(reg)
    except IDAError as e:
        return [{"addr": str(a), "error": str(e)} for a in normalize_list_input(addrs)]
    for addr in normalize_list_input(addrs):
        try:
            ea = parse_address(str(addr))
            results.append({"addr": str(addr), "reg": reg, "value": _get_sreg_value(ea, reg_idx)})
        except Exception as e:
            results.append({"addr": str(addr), "error": str(e)})
    return results
