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

from typing import Annotated, NotRequired, TypedDict

import idaapi
import idautils
import ida_auto
import ida_bytes
import ida_diskio
import ida_ida
import ida_idp
import ida_loader
import ida_segment

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
        for seg in changed:
            ida_auto.plan_range(seg.start_ea, seg.end_ea)
        ida_auto.auto_wait()
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
        for seg in created:
            ida_auto.plan_range(seg.start_ea, seg.end_ea)
        ida_auto.auto_wait()
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
