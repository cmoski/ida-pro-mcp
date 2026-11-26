"""Function-level attributes (flags) and function-list export/import.

IDA stores per-function attributes as bits in ``func_t.flags``. The one that
matters most for analysis quality is FUNC_NORET: a function wrongly marked
no-return makes IDA treat everything after each call as dead code (and a
missing mark leaves bogus fall-through). Changing it here also re-analyzes
every caller so the flow fix actually propagates, which is the step a plain
flag write would miss.
"""

import fnmatch
import json
import os
import re
from typing import Annotated, NotRequired, TypedDict

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idp
import ida_segregs
import ida_ua
import idaapi
import idautils

from .api_modify import rename_at_ea
from .rpc import OUTPUT_LIMIT_MAX_CHARS, tool
from .sync import idasync, tool_timeout, IDAError, get_tool_deadline
from .auto_steps import wait_analysis
from .mainthread import get_pump
from .utils import normalize_list_input, parse_address

# name -> (bit, settable). Settable flags are the ones whose meaning is a plain
# attribute; the rest are analysis state that IDA maintains itself.
FUNC_FLAG_BITS: dict[str, tuple[int, bool]] = {
    "noreturn": (ida_funcs.FUNC_NORET, True),
    "thunk": (ida_funcs.FUNC_THUNK, True),
    "lib": (ida_funcs.FUNC_LIB, True),
    "hidden": (ida_funcs.FUNC_HIDDEN, True),
    "static": (ida_funcs.FUNC_STATICDEF, True),
    "far": (ida_funcs.FUNC_FAR, True),
    "frame": (ida_funcs.FUNC_FRAME, False),
    "userfar": (ida_funcs.FUNC_USERFAR, False),
    "purged_ok": (ida_funcs.FUNC_PURGED_OK, False),
    "sp_ready": (ida_funcs.FUNC_SP_READY, False),
    "fuzzy_sp": (ida_funcs.FUNC_FUZZY_SP, False),
    "prolog_ok": (ida_funcs.FUNC_PROLOG_OK, False),
    "outline": (getattr(ida_funcs, "FUNC_OUTLINE", 0), False),
    "lumina": (getattr(ida_funcs, "FUNC_LUMINA", 0), False),
}
SETTABLE_FUNC_FLAGS = tuple(name for name, (_, settable) in FUNC_FLAG_BITS.items() if settable)


class FuncFlagsInfo(TypedDict):
    addr: str
    start: NotRequired[str]
    end: NotRequired[str]
    name: NotRequired[str]
    flags: NotRequired[dict[str, bool]]
    raw: NotRequired[str]
    error: NotRequired[str]


class FuncFlagsOp(TypedDict, total=False):
    addr: str
    noreturn: bool
    thunk: bool
    lib: bool
    hidden: bool
    static: bool
    far: bool


class FuncFlagsChange(TypedDict):
    addr: str
    start: NotRequired[str]
    before: NotRequired[dict[str, bool]]
    after: NotRequired[dict[str, bool]]
    changed: NotRequired[list[str]]
    callers_reanalyzed: NotRequired[int]
    error: NotRequired[str]


def func_flags_dict(fn: ida_funcs.func_t) -> dict[str, bool]:
    """All known flag names for ``fn`` -> bool."""
    flags = int(fn.flags)
    return {name: bool(flags & bit) for name, (bit, _) in FUNC_FLAG_BITS.items() if bit}


def resolve_func(addr: str) -> ida_funcs.func_t:
    ea = parse_address(addr)
    fn = ida_funcs.get_func(ea)
    if fn is None:
        raise IDAError(f"No function at {addr}")
    return fn


def apply_func_flags(
    fn: ida_funcs.func_t,
    spec: dict,
    *,
    reanalyze_callers: bool = True,
) -> tuple[list[str], int]:
    """Set/clear the settable flags named in ``spec`` on ``fn``.

    Returns (changed flag names, number of callers queued for re-analysis).
    Raises IDAError for unknown or read-only flag names.
    """
    unknown = [k for k in spec if k != "addr" and k not in FUNC_FLAG_BITS]
    if unknown:
        raise IDAError(
            f"Unknown flag(s) {unknown}; settable: {', '.join(SETTABLE_FUNC_FLAGS)}"
        )
    readonly = [k for k in spec if k in FUNC_FLAG_BITS and not FUNC_FLAG_BITS[k][1]]
    if readonly:
        raise IDAError(
            f"Flag(s) {readonly} are analysis state and can't be set; "
            f"settable: {', '.join(SETTABLE_FUNC_FLAGS)}"
        )

    old = int(fn.flags)
    new = old
    for name, value in spec.items():
        if name == "addr" or value is None:
            continue
        bit = FUNC_FLAG_BITS[name][0]
        new = (new | bit) if bool(value) else (new & ~bit)
    changed = [
        name
        for name, (bit, _) in FUNC_FLAG_BITS.items()
        if bit and (old & bit) != (new & bit)
    ]
    if not changed:
        return [], 0

    fn.flags = new
    if not ida_funcs.update_func(fn):
        raise IDAError(f"update_func failed at {fn.start_ea:#x}")

    callers = 0
    if "noreturn" in changed:
        noret = bool(new & ida_funcs.FUNC_NORET)
        if reanalyze_callers:
            # Re-plan every call site so flow after the call is rebuilt
            # (dead code removed or fall-through restored).
            ida_auto.reanalyze_callers(fn.start_ea, noret)
            callers = sum(1 for _ in idautils.CodeRefsTo(fn.start_ea, 0))
            if not get_pump().has_background():
                # With background analysis running, the re-planned callers are
                # picked up there; don't block on the whole binary's queue.
                wait_analysis(get_tool_deadline())
        for ref in idautils.CodeRefsTo(fn.start_ea, 0):
            caller = ida_funcs.get_func(ref)
            if caller is not None:
                _mark_decompiler_dirty(caller.start_ea)
    _mark_decompiler_dirty(fn.start_ea)
    return changed, callers


def _mark_decompiler_dirty(ea: int) -> None:
    try:
        if ida_hexrays.init_hexrays_plugin():
            ida_hexrays.mark_cfunc_dirty(ea, False)
    except Exception:
        pass


@tool
@idasync
def get_func_flags(
    addrs: Annotated[list[str] | str, "Function addresses or names (list or comma-separated)"],
) -> list[FuncFlagsInfo]:
    """Read function flags (noreturn, thunk, lib, hidden, static, far, frame, ...)."""
    results: list[FuncFlagsInfo] = []
    for addr in normalize_list_input(addrs):
        try:
            fn = resolve_func(addr)
            results.append(
                {
                    "addr": addr,
                    "start": hex(fn.start_ea),
                    "end": hex(fn.end_ea),
                    "name": ida_funcs.get_func_name(fn.start_ea) or "",
                    "flags": func_flags_dict(fn),
                    "raw": hex(int(fn.flags)),
                }
            )
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
    return results


@tool
@idasync
def set_func_flags(
    items: Annotated[
        list[FuncFlagsOp] | FuncFlagsOp,
        "{addr, noreturn?, thunk?, lib?, hidden?, static?, far?}; true sets, "
        "false clears, omitted keeps",
    ],
    reanalyze_callers: Annotated[
        bool, "When noreturn changes, re-analyze all callers (default true)"
    ] = True,
) -> list[FuncFlagsChange]:
    """Set or clear function flags; returns before/after per function.

    Changing noreturn re-analyzes every caller so code after the calls is
    rebuilt (dead code dropped or fall-through restored), and invalidates
    cached decompilation.
    """
    if isinstance(items, dict):
        items = [items]
    results: list[FuncFlagsChange] = []
    for item in items:
        addr = str(item.get("addr", ""))
        try:
            if not addr:
                raise IDAError("item is missing 'addr'")
            fn = resolve_func(addr)
            before = func_flags_dict(fn)
            changed, callers = apply_func_flags(
                fn, dict(item), reanalyze_callers=reanalyze_callers
            )
            fn = ida_funcs.get_func(fn.start_ea) or fn
            entry: FuncFlagsChange = {
                "addr": addr,
                "start": hex(fn.start_ea),
                "before": before,
                "after": func_flags_dict(fn),
                "changed": changed,
            }
            if "noreturn" in changed and reanalyze_callers:
                entry["callers_reanalyzed"] = callers
            results.append(entry)
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
    return results


# ---------------------------------------------------------------------------
# Function-list export / import (format "ida-mcp-funcs", version 1)
#
# Lets two databases -- e.g. IDA and Ghidra -- stay in sync without thousands
# of single calls. See docs/func-list-format.md for the schema.
# ---------------------------------------------------------------------------

FUNC_LIST_FORMAT = "ida-mcp-funcs"
FUNC_LIST_VERSION = 1
# Flags carried in the exchange format: plain attributes another tool can map.
EXCHANGE_FLAGS = ("noreturn", "thunk", "lib")
_EXPORT_PAGE_BUDGET = OUTPUT_LIMIT_MAX_CHARS - 4_000
_IMPORT_MAX_ERRORS = 200


class FuncListEntry(TypedDict, total=False):
    start: str
    end: str
    name: str
    user_name: bool
    comment: str
    repeatable_comment: str
    flags: dict[str, bool]
    thumb: bool


class FuncListExport(TypedDict, total=False):
    format: str
    version: int
    image_base: str
    processor: str
    bitness: int
    count: int
    total: int
    functions: list[FuncListEntry]
    next_offset: int | None
    path: str
    error: str


class FuncListImportError(TypedDict):
    start: str
    error: str


class FuncListImportResult(TypedDict, total=False):
    dry_run: bool
    total: int
    created: int
    bounds_updated: int
    renamed: int
    commented: int
    flags_changed: int
    thumb_set: int
    skipped: int
    failed: int
    delta: str
    errors: list[FuncListImportError]
    errors_truncated: bool
    analysis: dict
    notes: list[str]


def _is_arm32() -> bool:
    return ida_idp.ph_get_id() == ida_idp.PLFM_ARM and not ida_ida.inf_is_64bit()


def _func_entry(fn: ida_funcs.func_t, arm32: bool) -> FuncListEntry:
    start = fn.start_ea
    entry: FuncListEntry = {
        "start": hex(start),
        "end": hex(fn.end_ea),
        "name": ida_funcs.get_func_name(start) or "",
        "user_name": bool(ida_bytes.has_user_name(ida_bytes.get_flags(start))),
    }
    cmt = ida_funcs.get_func_cmt(fn, False)
    if cmt:
        entry["comment"] = cmt
    rcmt = ida_funcs.get_func_cmt(fn, True)
    if rcmt:
        entry["repeatable_comment"] = rcmt
    flags = func_flags_dict(fn)
    entry["flags"] = {k: flags[k] for k in EXCHANGE_FLAGS}
    if arm32:
        t_reg = ida_idp.str2reg("T")
        entry["thumb"] = bool(ida_segregs.get_sreg(start, t_reg) == 1)
    return entry


def _export_header() -> FuncListExport:
    return {
        "format": FUNC_LIST_FORMAT,
        "version": FUNC_LIST_VERSION,
        "image_base": hex(idaapi.get_imagebase()),
        "processor": ida_idp.get_idp_name() or "",
        "bitness": 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16),
    }


def _select_functions(filter: str, ranges: list[str] | str | None) -> list[ida_funcs.func_t]:
    spans: list[tuple[int, int]] = []
    if ranges:
        from .api_load import _parse_range_token, _resolve_segments

        for token in normalize_list_input(ranges):
            text = str(token)
            span = _parse_range_token(text)
            if span is not None:
                spans.append(span)
                continue
            segs, errs = _resolve_segments(text)
            if errs:
                raise IDAError(errs[0]["error"])
            spans.extend((s.start_ea, s.end_ea) for s in segs)
    pattern = re.compile(fnmatch.translate(filter), re.IGNORECASE) if filter else None
    out = []
    for ea in idautils.Functions():
        if spans and not any(s <= ea < e for s, e in spans):
            continue
        fn = ida_funcs.get_func(ea)
        if fn is None:
            continue
        if pattern and not pattern.match(ida_funcs.get_func_name(ea) or ""):
            continue
        out.append(fn)
    return out


@tool
@idasync
@tool_timeout(300.0)
def export_func_list(
    filter: Annotated[str, "Name glob, e.g. 'sub_*' (default: all)"] = "",
    ranges: Annotated[
        list[str] | str | None, "Limit to 'start-end' ranges or segment names"
    ] = None,
    path: Annotated[
        str, "Write the full list to this JSON file and return only a summary"
    ] = "",
    offset: Annotated[int, "Skip the first N functions (in-response paging)"] = 0,
) -> FuncListExport:
    """Export functions (bounds, names, comments, flags, Thumb) as ida-mcp-funcs JSON.

    Pair with import_func_list (or a Ghidra script using the same format) to
    sync databases. Without path, results page under the output cap; follow
    next_offset. With path, every function is written to the file.
    """
    header = _export_header()
    arm32 = _is_arm32()
    funcs = _select_functions(filter, ranges)

    if path:
        doc = dict(header)
        doc["functions"] = [_func_entry(fn, arm32) for fn in funcs]
        doc["count"] = len(funcs)
        target = os.path.abspath(path)
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
        return {**header, "count": len(funcs), "total": len(funcs), "path": target}

    offset = max(0, int(offset))
    page: list[FuncListEntry] = []
    used = len(json.dumps(header)) + 200
    next_offset = None
    for idx in range(offset, len(funcs)):
        entry = _func_entry(funcs[idx], arm32)
        size = len(json.dumps(entry)) + 2
        if page and used + size > _EXPORT_PAGE_BUDGET:
            next_offset = idx
            break
        page.append(entry)
        used += size
    return {
        **header,
        "count": len(page),
        "total": len(funcs),
        "functions": page,
        "next_offset": next_offset,
    }


def _create_function(start: int, end: int | None) -> None:
    """add_func that also works on undefined bytes.

    With an explicit end, add_func refuses a start that isn't decoded yet, so
    decode the first instruction; if it still fails, let IDA infer the bounds
    from flow and then move the end to the requested address.
    """
    if not ida_bytes.is_code(ida_bytes.get_flags(start)):
        ida_ua.create_insn(start)
    if ida_funcs.add_func(start, end if end is not None else idaapi.BADADDR):
        return
    if end is not None and ida_funcs.add_func(start, idaapi.BADADDR):
        fn = ida_funcs.get_func(start)
        if fn is not None and fn.end_ea != end:
            ida_funcs.set_func_end(start, end)
        return
    raise IDAError("add_func failed (no decodable code at start?)")


def _parse_ea_field(value) -> int:
    if isinstance(value, int):
        return value
    return parse_address(str(value))


@tool
@idasync
@tool_timeout(900.0)
def import_func_list(
    data: Annotated[
        dict | str | None, "ida-mcp-funcs document (object or JSON string)"
    ] = None,
    path: Annotated[str, "Read the document from this JSON file instead"] = "",
    create_missing: Annotated[bool, "Create functions that don't exist"] = True,
    update_bounds: Annotated[bool, "Move function ends to match the file"] = False,
    overwrite_names: Annotated[
        bool, "Replace user-defined names (auto names are always replaced)"
    ] = False,
    overwrite_comments: Annotated[bool, "Replace existing function comments"] = False,
    apply_flags: Annotated[bool, "Apply noreturn/thunk/lib flags"] = True,
    rebase: Annotated[
        str, "'auto': shift by current image base - file image_base; 'none'"
    ] = "auto",
    dry_run: Annotated[bool, "Report what would change without changing anything"] = False,
) -> FuncListImportResult:
    """Apply an ida-mcp-funcs function list: create functions, bounds, names, comments, flags.

    Per entry: Thumb mode (ARM), create/resize, flags, name, comments; callers
    of changed noreturn functions and new functions are re-analyzed once at
    the end. Conservative by default. Run large imports via submit_job.
    """
    if path:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    elif isinstance(data, str):
        doc = json.loads(data)
    elif isinstance(data, dict):
        doc = data
    else:
        raise IDAError("Provide data (object/JSON) or path")
    if doc.get("format") not in (None, FUNC_LIST_FORMAT):
        raise IDAError(f"Unsupported format {doc.get('format')!r}; expected {FUNC_LIST_FORMAT!r}")
    if int(doc.get("version", FUNC_LIST_VERSION)) > FUNC_LIST_VERSION:
        raise IDAError(f"Document version {doc.get('version')} is newer than supported ({FUNC_LIST_VERSION})")
    entries = doc.get("functions")
    if not isinstance(entries, list):
        raise IDAError("Document has no 'functions' list")

    delta = 0
    notes: list[str] = []
    if rebase == "auto" and doc.get("image_base") is not None:
        delta = idaapi.get_imagebase() - _parse_ea_field(doc["image_base"])
        if delta:
            notes.append(f"Addresses shifted by {delta:#x} (image base differs).")
    elif rebase not in ("auto", "none"):
        raise IDAError("rebase must be 'auto' or 'none'")

    arm32 = _is_arm32()
    counts = dict(
        created=0, bounds_updated=0, renamed=0, commented=0,
        flags_changed=0, thumb_set=0, skipped=0, failed=0,
    )
    errors: list[FuncListImportError] = []
    new_spans: list[tuple[int, int]] = []
    noret_changed: list[tuple[int, bool]] = []

    def fail(start_s: str, msg: str) -> None:
        counts["failed"] += 1
        if len(errors) < _IMPORT_MAX_ERRORS:
            errors.append({"start": start_s, "error": msg})

    for raw in entries:
        start_s = str(raw.get("start", "")) if isinstance(raw, dict) else ""
        try:
            if not start_s:
                raise IDAError("entry is missing 'start'")
            start = _parse_ea_field(raw["start"]) + delta
            end = _parse_ea_field(raw["end"]) + delta if raw.get("end") not in (None, "") else None
            if end is not None and end <= start:
                raise IDAError("end must be greater than start")
            if idaapi.getseg(start) is None:
                raise IDAError(f"{start:#x} is not in any segment")
            touched = False

            # 1. Instruction set (ARM/Thumb) must be right before decoding.
            if arm32 and raw.get("thumb") is not None:
                t_reg = ida_idp.str2reg("T")
                want = 1 if raw["thumb"] else 0
                if ida_segregs.get_sreg(start, t_reg) != want:
                    if not dry_run:
                        from .api_load import set_sreg_range

                        set_sreg_range(start, end, "T", want)
                    counts["thumb_set"] += 1
                    touched = True

            # 2. Existence and bounds.
            fn = ida_funcs.get_func(start)
            if fn is not None and fn.start_ea != start:
                raise IDAError(
                    f"{start:#x} lies inside {ida_funcs.get_func_name(fn.start_ea)} "
                    f"({fn.start_ea:#x}); not creating an overlapping function"
                )
            if fn is None:
                if not create_missing:
                    counts["skipped"] += 1
                    continue
                if not dry_run:
                    _create_function(start, end)
                    fn = ida_funcs.get_func(start)
                    new_spans.append((fn.start_ea, fn.end_ea))
                counts["created"] += 1
                touched = True
            elif update_bounds and end is not None and fn.end_ea != end:
                if not dry_run and not ida_funcs.set_func_end(start, end):
                    raise IDAError(f"set_func_end({end:#x}) failed")
                counts["bounds_updated"] += 1
                touched = True
            if not dry_run:
                fn = ida_funcs.get_func(start)

            # 3. Flags.
            wanted = raw.get("flags") or {}
            if apply_flags and wanted:
                spec = {k: bool(v) for k, v in wanted.items() if k in EXCHANGE_FLAGS}
                if fn is not None:
                    current = func_flags_dict(fn)
                    diff = {k: v for k, v in spec.items() if current.get(k) != v}
                else:
                    diff = spec  # dry run of a function that doesn't exist yet
                if diff:
                    if not dry_run:
                        changed, _ = apply_func_flags(fn, diff, reanalyze_callers=False)
                        if "noreturn" in changed:
                            noret_changed.append((start, bool(diff["noreturn"])))
                    counts["flags_changed"] += 1
                    touched = True

            # 4. Name: only names the source marked as user-chosen (or unmarked).
            name = raw.get("name") or ""
            if name and raw.get("user_name", True):
                current_name = ida_funcs.get_func_name(start) or ""
                if current_name != name:
                    has_user = bool(ida_bytes.has_user_name(ida_bytes.get_flags(start)))
                    if has_user and not overwrite_names:
                        counts["skipped"] += 1
                    else:
                        if not dry_run:
                            ok, err = rename_at_ea(start, name, allow_overwrite=False)
                            if not ok:
                                raise IDAError(err or f"rename to {name!r} failed")
                        counts["renamed"] += 1
                        touched = True

            # 5. Comments.
            for key, repeatable in (("comment", False), ("repeatable_comment", True)):
                text = raw.get(key)
                if not text:
                    continue
                existing = ida_funcs.get_func_cmt(fn, repeatable) if fn is not None else ""
                if existing == text:
                    continue
                if existing and not overwrite_comments:
                    counts["skipped"] += 1
                    continue
                if not dry_run and not ida_funcs.set_func_cmt(fn, text, repeatable):
                    raise IDAError(f"set_func_cmt ({key}) failed")
                counts["commented"] += 1
                touched = True
            del touched
        except Exception as e:
            fail(start_s, str(e))

    result: FuncListImportResult = {
        "dry_run": dry_run,
        "total": len(entries),
        **counts,
        "delta": hex(delta),
    }
    if not dry_run and (noret_changed or new_spans):
        for ea, noret in noret_changed:
            ida_auto.reanalyze_callers(ea, noret)
        from .api_load import plan_and_wait

        result["analysis"] = plan_and_wait(new_spans)
    if errors:
        result["errors"] = errors
        if counts["failed"] > len(errors):
            result["errors_truncated"] = True
    if notes:
        result["notes"] = notes
    return result
