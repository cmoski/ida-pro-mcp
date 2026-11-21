"""Function-level attributes: flags (noreturn, thunk, library, ...).

IDA stores per-function attributes as bits in ``func_t.flags``. The one that
matters most for analysis quality is FUNC_NORET: a function wrongly marked
no-return makes IDA treat everything after each call as dead code (and a
missing mark leaves bogus fall-through). Changing it here also re-analyzes
every caller so the flow fix actually propagates, which is the step a plain
flag write would miss.
"""

from typing import Annotated, NotRequired, TypedDict

import ida_auto
import ida_funcs
import ida_hexrays
import idautils

from .rpc import tool
from .sync import idasync, IDAError
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
            ida_auto.auto_wait()
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
