"""Searchable index of the rendered listing, for whole-image search_text.

Rendering the listing is the expensive part of a text search (~30-60 us per
head). A whole-image search on a large binary (tens of millions of heads) took
tens of minutes. The index renders each head once, cheaply (one disassembly
line plus real comments, no xref/header boilerplate), keeps it zlib-compressed
per fixed address window, and searches it with one C regex pass per window.

- Windows not yet indexed are rendered on first touch (and kept), so the index
  fills in as searches run. Headless workers also build it in the background
  between tool calls (``build_step``).
- IDB edits mark the affected windows stale (dropped and re-rendered on next
  touch). A rename or repeatable-comment change also marks every window that
  references the item.
- Every candidate hit is re-rendered live and re-matched before it is
  returned, so a stale window can never produce a false hit. (Only changes
  with database-wide effect, like a struct rename, can briefly hide a hit
  until the window is re-rendered.)

All functions here must run on the IDA main thread.
"""

from __future__ import annotations

import logging
import time
import zlib
from array import array
from typing import Any, Callable

import ida_bytes
import ida_funcs
import ida_idp
import ida_lines
import ida_segment
import idaapi
import idautils

logger = logging.getLogger(__name__)

WINDOW = 0x4000  # bytes of address space per index window
_ZLEVEL = 1

_COMMENT_SCOLORS = (
    ida_lines.SCOLOR_REGCMT,
    ida_lines.SCOLOR_RPTCMT,
    ida_lines.SCOLOR_AUTOCMT,
    ida_lines.SCOLOR_COLLAPSED,
)
_COMMENT_TAGS = tuple(ida_lines.COLOR_ON + sc for sc in _COMMENT_SCOLORS)

KIND_DISASM = "disasm"
KIND_COMMENT = "comment"
_KIND_CODES = {b"d"[0]: KIND_DISASM, b"c"[0]: KIND_COMMENT}


# ----------------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------------


def _extra_lines(ea: int, base: int, out: list[tuple[str, str]]) -> None:
    for i in range(1000):
        line = ida_lines.get_extra_cmt(ea, base + i)
        if line is None:
            return
        for part in line.splitlines():
            if part:
                out.append((KIND_COMMENT, part))


def render_head(ea: int) -> list[tuple[str, str]]:
    """The searchable lines for one head: [(kind, text)], kind disasm/comment."""
    out: list[tuple[str, str]] = []
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_func(flags):
        fn = ida_funcs.get_func(ea)
        if fn is not None and fn.start_ea == ea:
            for repeatable in (False, True):
                cmt = ida_funcs.get_func_cmt(fn, repeatable)
                if cmt:
                    out.extend((KIND_COMMENT, p) for p in cmt.splitlines() if p)
    has_extra = ida_bytes.has_extra_cmts(flags)
    if has_extra:
        _extra_lines(ea, ida_lines.E_PREV, out)

    tagged = ida_lines.generate_disasm_line(ea, 0) or ""
    cut = -1
    for tag in _COMMENT_TAGS:
        i = tagged.find(tag)
        if i != -1 and (cut == -1 or i < cut):
            cut = i
    if cut == -1:
        text = ida_lines.tag_remove(tagged).strip()
        if text:
            out.append((KIND_DISASM, text))
    else:
        text = ida_lines.tag_remove(tagged[:cut]).strip()
        if text:
            out.append((KIND_DISASM, text))
        cmt = ida_lines.tag_remove(tagged[cut:]).strip()
        if cmt:
            out.append((KIND_COMMENT, cmt))

    if has_extra:
        _extra_lines(ea, ida_lines.E_NEXT, out)
    return [(k, t.replace("\n", " ")) for k, t in out]


def matching_lines(
    ea: int, matcher: Callable[[str], bool], want_disasm: bool, want_comments: bool
) -> list[dict[str, str]]:
    """Live re-render of one head; the lines that match and are wanted."""
    found = []
    for kind, text in render_head(ea):
        if kind == KIND_DISASM and not want_disasm:
            continue
        if kind == KIND_COMMENT and not want_comments:
            continue
        if matcher(text):
            found.append({"kind": kind, "text": text})
    return found


# ----------------------------------------------------------------------------
# Index
# ----------------------------------------------------------------------------


class _Window:
    __slots__ = ("ztext", "zeas", "zkinds", "lines")

    def __init__(self, ztext: bytes, zeas: bytes, zkinds: bytes, lines: int):
        self.ztext = ztext
        self.zeas = zeas
        self.zkinds = zkinds
        self.lines = lines

    def unpack(self) -> tuple[str, array, bytes]:
        text = zlib.decompress(self.ztext).decode("utf-8", "replace")
        eas = array("Q")
        eas.frombytes(zlib.decompress(self.zeas))
        return text, eas, zlib.decompress(self.zkinds)

    @property
    def nbytes(self) -> int:
        return len(self.ztext) + len(self.zeas) + len(self.zkinds)


def _window_of(ea: int) -> int:
    return ea - (ea % WINDOW)


def _render_window(start: int) -> _Window:
    texts: list[str] = []
    eas = array("Q")
    kinds = bytearray()
    for head in idautils.Heads(start, start + WINDOW):
        for kind, text in render_head(head):
            texts.append(text)
            eas.append(head)
            kinds.append(100 if kind == KIND_DISASM else 99)  # b"d" / b"c"
    return _Window(
        zlib.compress("\n".join(texts).encode("utf-8"), _ZLEVEL),
        zlib.compress(eas.tobytes(), _ZLEVEL),
        zlib.compress(bytes(kinds), _ZLEVEL),
        len(texts),
    )


def _segment_windows(exec_first: bool = True) -> list[int]:
    """Window starts covering every segment, executable segments first."""
    code: list[int] = []
    other: list[int] = []
    seen: set[int] = set()
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg is None:
            continue
        bucket = code if (seg.perm & idaapi.SEGPERM_EXEC or not exec_first) else other
        w = _window_of(seg.start_ea)
        while w < seg.end_ea:
            if w not in seen:
                seen.add(w)
                bucket.append(w)
            w += WINDOW
    return code + other


class _IdbInvalidator(ida_idp.IDB_Hooks):
    """Drops index windows touched by database edits."""

    def __init__(self, index: "ListingIndex"):
        super().__init__()
        self.index = index

    def _ea(self, ea, *_a):
        self.index.invalidate(ea)
        return 0

    def _with_refs(self, ea):
        self.index.invalidate(ea)
        try:
            for xref in idautils.XrefsTo(ea, 0):
                self.index.invalidate(xref.frm)
        except Exception:
            pass

    def renamed(self, ea, *args):
        self._with_refs(ea)
        return 0

    def cmt_changed(self, ea, repeatable_cmt, *args):
        if repeatable_cmt:
            self._with_refs(ea)
        else:
            self.index.invalidate(ea)
        return 0

    def extra_cmt_changed(self, ea, *args):
        return self._ea(ea)

    def range_cmt_changed(self, kind, a, *args):
        try:
            self.index.invalidate(a.start_ea)
        except Exception:
            self.index.clear()
        return 0

    def make_code(self, insn, *args):
        return self._ea(insn.ea)

    def make_data(self, ea, flags, tid, length, *args):
        self.index.invalidate_range(ea, ea + max(1, int(length)))
        return 0

    def destroyed_items(self, ea1, ea2, *args):
        self.index.invalidate_range(ea1, ea2)
        return 0

    def _func(self, pfn, *args):
        try:
            self.index.invalidate_range(pfn.start_ea, pfn.end_ea)
        except Exception:
            pass
        return 0

    func_added = _func
    func_updated = _func
    deleting_func = _func
    set_func_start = _func
    set_func_end = _func

    def ti_changed(self, ea, *args):
        return self._ea(ea)

    def op_type_changed(self, ea, *args):
        return self._ea(ea)

    def byte_patched(self, ea, *args):
        return self._ea(ea)

    def _all(self, *args):
        self.index.clear()
        return 0

    segm_added = _all
    segm_deleted = _all
    segm_moved = _all
    allsegs_moved = _all


class ListingIndex:
    def __init__(self):
        self.windows: dict[int, _Window] = {}
        self._order: list[int] | None = None
        self._build_pos = 0
        self._hooks: _IdbInvalidator | None = None
        self.render_seconds = 0.0

    # -- lifecycle -----------------------------------------------------------

    def _ensure_hooks(self) -> None:
        if self._hooks is None:
            hooks = _IdbInvalidator(self)
            if hooks.hook():
                self._hooks = hooks

    def clear(self) -> None:
        self.windows.clear()
        self._order = None
        self._build_pos = 0

    def reset(self) -> None:
        """Drop everything, including hooks (database closed)."""
        if self._hooks is not None:
            try:
                self._hooks.unhook()
            except Exception:
                pass
            self._hooks = None
        self.clear()

    def invalidate(self, ea: int) -> None:
        if self.windows.pop(_window_of(ea), None) is not None:
            self._build_pos = 0  # let the background builder refill it

    def invalidate_range(self, start: int, end: int) -> None:
        if end - start > 64 * WINDOW:
            for w in [w for w in self.windows if start - WINDOW < w < end]:
                del self.windows[w]
        else:
            w = _window_of(start)
            while w < end:
                self.windows.pop(w, None)
                w += WINDOW
        self._build_pos = 0

    # -- building ------------------------------------------------------------

    def window(self, start: int) -> _Window:
        win = self.windows.get(start)
        if win is None:
            self._ensure_hooks()
            t0 = time.perf_counter()
            win = _render_window(start)
            self.render_seconds += time.perf_counter() - t0
            self.windows[start] = win
        return win

    def _all_windows(self) -> list[int]:
        if self._order is None:
            self._order = _segment_windows()
        return self._order

    def build_step(self, budget_sec: float) -> bool:
        """Render missing windows for up to budget_sec. True when complete."""
        order = self._all_windows()
        deadline = time.monotonic() + budget_sec
        while self._build_pos < len(order):
            w = order[self._build_pos]
            if w not in self.windows:
                self.window(w)
                if time.monotonic() >= deadline:
                    self._build_pos += 1
                    return self._build_pos >= len(order) and self._complete()
            self._build_pos += 1
        return self._complete()

    def _complete(self) -> bool:
        return all(w in self.windows for w in self._all_windows())

    def status(self) -> dict[str, Any]:
        order = self._all_windows()
        done = sum(1 for w in order if w in self.windows)
        return {
            "windows": len(order),
            "indexed": done,
            "coverage": round(done / len(order), 4) if order else 1.0,
            "mb": round(sum(w.nbytes for w in self.windows.values()) / 1e6, 1),
        }

    # -- searching -----------------------------------------------------------

    def search(
        self,
        rx,  # compiled with re.MULTILINE, for whole-window text
        matcher: Callable[[str], bool],  # per-line matcher used to verify
        ranges: list[tuple[int, int]],
        limit: int,
        want_disasm: bool,
        want_comments: bool,
        deadline: float | None,
        is_cancelled: Callable[[], bool],
    ) -> tuple[list[dict], int | None, bool]:
        """Scan [start, end) ranges in order. Returns (hits, next_ea, cancelled)."""
        hits: list[dict] = []
        want = {KIND_DISASM: want_disasm, KIND_COMMENT: want_comments}
        for walk_start, walk_end in ranges:
            w = _window_of(walk_start)
            while w < walk_end:
                if (deadline is not None and time.monotonic() >= deadline) or is_cancelled():
                    return hits, max(w, walk_start), True
                text, eas, kinds = self.window(w).unpack()
                w += WINDOW
                if not eas:
                    continue
                n = len(text)
                pos = 0  # where the next regex search starts (a line start)
                counted = 0  # newlines before `counted` are in line_no
                line_no = 0
                last_ea = None
                while pos <= n:
                    m = rx.search(text, pos)
                    if m is None:
                        break
                    s = m.start()
                    line_no += text.count("\n", counted, s)
                    counted = s
                    line_end = text.find("\n", s)
                    if line_end == -1:
                        line_end = n
                    pos = line_end + 1  # one candidate per line
                    ea = eas[line_no]
                    if ea == last_ea or not (walk_start <= ea < walk_end):
                        continue
                    if not want[_KIND_CODES[kinds[line_no]]]:
                        continue
                    last_ea = ea
                    # Verify against a live render: the window may be stale.
                    lines = matching_lines(ea, matcher, want_disasm, want_comments)
                    if lines:
                        hits.append(_hit(ea, lines))
                        if len(hits) >= limit:
                            return hits, ea + max(1, idaapi.get_item_size(ea)), False
        return hits, None, False


def _hit(ea: int, lines: list[dict]) -> dict:
    entry: dict[str, Any] = {"addr": hex(ea), "matches": lines}
    func = idaapi.get_func(ea)
    if func is not None:
        fname = ida_funcs.get_func_name(func.start_ea)
        if fname:
            entry["function"] = fname
    seg = idaapi.getseg(ea)
    if seg is not None:
        sname = ida_segment.get_segm_name(seg)
        if sname:
            entry["segment"] = sname
    return entry


_INDEX: ListingIndex | None = None


def get_index() -> ListingIndex:
    global _INDEX
    if _INDEX is None:
        _INDEX = ListingIndex()
    return _INDEX


def reset_index() -> None:
    """Drop the index (call when the database changes)."""
    if _INDEX is not None:
        _INDEX.reset()
