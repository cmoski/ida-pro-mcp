"""Off-main-thread disassembly text search via objdump.

This is the fast path for `search_text` when the IDA main thread is busy:
instead of queueing behind a long @idasync call, we disassemble the *on-disk*
input file with objdump and grep the instruction lines. No idaapi import on
purpose — everything here runs in the HTTP handler thread and is unit-testable
without IDA.

Limitations (the caller decides when these are acceptable):
- Sees raw disassembly only: no IDA-applied names, types, or comments.
- Addresses are file/section VAs; the caller passes a `delta` (IDA imagebase
  minus the file's preferred base) so returned addresses live in IDA's space.
- Executable code only (objdump -d), so it can't serve comments-only or
  data-segment searches.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from typing import Callable, Optional

# Instruction lines are indented and look like:  "    1014:\tcall   *%rax"
# (with --no-show-raw-insn the raw byte column is gone). Section headers and
# "<name>:" labels start at column 0, so the leading-whitespace anchor skips
# them.
_INSN_RE = re.compile(r"^\s+([0-9a-fA-F]+):[ \t]+(.*?)\s*$")
# Function/label lines:  "0000000000001014 <_init+0x14>:"
_LABEL_RE = re.compile(r"^[0-9a-fA-F]+ <(.+)>:\s*$")
# objdump -p: ELF "LOAD off ... vaddr 0x...." and PE "ImageBase  000000....".
_LOAD_VADDR_RE = re.compile(r"\bLOAD\b.*?\bvaddr\s+0x([0-9a-fA-F]+)")
_IMAGEBASE_RE = re.compile(r"^ImageBase\s+([0-9a-fA-F]+)\s*$")

_ENV_OBJDUMP = "IDA_MCP_OBJDUMP"

# objdump -p / -f results are stable per file; cache them so the fast path
# only pays the probe cost once per binary.
_base_cache: dict[str, Optional[int]] = {}
_arch_cache: dict[str, Optional[str]] = {}

# objdump -f: "architecture: i386:x86-64, flags ...". The i386 family is the
# only one whose default (AT&T) syntax diverges enough from IDA's (Intel) to
# matter for text matching, and the only one `-M intel` applies to.
_ARCH_RE = re.compile(r"^architecture:\s*([^\s,]+)", re.IGNORECASE)


def _no_window_kwargs() -> dict:
    """Avoid flashing a console window when spawning objdump on Windows."""
    if sys.platform == "win32":
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    return {}


def find_objdump() -> Optional[str]:
    """Locate objdump: $IDA_MCP_OBJDUMP, then the bundled w64devkit, then PATH.

    Returns an absolute path/command, or None if nothing usable is found (the
    caller then declines the fast path).
    """
    override = os.environ.get(_ENV_OBJDUMP, "").strip()
    if override:
        return override if os.path.isfile(override) else None

    exe = "objdump.exe" if sys.platform == "win32" else "objdump"
    # Repo layout: this file is src/ida_pro_mcp/ida_mcp/_objdump_search.py;
    # the bundled w64devkit lives at <repo>/bin/bin/objdump.exe.
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(here, "..", "..", ".."))
    bundled = os.path.join(repo_root, "bin", "bin", exe)
    if os.path.isfile(bundled):
        return bundled

    return shutil.which("objdump")


def objdump_base(objdump_path: str, file_path: str) -> Optional[int]:
    """Return the VA objdump assumes for the file (ELF min LOAD vaddr / PE ImageBase).

    Cached per file_path. Returns None if it can't be determined, in which case
    the caller should decline the fast path rather than guess an address delta.
    """
    if file_path in _base_cache:
        return _base_cache[file_path]

    base: Optional[int] = None
    try:
        proc = subprocess.run(
            [objdump_path, "-p", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20.0,
            **_no_window_kwargs(),
        )
        out = proc.stdout or ""
    except Exception:
        out = ""

    image_base: Optional[int] = None
    load_vaddrs: list[int] = []
    for line in out.splitlines():
        m = _IMAGEBASE_RE.match(line.strip())
        if m:
            image_base = int(m.group(1), 16)
            continue
        m = _LOAD_VADDR_RE.search(line)
        if m:
            load_vaddrs.append(int(m.group(1), 16))

    if image_base is not None:
        base = image_base
    elif load_vaddrs:
        base = min(load_vaddrs)

    _base_cache[file_path] = base
    return base


def architecture(objdump_path: str, file_path: str) -> Optional[str]:
    """Return objdump's architecture string for the file (e.g. 'i386:x86-64'), cached."""
    if file_path in _arch_cache:
        return _arch_cache[file_path]
    arch: Optional[str] = None
    try:
        proc = subprocess.run(
            [objdump_path, "-f", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20.0,
            **_no_window_kwargs(),
        )
        for line in (proc.stdout or "").splitlines():
            m = _ARCH_RE.match(line.strip())
            if m:
                arch = m.group(1)
                break
    except Exception:
        arch = None
    _arch_cache[file_path] = arch
    return arch


def is_x86(objdump_path: str, file_path: str) -> bool:
    """True if the file is x86/x86-64, where `-M intel` aligns syntax with IDA."""
    arch = architecture(objdump_path, file_path)
    return bool(arch and "i386" in arch.lower())


def clear_base_cache() -> None:
    _base_cache.clear()
    _arch_cache.clear()


def search_disasm(
    objdump_path: str,
    file_path: str,
    matcher: Callable[[str], bool],
    *,
    delta: int = 0,
    limit: int = 30,
    start_ea: Optional[int] = None,
    time_budget_sec: float = 0.0,
    intel: bool = False,
) -> dict:
    """Disassemble file_path with objdump and return instruction lines matching `matcher`.

    Addresses in the result are in IDA space (objdump address + `delta`).
    `start_ea` (IDA space) resumes the scan; only instructions at or after it
    are considered. `intel=True` adds `-M intel` so x86 mnemonics/registers
    match IDA's Intel rendering instead of objdump's AT&T default. Returns a
    dict shaped like SearchTextResult:
        {"n", "hits": [{"addr","matches":[{"kind":"disasm","text"}],"function"?}],
         "cursor": {...}, "engine": "objdump"}
    On objdump failure returns {"error": ...} so the caller can fall back.
    """
    args = [objdump_path, "-d", "-w", "--no-show-raw-insn"]
    if intel:
        args += ["-M", "intel"]
    args.append(file_path)
    start_od = None if start_ea is None else start_ea - delta

    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            **_no_window_kwargs(),
        )
    except Exception as e:
        return {"error": f"objdump failed to start: {e}"}

    hits: list[dict] = []
    cur_func: Optional[str] = None
    next_cursor: Optional[int] = None
    timed_out = False
    deadline = time.monotonic() + time_budget_sec if time_budget_sec > 0 else None

    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                break

            label = _LABEL_RE.match(line)
            if label:
                cur_func = label.group(1)
                continue

            m = _INSN_RE.match(line)
            if not m:
                continue

            od_addr = int(m.group(1), 16)
            if start_od is not None and od_addr < start_od:
                continue

            text = m.group(2)
            if not text or not matcher(text):
                continue

            ea = od_addr + delta
            entry: dict = {"addr": hex(ea), "matches": [{"kind": "disasm", "text": text}]}
            if cur_func:
                entry["function"] = cur_func
            hits.append(entry)

            if len(hits) >= limit:
                next_cursor = ea + 1
                break

        if timed_out:
            # Resume just past the address we stopped scanning at.
            last = hits[-1] if hits else None
            next_cursor = (int(last["addr"], 16) + 1) if last else start_ea
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.stdout.close()
        except Exception:
            pass
        proc.wait()

    if timed_out and next_cursor is not None:
        cursor = {"next": hex(next_cursor), "truncated": True, "limit_hit": "time_budget"}
    elif next_cursor is not None:
        cursor = {"next": hex(next_cursor)}
    else:
        cursor = {"done": True}

    return {"n": len(hits), "hits": hits, "cursor": cursor, "engine": "objdump"}
