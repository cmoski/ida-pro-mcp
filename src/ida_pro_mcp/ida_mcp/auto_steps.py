"""Run IDA auto-analysis in small steps instead of one blocking auto_wait().

Why: in idalib, ``ida_auto.auto_wait()`` holds the Python GIL for its whole
run and ignores ``set_cancelled()``. On a large binary that freezes the worker
for minutes to hours: no other Python thread runs, so HTTP requests (and the
tool deadline timers) all stall until analysis ends, or the supervisor's open
timeout kills the worker.

``ida_auto.auto_make_step(ea1, ea2)`` analyzes a single queued address and
returns. Looping it with a time budget gives the same result as auto_wait()
(verified: identical function counts) at a few percent overhead, and hands
control back between slices, so queued tool calls run while analysis is still
in progress, and a deadline can stop the wait honestly.

A single step can still take a while (one huge function, or a FLIRT/type pass;
seconds, rarely more), which bounds how long a queued call waits.

Main thread only.
"""

from __future__ import annotations

import time
from typing import TypedDict

import ida_auto
import ida_idaapi


class StepResult(TypedDict):
    finished: bool
    steps: int
    max_step_ms: float
    elapsed_ms: float


def step_analysis(budget_sec: float) -> StepResult:
    """Analyze queued items for about ``budget_sec`` seconds.

    Returns ``finished=True`` once the queues are empty. When the stepper runs
    out of items, a final ``auto_wait()`` drains anything outside the stepped
    range and fires IDA's end-of-analysis processing. That call is normally
    instant.
    """
    start = time.perf_counter()
    end = start + max(0.0, budget_sec)
    steps = 0
    max_step = 0.0
    bad = ida_idaapi.BADADDR
    while True:
        a = time.perf_counter()
        more = ida_auto.auto_make_step(0, bad)
        b = time.perf_counter()
        if b - a > max_step:
            max_step = b - a
        if not more:
            break
        steps += 1
        if b >= end:
            return {
                "finished": False,
                "steps": steps,
                "max_step_ms": round(max_step * 1000, 1),
                "elapsed_ms": round((b - start) * 1000, 1),
            }
    ida_auto.auto_wait()
    return {
        "finished": True,
        "steps": steps,
        "max_step_ms": round(max_step * 1000, 1),
        "elapsed_ms": round((time.perf_counter() - start) * 1000, 1),
    }


def wait_analysis(deadline: float | None, *, margin_sec: float = 1.0) -> bool:
    """Step analysis until the queues are empty or ``deadline`` (a
    ``time.monotonic()`` value) is near. Returns True when analysis finished.

    Replaces bare ``auto_wait()`` in tools, so a tool deadline actually stops
    the wait instead of being ignored.
    """
    while True:
        budget = 0.25
        if deadline is not None:
            remaining = deadline - margin_sec - time.monotonic()
            if remaining <= 0:
                return bool(ida_auto.auto_is_ok())
            budget = min(budget, remaining)
        result = step_analysis(budget)
        if result["finished"]:
            return True
