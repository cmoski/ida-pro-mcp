"""Inflight tool-call tracker.

Pure stdlib, NO idaapi dependency on purpose: this state is read and written
only in HTTP handler threads (in sync.sync_wrapper, around execute_sync), never
on the IDA main thread. That independence is what lets server_liveness() answer
instantly even while a long @idasync tool holds execute_sync(MFF_WRITE) — the
liveness probe reads this plain-Python state instead of queueing behind the
main-thread lock like server_health() does.

Kept as its own module (rather than living in sync.py) so it can be unit-tested
without importing idaapi.
"""

from __future__ import annotations

import threading
import time

_lock = threading.Lock()
_inflight: dict[int, tuple[str, float]] = {}
_seq = 0


def inflight_enter(tool_name: str) -> int:
    """Record a tool call as in-flight. Returns a token for inflight_exit()."""
    global _seq
    with _lock:
        _seq += 1
        token = _seq
        _inflight[token] = (tool_name, time.monotonic())
        return token


def inflight_exit(token: int) -> None:
    """Clear the in-flight record for a token. Idempotent."""
    with _lock:
        _inflight.pop(token, None)


def inflight_snapshot() -> dict:
    """Return current inflight state without touching the IDA main thread.

    depth: number of @idasync calls queued+running (at most one is actually
    executing on the main thread; the rest are blocked in execute_sync). tool
    and inflight_seconds describe the OLDEST in-flight call — i.e. the one most
    likely holding the main thread and the most useful "how long has it been
    stuck" signal.
    """
    with _lock:
        if not _inflight:
            return {"depth": 0, "tool": None, "inflight_seconds": 0.0}
        oldest_tool, oldest_start = min(_inflight.values(), key=lambda v: v[1])
        return {
            "depth": len(_inflight),
            "tool": oldest_tool,
            "inflight_seconds": round(time.monotonic() - oldest_start, 3),
        }
