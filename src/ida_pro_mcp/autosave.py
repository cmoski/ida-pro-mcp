"""Idle auto-save policy for idalib workers.

A headless worker holds its database as loose working files until it closes
cleanly. If the process dies (crash, kill, host reboot) everything since the
last save is lost. ``IdleAutosave`` decides when to save: the database has
changed since the last save, no tool call is running, and no request has
arrived for ``idle_sec`` seconds. It is on by default; clients can disable it
or change the delay per session.

Change tracking is generation based: ``mark_dirty`` bumps a counter (called
from IDB change hooks), a save records the generation it started from, and
changes that arrive while a save is running keep the database dirty. Hook
events raised by the save itself are ignored.

No IDA imports, so it can be unit-tested outside IDA; the worker supplies the
actual save callable.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable


class IdleAutosave:
    DEFAULT_IDLE_SEC = 60.0
    MIN_IDLE_SEC = 5.0

    def __init__(
        self,
        *,
        enabled: bool = True,
        idle_sec: float = DEFAULT_IDLE_SEC,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._lock = threading.Lock()
        self._clock = clock
        self.enabled = bool(enabled)
        self.idle_sec = max(self.MIN_IDLE_SEC, float(idle_sec))
        self._generation = 0
        self._saved_generation = 0
        self._saving = False
        self.saves = 0
        self.last_save_at: float | None = None
        self.last_save_ok: bool | None = None
        self.last_error: str | None = None

    # -- configuration ---------------------------------------------------

    def configure(self, *, enabled: bool | None = None, idle_sec: float | None = None) -> None:
        with self._lock:
            if enabled is not None:
                self.enabled = bool(enabled)
            if idle_sec is not None:
                self.idle_sec = max(self.MIN_IDLE_SEC, float(idle_sec))

    # -- change tracking -------------------------------------------------

    def mark_dirty(self) -> None:
        with self._lock:
            if self._saving:
                return  # events raised by our own save
            self._generation += 1

    def mark_clean(self) -> None:
        """Record that the database was saved by someone else (e.g. idb_save)."""
        with self._lock:
            self._saved_generation = self._generation

    @property
    def dirty(self) -> bool:
        with self._lock:
            return self._generation != self._saved_generation

    # -- decision + execution -------------------------------------------

    def due(self, *, idle_for_sec: float, busy: bool, min_interval_sec: float = 0.0) -> bool:
        """``min_interval_sec`` spaces out saves while the database keeps
        changing without client requests (background auto-analysis), which
        would otherwise re-save on every poll."""
        with self._lock:
            if (
                min_interval_sec > 0
                and self.last_save_at is not None
                and self._clock() - self.last_save_at < min_interval_sec
            ):
                return False
            return (
                self.enabled
                and not self._saving
                and not busy
                and self._generation != self._saved_generation
                and idle_for_sec >= self.idle_sec
            )

    def run_save(self, save: Callable[[], tuple[bool, str | None]]) -> bool:
        """Run ``save`` (returns (ok, error)) and record the outcome."""
        with self._lock:
            if self._saving:
                return False
            self._saving = True
            started_gen = self._generation
        ok, error = False, None
        try:
            ok, error = save()
        except Exception as e:  # never let the watchdog thread die
            ok, error = False, str(e)
        finally:
            with self._lock:
                self._saving = False
                self.last_save_at = self._clock()
                self.last_save_ok = bool(ok)
                self.last_error = None if ok else (error or "save failed")
                if ok:
                    self.saves += 1
                    self._saved_generation = started_gen
        return bool(ok)

    def maybe_save(
        self,
        *,
        idle_for_sec: float,
        busy: bool,
        save: Callable[[], tuple[bool, str | None]],
        min_interval_sec: float = 0.0,
    ) -> bool:
        if not self.due(idle_for_sec=idle_for_sec, busy=busy, min_interval_sec=min_interval_sec):
            return False
        return self.run_save(save)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            age = None
            if self.last_save_at is not None:
                age = round(self._clock() - self.last_save_at, 2)
            return {
                "enabled": self.enabled,
                "idle_sec": self.idle_sec,
                "dirty": self._generation != self._saved_generation,
                "saves": self.saves,
                "last_save_age_sec": age,
                "last_save_ok": self.last_save_ok,
                "last_error": self.last_error,
            }
