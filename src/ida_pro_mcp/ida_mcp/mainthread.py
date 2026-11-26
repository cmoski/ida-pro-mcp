"""Main-thread job pump for headless (idalib) workers.

idalib has no UI event loop, so execute_sync posted from a secondary thread is
never dispatched. IDA work must run on the thread that owns the database, so
the main thread parks here draining jobs while HTTP is served on background
threads. No IDA imports, so this is unit-testable outside IDA.

A *background task* (auto-analysis of a freshly opened database) can be
attached. It runs in short slices whenever no job is queued, so a job waits at
most one slice, runs, and the next slice resumes the work. This is what lets a
huge binary stay usable while it is still being analyzed. A slice should bound
its own length (the analysis slice steps ``auto_make_step`` against a time
budget); the optional ``preempt`` callback is for tasks that can be told to
stop early.
"""

import logging
import queue
import threading
import time
from typing import Any, Callable

logger = logging.getLogger(__name__)


class PumpBusyError(RuntimeError):
    """A job did not reach the main thread before its deadline."""


class _Job:
    __slots__ = ("fn", "label", "done", "result", "error", "cancelled", "started_at")

    def __init__(self, fn: Callable[[], Any], label: str):
        self.fn = fn
        self.label = label
        self.done = threading.Event()
        self.result: Any = None
        self.error: BaseException | None = None
        self.cancelled = False
        self.started_at: float | None = None

    def run(self) -> None:
        self.started_at = time.monotonic()
        try:
            self.result = self.fn()
        except BaseException as e:  # noqa: BLE001 - handed to the waiter
            self.error = e
        finally:
            self.done.set()


class MainThreadPump:
    """Queue of callables executed on the thread that calls :meth:`run`."""

    def __init__(self):
        self._queue: queue.Queue[_Job] = queue.Queue()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread_id: int | None = None
        self._current: _Job | None = None
        self._running = False
        # Background task: slice() -> True when finished. preempt() makes a
        # running slice return soon; reset() clears that request before a
        # slice or job starts. All three run IDA code only via callbacks.
        self._bg_slice: Callable[[], bool] | None = None
        self._bg_preempt: Callable[[], None] | None = None
        self._bg_reset: Callable[[], None] | None = None
        self._bg_label = ""
        self._bg_in_slice = False
        self._bg_started_at: float | None = None
        self._bg_slices = 0

    # -- state -------------------------------------------------------------

    @property
    def active(self) -> bool:
        return self._running

    def on_main_thread(self) -> bool:
        return self._thread_id == threading.get_ident()

    def busy_status(self) -> dict[str, Any] | None:
        """Describe the job occupying the main thread, or None if idle."""
        job = self._current
        if job is None:
            return None
        started = job.started_at
        return {
            "tool": job.label,
            "elapsed_sec": round(time.monotonic() - started, 3) if started else 0.0,
            "queued": self._queue.qsize(),
        }

    def background_status(self) -> dict[str, Any] | None:
        """Describe the attached background task, or None if there is none."""
        with self._lock:
            if self._bg_slice is None:
                return None
            started = self._bg_started_at
            return {
                "task": self._bg_label,
                "running_now": self._bg_in_slice,
                "elapsed_sec": round(time.monotonic() - started, 1) if started else 0.0,
                "slices": self._bg_slices,
            }

    def has_background(self) -> bool:
        return self._bg_slice is not None

    # -- background task ---------------------------------------------------

    def set_background(
        self,
        slice_fn: Callable[[], bool],
        *,
        preempt: Callable[[], None] | None = None,
        reset: Callable[[], None] | None = None,
        label: str = "background",
    ) -> None:
        """Attach a resumable task run in slices while no job is queued."""
        with self._lock:
            self._bg_slice = slice_fn
            self._bg_preempt = preempt
            self._bg_reset = reset
            self._bg_label = label
            self._bg_started_at = time.monotonic()
            self._bg_slices = 0

    def clear_background(self) -> None:
        with self._lock:
            preempt = self._bg_preempt if self._bg_in_slice else None
            self._bg_slice = None
            self._bg_label = ""
            self._bg_started_at = None
        if preempt is not None:
            preempt()

    def _preempt_background(self) -> None:
        with self._lock:
            preempt = self._bg_preempt if self._bg_in_slice else None
        if preempt is not None:
            try:
                preempt()
            except Exception:
                logger.exception("background preempt failed")

    def _run_background_slice(self) -> bool:
        """Run one slice if no job is waiting. Returns False if nothing ran."""
        with self._lock:
            slice_fn = self._bg_slice
            if slice_fn is None or not self._queue.empty() or self._stop.is_set():
                return False
            reset = self._bg_reset
            # Clear stale cancel requests *before* publishing in_slice: a job
            # submitted after this point sees in_slice and preempts, and that
            # request must not be wiped by the reset.
            if reset is not None:
                reset()
            self._bg_in_slice = True
        finished = False
        try:
            finished = bool(slice_fn())
        except Exception:
            logger.exception("background task '%s' failed; detaching it", self._bg_label)
            finished = True
        finally:
            with self._lock:
                self._bg_in_slice = False
                self._bg_slices += 1
                if finished and self._bg_slice is slice_fn:
                    self._bg_slice = None
                    self._bg_started_at = None
                reset = self._bg_reset
            # The preempt flag is sticky in IDA; don't leak it into the job.
            if reset is not None:
                try:
                    reset()
                except Exception:
                    logger.exception("background reset failed")
        return True

    # -- lifecycle ---------------------------------------------------------

    def arm(self) -> None:
        """Claim the calling thread as the pump thread, before run().

        HTTP starts first, and a request landing in that gap would otherwise
        call execute_sync on its handler thread and hang there forever.
        """
        self._thread_id = threading.get_ident()
        self._running = True

    def run(self, poll_interval: float = 0.25) -> None:
        """Drain jobs until :meth:`stop`. Call from the IDA main thread."""
        self.arm()
        try:
            while not self._stop.is_set():
                if self._run_background_slice():
                    continue
                try:
                    job = self._queue.get(timeout=poll_interval)
                except queue.Empty:
                    continue
                if job.cancelled:
                    job.done.set()
                    continue
                self._current = job
                try:
                    job.run()
                finally:
                    self._current = None
        finally:
            self._running = False
            self._drain_pending()

    def stop(self) -> None:
        self._stop.set()
        self._preempt_background()

    def _drain_pending(self) -> None:
        while True:
            try:
                job = self._queue.get_nowait()
            except queue.Empty:
                return
            job.error = RuntimeError("worker is shutting down")
            job.done.set()

    # -- submission --------------------------------------------------------

    def submit(
        self,
        fn: Callable[[], Any],
        *,
        label: str = "",
        timeout: float | None = None,
    ) -> Any:
        """Run `fn` on the main thread and return its result.

        Raises PumpBusyError past `timeout`. The job is dropped if it never
        started, else left running: IDA cannot be interrupted from here.
        """
        if not self._running:
            raise RuntimeError("main-thread pump is not running")
        if self.on_main_thread():
            return fn()

        job = _Job(fn, label)
        self._queue.put(job)
        self._preempt_background()
        if job.done.wait(timeout):
            if job.error is not None:
                raise job.error
            return job.result

        if job.started_at is None:
            job.cancelled = True
        busy = self.busy_status()
        raise PumpBusyError(
            f"worker did not run '{label or 'tool'}' within {timeout:.1f}s; "
            f"the IDA main thread is busy"
            + (f" with '{busy['tool']}' ({busy['elapsed_sec']:.1f}s)" if busy else "")
        )


_pump = MainThreadPump()


def get_pump() -> MainThreadPump:
    return _pump
