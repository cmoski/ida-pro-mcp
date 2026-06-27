"""Generic async job queue for long-running tool calls.

Pure stdlib, NO idaapi dependency on purpose (same discipline as inflight.py):
everything here runs in HTTP-handler / worker threads and is unit-testable
without IDA. The actual IDA work happens inside the `run` callable the caller
passes to `submit()` — that callable is what marshals onto the main thread via
the tool's own @idasync wrapper. This module only owns scheduling and state.

Why this exists
---------------
Long IDA work (full analysis, decompiling huge functions, whole-binary search)
otherwise holds the MCP `tools/call` HTTP request open for its entire duration,
which trips client-side request timeouts and long-held worker connections. A job
decouples the work from the request: `submit_job` returns a job id immediately,
and the client polls `job_status` (a cheap dict read, like server_liveness) until
the job is terminal.

What it does NOT give you
-------------------------
Parallelism. IDA's SDK is single-threaded: every @idasync call serializes on the
one main thread via execute_sync(MFF_WRITE). So a single worker thread drains the
queue — running jobs concurrently would only contend on that one lock and produce
confusing interleaving. The win is lifecycle decoupling + cheap polling +
cooperative cancellation, not concurrent execution.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# Job status values (plain strings so they serialize directly into tool output).
PENDING = "pending"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
CANCELLED = "cancelled"

_TERMINAL = frozenset({COMPLETED, FAILED, CANCELLED})

# How long terminal jobs are retained before cleanup sweeps them (seconds).
DEFAULT_RETENTION_SEC = 3600.0


@dataclass
class Job:
    """One queued/running/finished tool invocation."""

    job_id: str
    tool: str
    arguments: dict[str, Any]
    timeout: Optional[float]
    # threading.Event the run callable / sync layer checks to abort cooperatively.
    cancel_event: threading.Event = field(default_factory=threading.Event)
    status: str = PENDING
    result: Any = None
    error: Optional[str] = None
    created: float = field(default_factory=time.monotonic)
    started: Optional[float] = None
    completed: Optional[float] = None

    def is_terminal(self) -> bool:
        return self.status in _TERMINAL

    def duration_sec(self) -> Optional[float]:
        if self.started is None:
            return None
        end = self.completed if self.completed is not None else time.monotonic()
        return round(end - self.started, 3)

    def to_dict(self, *, include_result: bool = False) -> dict[str, Any]:
        """Serialize for tool output. Result is included only when asked and
        the job completed — failed jobs surface `error` instead."""
        out: dict[str, Any] = {
            "job_id": self.job_id,
            "tool": self.tool,
            "status": self.status,
            "duration_seconds": self.duration_sec(),
        }
        if self.error is not None:
            out["error"] = self.error
        if include_result and self.status == COMPLETED:
            out["result"] = self.result
        return out


class JobManager:
    """Schedules jobs onto a single background worker thread.

    `run` (passed to submit) has signature run(job: Job) -> Any. It is invoked
    on the worker thread and must perform the actual tool dispatch; its return
    value becomes the job result. Raising marks the job failed (or cancelled, if
    the job's cancel_event was set). Keeping `run` injected — rather than baking
    in MCP/IDA dispatch — is what keeps this module idaapi-free and unit-testable.
    """

    def __init__(self, retention_sec: float = DEFAULT_RETENTION_SEC) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, Job] = {}
        self._runners: dict[str, Callable[[Job], Any]] = {}
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._retention_sec = retention_sec
        self._worker: Optional[threading.Thread] = None

    # -- submission ---------------------------------------------------------

    def submit(
        self,
        tool: str,
        arguments: dict[str, Any] | None,
        run: Callable[[Job], Any],
        *,
        timeout: Optional[float] = None,
    ) -> Job:
        """Create a job, enqueue it, and return it immediately (status pending)."""
        self._cleanup_old()
        job = Job(
            job_id=uuid.uuid4().hex,
            tool=tool,
            arguments=dict(arguments or {}),
            timeout=timeout,
        )
        with self._lock:
            self._jobs[job.job_id] = job
            self._runners[job.job_id] = run
            self._ensure_worker_locked()
        self._queue.put(job.job_id)
        logger.info("Job submitted: %s tool=%s", job.job_id, tool)
        return job

    def run_inline(
        self,
        tool: str,
        arguments: dict[str, Any] | None,
        run: Callable[[Job], Any],
        *,
        timeout: Optional[float] = None,
    ) -> Job:
        """Create a job and run it synchronously on the calling thread.

        For single-threaded servers (headless idalib) where a background worker's
        execute_sync would never be pumped: the work runs inline so it can't
        deadlock, and the job is still recorded so job_status/job_list find it.
        Returns the job already in a terminal state.
        """
        self._cleanup_old()
        job = Job(
            job_id=uuid.uuid4().hex,
            tool=tool,
            arguments=dict(arguments or {}),
            timeout=timeout,
        )
        with self._lock:
            self._jobs[job.job_id] = job
            self._runners[job.job_id] = run
            job.status = RUNNING
            job.started = time.monotonic()
        logger.info("Job started (inline): %s tool=%s", job.job_id, tool)
        self._execute(job, run)
        return job

    # -- queries ------------------------------------------------------------

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self, status: Optional[str] = None) -> list[Job]:
        with self._lock:
            jobs = list(self._jobs.values())
        if status is not None:
            jobs = [j for j in jobs if j.status == status]
        # Most recent first.
        jobs.sort(key=lambda j: j.created, reverse=True)
        return jobs

    # -- cancellation -------------------------------------------------------

    def cancel(self, job_id: str) -> bool:
        """Request cancellation. Returns True if the job exists and was not
        already terminal. A pending job is cancelled immediately; a running
        job's cancel_event is set so the sync layer aborts it cooperatively."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.is_terminal():
                return False
            job.cancel_event.set()
            if job.status == PENDING:
                # Never started — mark cancelled now; the worker skips it on pop.
                job.status = CANCELLED
                job.completed = time.monotonic()
        logger.info("Job cancel requested: %s", job_id)
        return True

    # -- worker -------------------------------------------------------------

    def _ensure_worker_locked(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        self._worker = threading.Thread(
            target=self._worker_loop, name="ida-mcp-job-worker", daemon=True
        )
        self._worker.start()

    def _worker_loop(self) -> None:
        while True:
            job_id = self._queue.get()
            try:
                self._run_one(job_id)
            except Exception:  # pragma: no cover - defensive; _run_one catches its own
                logger.exception("Job worker crashed handling %s", job_id)
            finally:
                self._queue.task_done()

    def _run_one(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            run = self._runners.get(job_id)
            if job is None or run is None:
                return
            # Cancelled while still pending — skip without running.
            if job.status != PENDING:
                return
            job.status = RUNNING
            job.started = time.monotonic()
        logger.info("Job started: %s tool=%s", job.job_id, job.tool)
        self._execute(job, run)

    def _execute(self, job: Job, run: Callable[[Job], Any]) -> None:
        """Run the job body and record its terminal state. Assumes job is
        already marked RUNNING with started set. Shared by the worker thread
        and the inline path."""
        try:
            result = run(job)
        except BaseException as e:  # noqa: BLE001 - record everything, incl. cancellation
            cancelled = job.cancel_event.is_set()
            with self._lock:
                job.completed = time.monotonic()
                if cancelled:
                    job.status = CANCELLED
                else:
                    job.status = FAILED
                    job.error = f"{type(e).__name__}: {e}"
            level = logging.INFO if cancelled else logging.ERROR
            logger.log(
                level,
                "Job %s: %s (%.3fs)",
                job.job_id,
                "cancelled" if cancelled else "failed",
                job.duration_sec() or 0.0,
            )
            return
        with self._lock:
            job.completed = time.monotonic()
            # cancel may have raced in after run() returned cleanly; honor it.
            if job.cancel_event.is_set() and job.status == RUNNING:
                job.status = CANCELLED
            else:
                job.result = result
                job.status = COMPLETED
        logger.info("Job completed: %s (%.3fs)", job.job_id, job.duration_sec() or 0.0)

    # -- maintenance --------------------------------------------------------

    def _cleanup_old(self) -> None:
        cutoff = time.monotonic() - self._retention_sec
        with self._lock:
            stale = [
                jid
                for jid, j in self._jobs.items()
                if j.is_terminal() and j.completed is not None and j.completed < cutoff
            ]
            for jid in stale:
                self._jobs.pop(jid, None)
                self._runners.pop(jid, None)
        if stale:
            logger.info("Cleaned up %d old job(s)", len(stale))
