"""Unit tests for the generic async job queue (jobs.JobManager).

Pure logic — no idaapi — exercised with fake runner callables so we cover the
scheduling/state machine without IDA. Binary-agnostic (@test() with no binary).
"""

import threading
import time

from ..framework import test
from .. import jobs


def _wait_status(manager, job_id, status, timeout=5.0):
    """Poll until the job reaches `status`, or fail after `timeout`."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = manager.get(job_id)
        if job is not None and job.status == status:
            return job
        time.sleep(0.005)
    job = manager.get(job_id)
    raise AssertionError(
        f"job {job_id} did not reach {status!r} in {timeout}s "
        f"(last status: {None if job is None else job.status})"
    )


@test()
def test_jobs_submit_runs_and_completes():
    """A submitted job runs on the worker and stores its result."""
    mgr = jobs.JobManager()
    job = mgr.submit("echo", {"x": 1}, lambda j: {"echoed": j.arguments["x"]})
    # Returned immediately, not yet terminal.
    assert job.status in (jobs.PENDING, jobs.RUNNING)

    done = _wait_status(mgr, job.job_id, jobs.COMPLETED)
    assert done.result == {"echoed": 1}
    assert done.error is None
    assert done.duration_sec() is not None
    # Result only surfaces in to_dict when explicitly requested + completed.
    assert "result" not in done.to_dict()
    assert done.to_dict(include_result=True)["result"] == {"echoed": 1}


@test()
def test_jobs_failure_is_captured():
    """A runner that raises leaves the job FAILED with the error message."""
    mgr = jobs.JobManager()

    def boom(_job):
        raise ValueError("kaboom")

    job = mgr.submit("boom", {}, boom)
    failed = _wait_status(mgr, job.job_id, jobs.FAILED)
    assert failed.error is not None
    assert "kaboom" in failed.error
    assert failed.result is None


@test()
def test_jobs_cancel_running_marks_cancelled():
    """Cancelling a running job sets its event; a cooperative runner aborts."""
    mgr = jobs.JobManager()
    started = threading.Event()

    def blocker(job):
        started.set()
        while not job.cancel_event.is_set():
            time.sleep(0.005)
        raise RuntimeError("aborted on cancel")

    job = mgr.submit("blocker", {}, blocker)
    assert started.wait(5.0), "runner never started"
    assert mgr.cancel(job.job_id) is True
    cancelled = _wait_status(mgr, job.job_id, jobs.CANCELLED)
    # Cancellation wins over the runner's exception -> not FAILED.
    assert cancelled.status == jobs.CANCELLED
    assert cancelled.error is None


@test()
def test_jobs_cancel_pending_skips_execution():
    """A job cancelled while still queued never runs its runner."""
    mgr = jobs.JobManager()
    release = threading.Event()
    first_started = threading.Event()
    second_ran = threading.Event()

    def hog(_job):
        first_started.set()
        release.wait(5.0)
        return "first"

    def should_not_run(_job):
        second_ran.set()
        return "second"

    first = mgr.submit("hog", {}, hog)
    assert first_started.wait(5.0), "first job never started"
    # Worker is busy on `first`; this one stays pending.
    second = mgr.submit("second", {}, should_not_run)
    assert mgr.get(second.job_id).status == jobs.PENDING
    assert mgr.cancel(second.job_id) is True
    assert mgr.get(second.job_id).status == jobs.CANCELLED

    release.set()
    _wait_status(mgr, first.job_id, jobs.COMPLETED)
    # Give the worker a moment to (not) pick up the cancelled job.
    time.sleep(0.05)
    assert not second_ran.is_set(), "cancelled-pending job should not execute"


@test()
def test_jobs_cancel_unknown_and_terminal_return_false():
    """cancel() is False for unknown ids and already-terminal jobs."""
    mgr = jobs.JobManager()
    assert mgr.cancel("does-not-exist") is False
    job = mgr.submit("echo", {}, lambda j: "ok")
    _wait_status(mgr, job.job_id, jobs.COMPLETED)
    assert mgr.cancel(job.job_id) is False


@test()
def test_jobs_list_and_filter():
    """list() returns most-recent-first and honors the status filter."""
    mgr = jobs.JobManager()
    a = mgr.submit("a", {}, lambda j: 1)
    # Ensure distinct created timestamps so recency ordering is unambiguous
    # (monotonic() can tie for two back-to-back submits).
    time.sleep(0.01)
    b = mgr.submit("b", {}, lambda j: 2)
    _wait_status(mgr, a.job_id, jobs.COMPLETED)
    _wait_status(mgr, b.job_id, jobs.COMPLETED)

    all_jobs = mgr.list()
    assert {j.job_id for j in all_jobs} >= {a.job_id, b.job_id}
    # Most recent (b) first.
    ids = [j.job_id for j in all_jobs]
    assert ids.index(b.job_id) < ids.index(a.job_id)

    completed = mgr.list(status=jobs.COMPLETED)
    assert all(j.status == jobs.COMPLETED for j in completed)
    assert mgr.list(status=jobs.RUNNING) == []


@test()
def test_jobs_get_unknown_returns_none():
    mgr = jobs.JobManager()
    assert mgr.get("nope") is None


@test()
def test_jobs_retention_cleanup_purges_old_terminal_jobs():
    """A terminal job older than the retention window is swept on next submit."""
    mgr = jobs.JobManager(retention_sec=0.0)
    old = mgr.submit("old", {}, lambda j: "x")
    _wait_status(mgr, old.job_id, jobs.COMPLETED)
    # Ensure the completed timestamp is strictly in the past relative to cutoff.
    time.sleep(0.02)
    # Submitting a new job triggers _cleanup_old().
    fresh = mgr.submit("fresh", {}, lambda j: "y")
    _wait_status(mgr, fresh.job_id, jobs.COMPLETED)
    assert mgr.get(old.job_id) is None, "old terminal job should be purged"
