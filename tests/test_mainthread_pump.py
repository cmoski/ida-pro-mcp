"""Main-thread job pump tests (no IDA required)."""

import importlib.util
import threading
import time
from pathlib import Path

import pytest

# Import by path: ida_mcp/__init__.py pulls in IDA, which is absent here.
_spec = importlib.util.spec_from_file_location(
    "ida_mcp_mainthread",
    Path(__file__).resolve().parents[1] / "src/ida_pro_mcp/ida_mcp/mainthread.py",
)
assert _spec is not None and _spec.loader is not None
_mainthread = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mainthread)
MainThreadPump = _mainthread.MainThreadPump
PumpBusyError = _mainthread.PumpBusyError


def _run_pump(pump: MainThreadPump) -> threading.Thread:
    thread = threading.Thread(target=pump.run, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    for _ in range(200):
        if pump.active:
            return thread
        time.sleep(0.01)
    raise AssertionError("pump did not start")


def test_submit_runs_job_on_pump_thread():
    pump = MainThreadPump()
    thread = _run_pump(pump)
    try:
        assert pump.submit(lambda: threading.get_ident(), timeout=5) == thread.ident
    finally:
        pump.stop()


def test_submit_propagates_exception():
    pump = MainThreadPump()
    _run_pump(pump)
    try:
        with pytest.raises(ValueError, match="boom"):
            pump.submit(lambda: (_ for _ in ()).throw(ValueError("boom")), timeout=5)
    finally:
        pump.stop()


def test_submit_on_pump_thread_runs_inline():
    pump = MainThreadPump()
    _run_pump(pump)
    try:
        nested = pump.submit(lambda: pump.submit(lambda: "inner", timeout=5), timeout=5)
        assert nested == "inner"
    finally:
        pump.stop()


def test_busy_status_reports_running_job():
    pump = MainThreadPump()
    _run_pump(pump)
    release = threading.Event()
    try:
        blocker = threading.Thread(
            target=lambda: pump.submit(release.wait, label="slow", timeout=10), daemon=True
        )
        blocker.start()
        for _ in range(200):
            if pump.busy_status() is not None:
                break
            time.sleep(0.01)
        busy = pump.busy_status()
        assert busy is not None and busy["tool"] == "slow"
        assert busy["elapsed_sec"] >= 0
    finally:
        release.set()
        pump.stop()


def test_submit_times_out_while_pump_is_busy():
    pump = MainThreadPump()
    _run_pump(pump)
    release = threading.Event()
    try:
        blocker = threading.Thread(
            target=lambda: pump.submit(release.wait, label="slow", timeout=10), daemon=True
        )
        blocker.start()
        time.sleep(0.05)
        with pytest.raises(PumpBusyError, match="slow"):
            pump.submit(lambda: "never", label="quick", timeout=0.2)
    finally:
        release.set()
        pump.stop()


def test_queued_job_is_dropped_after_its_waiter_gives_up():
    pump = MainThreadPump()
    _run_pump(pump)
    release = threading.Event()
    ran = []
    try:
        blocker = threading.Thread(
            target=lambda: pump.submit(release.wait, label="slow", timeout=10), daemon=True
        )
        blocker.start()
        time.sleep(0.05)
        with pytest.raises(PumpBusyError):
            pump.submit(lambda: ran.append("late"), label="abandoned", timeout=0.2)
        release.set()
        time.sleep(0.2)
        assert ran == []
    finally:
        release.set()
        pump.stop()


def test_submit_without_running_pump_raises():
    pump = MainThreadPump()
    with pytest.raises(RuntimeError, match="not running"):
        pump.submit(lambda: None, timeout=1)


def test_stop_fails_pending_jobs():
    pump = MainThreadPump()
    _run_pump(pump)
    release = threading.Event()
    blocker = threading.Thread(
        target=lambda: pump.submit(release.wait, label="slow", timeout=10), daemon=True
    )
    blocker.start()
    time.sleep(0.05)

    errors = []

    def pending():
        try:
            pump.submit(lambda: "never", label="pending", timeout=10)
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    waiter = threading.Thread(target=pending, daemon=True)
    waiter.start()
    time.sleep(0.05)
    pump.stop()
    release.set()
    waiter.join(timeout=5)

    assert errors and "shutting down" in str(errors[0])


def test_job_submitted_before_run_is_queued_not_rejected():
    """Arming closes the window between serve() and run()."""
    pump = MainThreadPump()
    pump.arm()
    results: list = []
    submitter = threading.Thread(
        target=lambda: results.append(pump.submit(lambda: "late", timeout=5)),
        daemon=True,
    )
    submitter.start()
    time.sleep(0.05)
    assert results == []
    runner = threading.Thread(target=pump.run, kwargs={"poll_interval": 0.01}, daemon=True)
    runner.start()
    submitter.join(timeout=5)
    pump.stop()
    assert results == ["late"]


class _FakeAnalysis:
    """Resumable work that honours a sticky cancel flag, like ida_auto.auto_wait."""

    def __init__(self, units: int, unit_sec: float = 0.005):
        self.remaining = units
        self.unit_sec = unit_sec
        self.cancel = threading.Event()
        self.thread_ids: set[int] = set()
        self.preempts = 0

    def slice(self) -> bool:
        self.thread_ids.add(threading.get_ident())
        while self.remaining > 0:
            if self.cancel.is_set():
                return False
            time.sleep(self.unit_sec)
            self.remaining -= 1
        return True

    def preempt(self):
        self.preempts += 1
        self.cancel.set()

    def reset(self):
        self.cancel.clear()


def _attach(pump, work, label="auto_analysis"):
    pump.set_background(work.slice, preempt=work.preempt, reset=work.reset, label=label)


def _wait_until(cond, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False


def test_background_task_runs_to_completion_on_pump_thread():
    pump = MainThreadPump()
    work = _FakeAnalysis(units=50)
    _attach(pump, work)
    thread = _run_pump(pump)
    try:
        assert _wait_until(lambda: work.remaining == 0)
        assert _wait_until(lambda: pump.background_status() is None)
        assert work.thread_ids == {thread.ident}
    finally:
        pump.stop()


def test_job_preempts_background_and_background_resumes():
    pump = MainThreadPump()
    work = _FakeAnalysis(units=2000)  # ~10 s if never interrupted
    _attach(pump, work)
    _run_pump(pump)
    try:
        assert _wait_until(lambda: (pump.background_status() or {}).get("running_now"))
        t0 = time.monotonic()
        seen_cancel = pump.submit(lambda: work.cancel.is_set(), timeout=5)
        assert time.monotonic() - t0 < 1.0  # served promptly, not after analysis
        assert seen_cancel is False  # preempt flag does not leak into the job
        assert work.preempts >= 1
        left = work.remaining
        assert left > 0
        assert _wait_until(lambda: work.remaining < left)  # resumed afterwards
        status = pump.background_status()
        assert status is not None and status["task"] == "auto_analysis"
        assert status["slices"] >= 1
    finally:
        pump.stop()


def test_many_jobs_during_background_all_complete():
    pump = MainThreadPump()
    work = _FakeAnalysis(units=400)
    _attach(pump, work)
    _run_pump(pump)
    try:
        results = [pump.submit(lambda i=i: i * 2, timeout=5) for i in range(25)]
        assert results == [i * 2 for i in range(25)]
        assert _wait_until(lambda: work.remaining == 0)
    finally:
        pump.stop()


def test_failing_background_task_is_detached_and_pump_keeps_serving():
    pump = MainThreadPump()

    def boom():
        raise RuntimeError("analysis blew up")

    pump.set_background(boom, preempt=lambda: None, reset=lambda: None, label="bad")
    _run_pump(pump)
    try:
        assert _wait_until(lambda: pump.background_status() is None)
        assert pump.submit(lambda: 7, timeout=5) == 7
    finally:
        pump.stop()


def test_stop_interrupts_a_running_background_slice():
    pump = MainThreadPump()
    work = _FakeAnalysis(units=100000)
    _attach(pump, work)
    thread = _run_pump(pump)
    assert _wait_until(lambda: (pump.background_status() or {}).get("running_now"))
    pump.stop()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert work.remaining > 0


def test_clear_background_detaches_task():
    pump = MainThreadPump()
    work = _FakeAnalysis(units=100000)
    _attach(pump, work)
    _run_pump(pump)
    try:
        assert _wait_until(lambda: (pump.background_status() or {}).get("running_now"))
        pump.clear_background()
        assert pump.background_status() is None
        time.sleep(0.05)  # let the interrupted slice finish its current unit
        left = work.remaining
        time.sleep(0.2)
        assert work.remaining == left  # no further slices
        assert pump.submit(lambda: "ok", timeout=5) == "ok"
    finally:
        pump.stop()
