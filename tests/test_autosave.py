"""Idle auto-save policy tests (no IDA required)."""

from ida_pro_mcp.autosave import IdleAutosave


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _ok():
    return True, None


def test_enabled_by_default_and_clean_until_changed():
    a = IdleAutosave()
    assert a.enabled is True
    assert a.idle_sec == IdleAutosave.DEFAULT_IDLE_SEC
    assert a.dirty is False
    assert a.maybe_save(idle_for_sec=9999, busy=False, save=_ok) is False


def test_saves_only_when_dirty_idle_and_not_busy():
    a = IdleAutosave(idle_sec=30)
    a.mark_dirty()
    assert a.maybe_save(idle_for_sec=10, busy=False, save=_ok) is False  # not idle long enough
    assert a.maybe_save(idle_for_sec=60, busy=True, save=_ok) is False  # tool call running
    assert a.maybe_save(idle_for_sec=60, busy=False, save=_ok) is True
    assert a.dirty is False
    assert a.saves == 1
    # Nothing changed since: no second save.
    assert a.maybe_save(idle_for_sec=600, busy=False, save=_ok) is False


def test_disable_and_reenable():
    a = IdleAutosave(idle_sec=5)
    a.configure(enabled=False)
    a.mark_dirty()
    assert a.maybe_save(idle_for_sec=600, busy=False, save=_ok) is False
    assert a.dirty is True
    a.configure(enabled=True)
    assert a.maybe_save(idle_for_sec=600, busy=False, save=_ok) is True


def test_idle_sec_has_a_floor():
    a = IdleAutosave(idle_sec=0)
    assert a.idle_sec == IdleAutosave.MIN_IDLE_SEC
    a.configure(idle_sec=1)
    assert a.idle_sec == IdleAutosave.MIN_IDLE_SEC


def test_failed_save_stays_dirty_and_reports_error():
    a = IdleAutosave(idle_sec=5)
    a.mark_dirty()
    assert a.maybe_save(idle_for_sec=60, busy=False, save=lambda: (False, "disk full")) is False
    snap = a.snapshot()
    assert snap["dirty"] is True
    assert snap["last_save_ok"] is False
    assert snap["last_error"] == "disk full"


def test_exception_in_save_is_contained():
    a = IdleAutosave(idle_sec=5)
    a.mark_dirty()

    def boom():
        raise RuntimeError("kaboom")

    assert a.maybe_save(idle_for_sec=60, busy=False, save=boom) is False
    assert a.snapshot()["last_error"] == "kaboom"


def test_events_raised_by_the_save_itself_are_ignored():
    a = IdleAutosave(idle_sec=5)
    a.mark_dirty()

    def save_that_fires_hooks():
        a.mark_dirty()  # e.g. IDB events emitted while flushing
        return True, None

    assert a.maybe_save(idle_for_sec=60, busy=False, save=save_that_fires_hooks) is True
    assert a.dirty is False


def test_external_save_marks_clean():
    a = IdleAutosave()
    a.mark_dirty()
    a.mark_clean()
    assert a.dirty is False


def test_snapshot_reports_save_age():
    clock = _Clock()
    a = IdleAutosave(idle_sec=5, clock=clock)
    a.mark_dirty()
    a.maybe_save(idle_for_sec=60, busy=False, save=_ok)
    clock.t += 42
    snap = a.snapshot()
    assert snap["last_save_age_sec"] == 42
    assert snap["saves"] == 1
    assert snap["enabled"] is True


def test_min_interval_spaces_out_saves_while_db_keeps_changing():
    clock = _Clock()
    a = IdleAutosave(idle_sec=5, clock=clock)
    a.mark_dirty()
    assert a.maybe_save(idle_for_sec=60, busy=False, save=_ok, min_interval_sec=900) is True
    a.mark_dirty()  # background analysis keeps changing the database
    clock.t += 30
    assert a.maybe_save(idle_for_sec=90, busy=False, save=_ok, min_interval_sec=900) is False
    clock.t += 900
    assert a.maybe_save(idle_for_sec=990, busy=False, save=_ok, min_interval_sec=900) is True
    assert a.saves == 2
