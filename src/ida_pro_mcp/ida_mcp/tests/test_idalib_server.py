"""Tests for idalib_server integration helpers."""

import hashlib
import os
import sys
import tempfile
from pathlib import Path

from ..framework import test

try:
    from ida_pro_mcp import idalib_server
    from ida_pro_mcp import idalib_supervisor
except ImportError:
    _parent = os.path.join(os.path.dirname(__file__), "..", "..")
    sys.path.insert(0, _parent)
    try:
        import idalib_server  # type: ignore
        import idalib_supervisor  # type: ignore
    finally:
        sys.path.remove(_parent)


class _FakeMcp:
    """Minimal stand-in so IdalibSupervisor can be built without a server."""

    def get_current_transport_session_id(self):
        return None


def _make_supervisor() -> "idalib_supervisor.IdalibSupervisor":
    return idalib_supervisor.IdalibSupervisor(_FakeMcp())


@test()
def test_idalib_health_treats_successful_server_health_as_ready():
    """idalib_health should report ready when server_health returns a healthy payload."""
    original_get_session_manager = idalib_server.get_session_manager
    original_resolve_context = idalib_server._resolve_effective_context_id
    original_context_fields = idalib_server._context_response_fields
    original_server_health = idalib_server.server_health

    class _FakeSession:
        def to_dict(self):
            return {"session_id": "sess-1", "input_path": "dummy.bin"}

    class _FakeManager:
        def get_context_session(self, context_id):
            return _FakeSession()

        def activate_context(self, context_id):
            self.activated = context_id

    idalib_server.get_session_manager = lambda: _FakeManager()
    idalib_server._resolve_effective_context_id = lambda: "ctx-1"
    idalib_server._context_response_fields = lambda context_id: {
        "context_id": context_id,
        "transport_context_id": None,
        "isolated_contexts": False,
    }
    idalib_server.server_health = lambda: {
        "uptime_sec": 1.0,
        "module": "dummy.bin",
        "imagebase": "0x0",
        "strings_cache_ready": True,
        "hexrays_ready": False,
    }
    try:
        result = idalib_server.idalib_health()
        assert result["error"] is None
        assert result["health"]["module"] == "dummy.bin"
        assert result["ready"] is True
    finally:
        idalib_server.get_session_manager = original_get_session_manager
        idalib_server._resolve_effective_context_id = original_resolve_context
        idalib_server._context_response_fields = original_context_fields
        idalib_server.server_health = original_server_health


# ============================================================================
# Path resolution: suffix matching, hashing, and resolve_open_target
# ============================================================================


@test()
def test_suffix_match_len_counts_trailing_components():
    """Trailing-component overlap drives duplicate-filename disambiguation."""
    f = idalib_supervisor._suffix_match_len
    full = "F:/Reversing/mplayer/files/system/Mplayer.dll"
    # bare filename matches the filename only
    assert f(["mplayer.dll"], full) == 1
    # one dir + filename
    assert f(["system", "mplayer.dll"], full) == 2
    # backslash query against forward-slash candidate, case-insensitive
    assert f(idalib_supervisor._path_components(r"System\\Mplayer.DLL"), full) == 2
    # a wrong trailing dir breaks the match at the filename
    assert f(["programs", "mplayer.dll"], full) == 1
    # no overlap
    assert f(["other.exe"], full) == 0


@test()
def test_hash_file_verify_matches_hashlib():
    """_hash_file_verify returns the real sha256/md5 of the file bytes."""
    data = b"the quick brown fox" * 1000
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(data)
        path = tf.name
    try:
        sha256, md5 = idalib_supervisor._hash_file_verify(Path(path))
        assert sha256 == hashlib.sha256(data).hexdigest()
        assert md5 == hashlib.md5(data).hexdigest()
    finally:
        os.unlink(path)


@test()
def test_resolve_open_target_unique_filename_opens():
    """A unique registered filename resolves and opens directly."""
    sup = _make_supervisor()
    sup.record_aliases({"Solo.dll": "F:/a/Solo.dll"})
    out = sup.resolve_open_target("Solo.dll", allow_search=False)
    assert out["status"] == "open"
    assert out["path"] == "F:/a/Solo.dll"


@test()
def test_resolve_open_target_exact_path_wins():
    """An existing absolute path opens as-is regardless of the registry."""
    sup = _make_supervisor()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tf.write(b"MZ")
        path = tf.name
    try:
        out = sup.resolve_open_target(path, allow_search=False)
        assert out["status"] == "open"
        assert out["how"] == "exact path"
        assert os.path.normcase(out["path"]) == os.path.normcase(path)
    finally:
        os.unlink(path)


@test()
def test_resolve_open_target_duplicate_bare_filename_is_ambiguous():
    """A bare filename shared by multiple paths returns candidates, not a guess."""
    sup = _make_supervisor()
    sup.record_aliases({"Mplayer.dll": "F:/a/system/Mplayer.dll"})
    sup.record_aliases({"Mplayer.dll": "F:/a/Programs/Mplayer.dll"})
    out = sup.resolve_open_target("Mplayer.dll", allow_search=False)
    assert out["status"] == "ambiguous"
    assert set(out["candidates"]) == {
        "F:/a/system/Mplayer.dll",
        "F:/a/Programs/Mplayer.dll",
    }


@test()
def test_resolve_open_target_suffix_disambiguates_duplicates():
    """Trailing path components pick the right copy among duplicate names."""
    sup = _make_supervisor()
    sup.record_aliases({"Mplayer.dll": "F:/a/system/Mplayer.dll"})
    sup.record_aliases({"Mplayer.dll": "F:/a/Programs/Mplayer.dll"})
    out = sup.resolve_open_target("system/Mplayer.dll", allow_search=False)
    assert out["status"] == "open"
    assert out["path"] == "F:/a/system/Mplayer.dll"


@test()
def test_resolve_open_target_miss_returns_suggestions():
    """A typo'd unknown filename misses and suggests near matches."""
    sup = _make_supervisor()
    sup.record_aliases({"Mplayer.dll": "F:/a/Mplayer.dll"})
    out = sup.resolve_open_target("Mplaer.dll", allow_search=False)
    assert out["status"] == "miss"
    assert "Mplayer.dll" in out["suggestions"]


@test()
def test_resolve_open_target_on_disk_search_finds_and_registers():
    """When the filename is unknown, a bounded on-disk search under a configured
    search root finds it, registers an alias, and resolves."""
    with tempfile.TemporaryDirectory() as root:
        sub = Path(root) / "system"
        sub.mkdir()
        target = sub / "Found.bin"
        target.write_bytes(b"MZ\x00\x00")

        sup = _make_supervisor()
        sup.search_roots = [root]
        out = sup.resolve_open_target("Found.bin", allow_search=True)
        assert out["status"] == "open"
        assert os.path.normcase(out["path"]) == os.path.normcase(str(target))
        # The hit is now cached in the alias registry for instant re-resolution.
        assert "Found.bin" in sup.alias_registry


@test()
def test_iter_candidate_files_reports_skipped_subdirs():
    """Non-recursive iteration yields top-level files and reports subdirs."""
    with tempfile.TemporaryDirectory() as root:
        (Path(root) / "top.exe").write_bytes(b"MZ")
        (Path(root) / "sub").mkdir()
        (Path(root) / "sub" / "deep.exe").write_bytes(b"MZ")

        seen_subdirs: list[str] = []
        files = [
            p.name
            for p, _st in idalib_supervisor._iter_candidate_files(
                Path(root),
                False,
                lambda *_: None,
                on_subdir=lambda d: seen_subdirs.append(d),
            )
        ]
        assert "top.exe" in files
        assert "deep.exe" not in files  # non-recursive
        assert len(seen_subdirs) == 1
