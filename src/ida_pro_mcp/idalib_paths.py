"""Path resolution and binary discovery for the idalib supervisor.

Pure filesystem logic (no IDA imports): the bare-filename alias registry,
``--search-root`` pre-scanning, decisive open-target resolution (exact path ->
unique filename -> trailing-path-component match -> bounded on-disk search),
PE / non-PE header sniffing, file hashing, and handling of unpacked database
components left next to a binary.
"""

from __future__ import annotations

import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Iterable, TypedDict


class IdalibOpenCandidate(TypedDict, total=False):
    # A possible match returned when an open request is ambiguous (duplicate
    # filenames). sha256/md5 let the caller verify which copy is which; pass a
    # longer trailing path slice back to idalib_open to disambiguate.
    path: str
    filename: str
    sha256: str
    md5: str
    error: str



class PeImageInfo(TypedDict):
    path: str
    filename: str
    size: int
    mtime: str
    # Detected container format: PE, NE, LE, LX, MZ, ELF, MACHO or RAW. Only PE
    # entries are listed unless the scan passes include_non_pe=True.
    format: str
    sha1: str  # empty string when hash=False
    crc32: str  # empty string when hash=False
    machine: str
    arch: str
    bitness: int | None
    characteristics: str
    is_executable_image: bool
    is_dll: bool
    is_system: bool
    loaded: bool
    session_id: str | None
    # Empty string for normal scans; set to the configured --search-root path
    # this entry came from when list_pe_images fell back because the caller's
    # requested directory wasn't reachable from the server.
    source_root: str


class PeImageError(TypedDict):
    path: str
    error: str


class ListPeImagesResult(TypedDict, total=False):
    directory: str
    recursive: bool
    count: int
    images: list[PeImageInfo]
    errors: list[PeImageError]
    truncated: bool
    limit_hit: str
    error: str
    # Populated when the requested directory was not reachable but the
    # supervisor served the call from --search-root pre-configured directories.
    fallback_to_search_roots: bool
    searched_roots: list[str]
    notes: list[str]



_PE_MACHINE_TABLE: dict[int, tuple[str, int | None]] = {
    0x014C: ("x86", 32),
    0x8664: ("x64", 64),
    0x01C0: ("arm", 32),
    0x01C4: ("armnt", 32),
    0xAA64: ("arm64", 64),
    0xA641: ("arm64ec", 64),
    0x0200: ("ia64", 64),
}

_PE_OPT_MAGIC_BITNESS: dict[int, int] = {
    0x10B: 32,
    0x20B: 64,
}

_HASH_CHUNK_SIZE = 1024 * 1024

# IDA on-disk artifacts that sit next to an analyzed binary. They are never
# PE images, frequently exclusively locked by a live IDA worker (PermissionError
# on read), and would otherwise show up as noise in every result entry for any
# folder where someone has previously run IDA.
_IDA_ARTIFACT_SUFFIXES = frozenset({
    ".id0", ".id1", ".id2", ".nam", ".til", ".i64", ".idb",
})


# Unpacked database components. IDA keeps a database in this form only while it
# is open and packs it into .i64/.idb on a clean close, so finding them with no
# live owner means a worker died (killed, recycled, supervisor restart) before
# saving. Reopening silently attaches to that half-written state.
_IDA_COMPONENT_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til", ".$$$")


def _stale_idb_components(input_path: str) -> list[Path]:
    """Unpacked database components next to ``input_path`` (GAME.EXE.id0 or GAME.id0)."""
    path = Path(input_path)
    bases = {str(path), str(path.with_suffix(""))}
    found: list[Path] = []
    for base in sorted(bases):
        for suffix in _IDA_COMPONENT_SUFFIXES:
            candidate = Path(base + suffix)
            if candidate.is_file() and candidate not in found:
                found.append(candidate)
    return found


def _quarantine_idb_components(
    input_path: str, components: list[Path]
) -> tuple[Path | None, list[str]]:
    """Move orphaned components to ``.ida_stale/<name>-<timestamp>/`` beside the binary.

    Moved rather than deleted so a crashed session's work stays recoverable.
    Returns the quarantine directory (None if nothing moved) and per-file
    failures; a file that can't be moved is usually locked by a live IDA.
    """
    path = Path(input_path)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = path.parent / ".ida_stale" / f"{path.name}-{stamp}"
    moved = False
    failures: list[str] = []
    for component in components:
        try:
            target.mkdir(parents=True, exist_ok=True)
            shutil.move(str(component), str(target / component.name))
            moved = True
        except OSError as e:
            failures.append(f"{component.name}: {e}")
    return (target if moved else None), failures


def _is_ida_artifact(name: str) -> bool:
    # Path.suffix is lowercase-sensitive; normalize.
    dot = name.rfind(".")
    if dot < 0:
        return False
    return name[dot:].lower() in _IDA_ARTIFACT_SUFFIXES


def _iter_candidate_files(
    root: Path,
    recursive: bool,
    on_dir_error,
    on_subdir=None,
):
    """Yield regular files under ``root``, skipping IDA artifact files.

    Symlinks are not followed. Per-directory traversal errors are passed to
    ``on_dir_error(path, exc)`` instead of aborting the walk. In non-recursive
    mode, ``on_subdir(path)`` (when given) is called once per immediate
    subdirectory so callers can report what a shallow scan skipped.
    """
    if recursive:
        def _walk_error(err: OSError) -> None:
            on_dir_error(getattr(err, "filename", str(root)) or str(root), err)

        for dirpath, _dirnames, filenames in os.walk(
            str(root), followlinks=False, onerror=_walk_error
        ):
            for name in filenames:
                if _is_ida_artifact(name):
                    continue
                full = Path(dirpath) / name
                try:
                    st = full.lstat()
                except OSError as e:
                    on_dir_error(str(full), e)
                    continue
                import stat as _stat

                if not _stat.S_ISREG(st.st_mode):
                    continue
                yield full, st
        return

    try:
        entries = list(os.scandir(str(root)))
    except OSError as e:
        on_dir_error(str(root), e)
        return
    try:
        import stat as _stat

        for entry in entries:
            if _is_ida_artifact(entry.name):
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as e:
                on_dir_error(entry.path, e)
                continue
            if _stat.S_ISDIR(st.st_mode):
                if on_subdir is not None:
                    on_subdir(entry.path)
                continue
            if not _stat.S_ISREG(st.st_mode):
                continue
            yield Path(entry.path), st
    finally:
        for entry in entries:
            try:
                entry.close = entry.close  # entries from scandir are closed when GC'd
            except Exception:
                pass


def _parse_pe_header(fh, file_size: int) -> dict | None:
    """Parse a PE header from an open binary file. Returns ``None`` if not a PE."""
    import struct

    if file_size < 0x40:
        return None
    fh.seek(0)
    dos = fh.read(0x40)
    if len(dos) < 0x40 or dos[:2] != b"MZ":
        return None
    (e_lfanew,) = struct.unpack_from("<I", dos, 0x3C)
    if e_lfanew < 0x40 or e_lfanew + 24 > file_size:
        return None
    fh.seek(e_lfanew)
    pe_sig = fh.read(4)
    if pe_sig != b"PE\x00\x00":
        return None
    file_header = fh.read(20)
    if len(file_header) < 20:
        return None
    machine, _num_sections, _ts, _ptr_sym, _num_sym, size_opt, characteristics = struct.unpack(
        "<HHIIIHH", file_header
    )
    bitness: int | None
    arch_entry = _PE_MACHINE_TABLE.get(machine)
    if arch_entry is not None:
        arch, bitness = arch_entry
    else:
        arch, bitness = "unknown", None

    if size_opt >= 2:
        opt_magic_bytes = fh.read(2)
        if len(opt_magic_bytes) == 2:
            (opt_magic,) = struct.unpack("<H", opt_magic_bytes)
            mag_bits = _PE_OPT_MAGIC_BITNESS.get(opt_magic)
            if mag_bits is not None:
                bitness = mag_bits

    return {
        "machine": "0x%04x" % machine,
        "arch": arch,
        "bitness": bitness,
        "characteristics": "0x%04x" % characteristics,
        "is_executable_image": bool(characteristics & 0x0002),
        "is_dll": bool(characteristics & 0x2000),
        "is_system": bool(characteristics & 0x1000),
    }


_ELF_MAGIC = bytes((0x7F, 0x45, 0x4C, 0x46))
_MACHO_MAGICS_32 = (bytes((0xFE, 0xED, 0xFA, 0xCE)), bytes((0xCE, 0xFA, 0xED, 0xFE)))
_MACHO_MAGICS_64 = (bytes((0xFE, 0xED, 0xFA, 0xCF)), bytes((0xCF, 0xFA, 0xED, 0xFE)))
_ET_DYN = bytes((0x03, 0x00))

_ELF_MACHINE_TABLE = {
    0x03: ("x86", 32),
    0x3E: ("x86_64", 64),
    0x28: ("arm", 32),
    0xB7: ("arm64", 64),
    0x08: ("mips", 32),
    0x14: ("ppc", 32),
    0x15: ("ppc64", 64),
    0xF3: ("riscv", None),
}

# MZ stub sub-formats keyed by the signature at e_lfanew. LE/LX are the DOS
# extender / OS2 formats Watcom-era 386 tooling ships (DOS/4GW and friends) --
# exactly the class of image a PE-only filter hides.
_MZ_SUBFORMATS = {
    b"NE": ("NE", "i386-16", 16),
    b"LE": ("LE", "i386", 32),
    b"LX": ("LX", "i386", 32),
}


def _sniff_binary_header(fh, file_size: int) -> dict:
    """Classify any file the way ``_parse_pe_header`` classifies PE files.

    Always returns a dict (``format`` "RAW" when nothing is recognized), so
    non-PE images -- LE/LX extender images, ELF, headerless blobs -- can be
    listed with the same entry shape as PE images.
    """
    import struct

    unknown = {
        "format": "RAW",
        "machine": "",
        "arch": "unknown",
        "bitness": None,
        "characteristics": "",
        "is_executable_image": False,
        "is_dll": False,
        "is_system": False,
    }

    pe = _parse_pe_header(fh, file_size)
    if pe is not None:
        return {**pe, "format": "PE"}

    fh.seek(0)
    head = fh.read(0x40)
    if len(head) < 4:
        return unknown

    if head[:4] == _ELF_MAGIC:
        bitness = {1: 32, 2: 64}.get(head[4])
        machine = None
        if len(head) >= 0x14:
            (machine,) = struct.unpack_from("<H", head, 0x12)
        arch, arch_bits = _ELF_MACHINE_TABLE.get(machine, ("unknown", None))
        return {
            **unknown,
            "format": "ELF",
            "machine": "0x%04x" % machine if machine is not None else "",
            "arch": arch,
            "bitness": bitness or arch_bits,
            "is_executable_image": True,
            "is_dll": head[0x10:0x12] == _ET_DYN,
        }

    if head[:4] in _MACHO_MAGICS_32:
        return {**unknown, "format": "MACHO", "bitness": 32, "is_executable_image": True}
    if head[:4] in _MACHO_MAGICS_64:
        return {**unknown, "format": "MACHO", "bitness": 64, "is_executable_image": True}

    # A bare LE/LX image: an extender payload already carved out of its MZ stub.
    if head[:2] in _MZ_SUBFORMATS:
        fmt, arch, bitness = _MZ_SUBFORMATS[head[:2]]
        return {
            **unknown,
            "format": fmt,
            "arch": arch,
            "bitness": bitness,
            "is_executable_image": True,
        }

    if head[:2] in (b"MZ", b"ZM") and len(head) >= 0x40:
        (e_lfanew,) = struct.unpack_from("<I", head, 0x3C)
        if e_lfanew >= 0x40 and e_lfanew + 2 <= file_size:
            fh.seek(e_lfanew)
            sig = fh.read(2)
            if sig in _MZ_SUBFORMATS:
                fmt, arch, bitness = _MZ_SUBFORMATS[sig]
                return {
                    **unknown,
                    "format": fmt,
                    "arch": arch,
                    "bitness": bitness,
                    "is_executable_image": True,
                }
        return {
            **unknown,
            "format": "MZ",
            "arch": "i386-16",
            "bitness": 16,
            "is_executable_image": True,
        }

    return unknown


def _hash_file(path: Path) -> tuple[str, str]:
    """Stream ``path`` and return ``(sha1_hex, "0x%08x" % crc32)``."""
    import hashlib
    import zlib

    sha1 = hashlib.sha1()
    crc = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_HASH_CHUNK_SIZE)
            if not chunk:
                break
            sha1.update(chunk)
            crc = zlib.crc32(chunk, crc)
    return sha1.hexdigest(), "0x%08x" % (crc & 0xFFFFFFFF)


def _hash_file_verify(path: Path) -> tuple[str, str]:
    """Stream ``path`` and return ``(sha256_hex, md5_hex)`` for caller verification."""
    import hashlib

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_HASH_CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def _path_components(p: str) -> list[str]:
    """Split a path into lowercased components, tolerant of mixed / and \\.

    A leading drive letter (``c:``) is dropped so ``c:/a/x.exe`` and ``/a/x.exe``
    compare on their tails.
    """
    norm = (p or "").replace("\\", "/")
    parts = [seg for seg in norm.split("/") if seg not in ("", ".")]
    if parts and len(parts[0]) == 2 and parts[0][1] == ":":
        parts = parts[1:]
    return [seg.lower() for seg in parts]


def _suffix_match_len(query_parts: list[str], candidate_path: str) -> int:
    """Count trailing path components shared by query and candidate.

    e.g. query ``system/Mplayer.dll`` vs candidate
    ``F:/Reversing/mplayer/files/system/Mplayer.dll`` -> 2 (``system``,
    ``mplayer.dll``). A bare filename matching the candidate's filename scores 1.
    """
    cand_parts = _path_components(candidate_path)
    n = 0
    for q, c in zip(reversed(query_parts), reversed(cand_parts)):
        if q != c:
            break
        n += 1
    return n

class PathResolver:
    """Alias registry + search roots + decisive open-target resolution.

    ``session_paths`` returns the input paths of currently open sessions; their
    parent directories are used as search bases when resolving a missing path.
    """

    def __init__(self, session_paths: Callable[[], Iterable[str]] | None = None):
        # Filename -> absolute paths seen via list_pe_images / searches. Lets
        # callers open binaries by bare filename when their upstream safety
        # layer rejects absolute paths, or when they don't know server paths.
        self.alias_registry: dict[str, set[str]] = {}
        # Directories pre-scanned at startup via --search-root.
        self.search_roots: list[str] = []
        self._session_paths = session_paths or (lambda: ())
        self._lock = RLock()

    def record_aliases(self, filename_to_paths: dict[str, str]) -> None:
        """Add (filename, absolute_path) pairs to the registry. Idempotent."""
        with self._lock:
            for name, path in filename_to_paths.items():
                self.alias_registry.setdefault(name, set()).add(path)

    def suggest_aliases(self, name: str, n: int = 3) -> list[str]:
        """Return up to ``n`` registered filenames similar to ``name``.

        Matching is case-insensitive and combines difflib ratio similarity with
        a substring fallback so common casing/format variants surface even when
        difflib's ratio is borderline. Order is best-match first, no duplicates.
        """
        import difflib

        with self._lock:
            registry_names = list(self.alias_registry.keys())
        if not registry_names:
            return []
        norm = (name or "").lower()
        if not norm:
            return []
        lower_to_orig: dict[str, str] = {}
        for orig in registry_names:
            lower_to_orig.setdefault(orig.lower(), orig)
        result: list[str] = []
        seen: set[str] = set()
        for low in difflib.get_close_matches(
            norm, list(lower_to_orig.keys()), n=n, cutoff=0.5
        ):
            orig = lower_to_orig[low]
            if orig in seen:
                continue
            seen.add(orig)
            result.append(orig)
        if len(result) < n:
            for orig in registry_names:
                if orig in seen:
                    continue
                low = orig.lower()
                if norm in low or low in norm:
                    seen.add(orig)
                    result.append(orig)
                    if len(result) >= n:
                        break
        return result[:n]

    def prepopulate_aliases(
        self, roots: list[str], *, recursive: bool = False
    ) -> dict[str, dict[str, Any]]:
        """Scan each root for PE images and register them in alias_registry.

        Used by ``main()`` to honor ``--search-root`` flags at startup so that
        ``idb_aliases()`` returns useful data before any client call. Each
        root is summarized as ``{"count": int, "error": str | None}``. A failing
        root does not abort the scan of others. Recorded roots are surfaced via
        ``idb_search_roots()`` for caller introspection.
        """
        summary: dict[str, dict[str, Any]] = {}
        for raw_root in roots:
            # Record every attempted root for introspection regardless of
            # outcome -- operators want to see "you asked for this, here's
            # what happened" via idb_search_roots().
            with self._lock:
                if raw_root not in self.search_roots:
                    self.search_roots.append(raw_root)
            entry: dict[str, Any] = {"count": 0, "error": None}
            root_path = Path(raw_root)
            if not root_path.is_absolute():
                entry["error"] = "not an absolute path"
                summary[raw_root] = entry
                continue
            if not root_path.exists():
                entry["error"] = "not found"
                summary[raw_root] = entry
                continue
            if not root_path.is_dir():
                entry["error"] = "not a directory"
                summary[raw_root] = entry
                continue
            count = 0
            try:
                for full_path, st in _iter_candidate_files(
                    root_path, recursive, lambda *_: None
                ):
                    try:
                        with open(full_path, "rb") as fh:
                            header = _parse_pe_header(fh, st.st_size)
                    except OSError:
                        continue
                    if header is None:
                        continue
                    self.record_aliases({full_path.name: str(full_path)})
                    count += 1
            except Exception as e:
                entry["error"] = f"{type(e).__name__}: {e}"
            entry["count"] = count
            summary[raw_root] = entry
        return summary

    def resolve_alias(
        self, name_or_path: str, directory_hint: str | None = None
    ) -> str | None:
        """Resolve a bare filename to an absolute path via the alias registry.

        - Returns the matching path on unique resolution.
        - Returns None when no match is registered (caller falls back to its own logic).
        - Raises RuntimeError when multiple paths share the filename and the caller
          did not narrow with ``directory_hint``.
        """
        with self._lock:
            paths = set(self.alias_registry.get(name_or_path) or ())
        if not paths:
            return None
        if directory_hint:
            try:
                hint_key = os.path.normcase(str(Path(directory_hint).resolve()))
            except Exception:
                hint_key = os.path.normcase(directory_hint)
            paths = {
                p for p in paths if os.path.normcase(p).startswith(hint_key)
            }
            if not paths:
                return None
        if len(paths) == 1:
            return next(iter(paths))
        raise RuntimeError(
            f"Ambiguous alias '{name_or_path}'; pass directory= to disambiguate. "
            f"Candidates: {sorted(paths)}"
        )

    def _search_bases(
        self, input_path: str, directory_hint: str | None
    ) -> list[Path]:
        """Existing directories to recurse when resolving a missing path.

        Ordered by how targeted (and cheap to scan) each base is likely to be:
        the directory hint, the operator-curated --search-roots, the parent
        directories of open sessions, and -- LAST -- the nearest existing
        ancestor of the requested path. The ancestor goes last on purpose: a
        guessed path like C:\\Users\\me\\Desktop\\proj\\x.exe can have a huge
        existing ancestor (the whole Desktop tree), which would otherwise starve
        the curated roots where the file usually lives. Deduplicated; only
        absolute, existing directories are returned.
        """
        bases: list[Path] = []
        seen: set[str] = set()

        def add(d: str | None) -> None:
            if not d:
                return
            try:
                rp = Path(d)
            except Exception:
                return
            if not rp.is_absolute():
                return
            key = os.path.normcase(str(rp))
            if key in seen:
                return
            try:
                if rp.exists() and rp.is_dir():
                    seen.add(key)
                    bases.append(rp)
            except OSError:
                return

        add(directory_hint)
        with self._lock:
            roots = list(self.search_roots)
        session_paths = [p for p in self._session_paths() if p]
        for r in roots:
            add(r)
        for sp in session_paths:
            try:
                add(str(Path(sp).parent))
            except Exception:
                pass
        try:
            for anc in Path(input_path).parents:
                if anc.exists() and anc.is_dir():
                    add(str(anc))
                    break
        except Exception:
            pass
        return bases

    def _search_for_basename(
        self,
        basename: str,
        input_path: str,
        directory_hint: str | None,
        *,
        max_files: int = 5000,
        time_budget_sec: float = 8.0,
    ) -> list[str]:
        """Bounded recursive on-disk search for files named ``basename``.

        Walks _search_bases() recursively, registering every hit in the alias
        registry so subsequent opens resolve instantly. Matching is
        case-insensitive on the filename only (no PE filter) so non-PE targets
        like 16-bit installers resolve too.

        Each base gets its own slice of the file/time budget so a single huge
        base can't starve the rest, and the search stops at the first base that
        yields any match -- bases are ordered most-targeted-first, so this finds
        the file in a curated --search-root without ever walking a giant ancestor
        tree. Duplicate names within the winning base are all returned, leaving
        disambiguation to resolve_open_target's suffix scoring.
        """
        target = basename.lower()
        found: list[str] = []
        seen_paths: set[str] = set()
        bases = self._search_bases(input_path, directory_hint)
        if not bases:
            return found
        global_deadline = (
            time.monotonic() + time_budget_sec if time_budget_sec > 0 else None
        )
        # Fair share per base, with sensible floors so a small base still gets a
        # real chance and a large one can't monopolize the whole budget.
        per_base_files = max(1000, max_files // len(bases))
        per_base_time = (
            max(2.0, time_budget_sec / len(bases)) if time_budget_sec > 0 else 0.0
        )
        scanned_total = 0
        for base in bases:
            if global_deadline is not None and time.monotonic() >= global_deadline:
                break
            if scanned_total >= max_files:
                break
            base_scanned = 0
            base_deadline = (
                time.monotonic() + per_base_time if per_base_time > 0 else None
            )
            for full_path, _st in _iter_candidate_files(base, True, lambda *_: None):
                scanned_total += 1
                base_scanned += 1
                if base_scanned > per_base_files or scanned_total > max_files:
                    break
                now = time.monotonic()
                if base_deadline is not None and now >= base_deadline:
                    break
                if global_deadline is not None and now >= global_deadline:
                    break
                if full_path.name.lower() == target:
                    key = os.path.normcase(str(full_path))
                    if key not in seen_paths:
                        seen_paths.add(key)
                        found.append(str(full_path))
            # First base with a hit wins -- don't walk lower-priority (broader) bases.
            if found:
                break
        if found:
            self.record_aliases({Path(p).name: p for p in found})
        return found

    def resolve_open_target(
        self,
        input_path: str,
        directory_hint: str | None = None,
        *,
        allow_search: bool = True,
    ) -> dict:
        """Resolve ``input_path`` to a concrete file to open, decisively.

        Designed so a client passing an imperfect path gets opened in ONE call
        rather than looping. Returns a dict with ``status``:

        - ``open``: ``path`` is the absolute file to open; ``how`` explains the match.
        - ``ambiguous``: ``candidates`` are equally-good matches (duplicate
          filenames) — the caller should re-call with more path components.
        - ``miss``: nothing matched; ``suggestions`` are near filenames.

        Match order: an existing absolute path wins outright; otherwise a unique
        registered filename opens; otherwise, among duplicates, the candidate
        sharing the most trailing path components with the query opens when it is
        a clear winner (>= 2 components, e.g. ``system/Mplayer.dll``). A bare
        filename shared by multiple paths stays ambiguous. When the filename is
        unknown to the registry and ``allow_search`` is set, a bounded recursive
        on-disk search runs first.
        """
        cand = Path(input_path)
        if cand.is_absolute():
            try:
                if cand.exists() and cand.is_file():
                    return {"status": "open", "path": str(cand), "how": "exact path"}
            except OSError:
                pass

        basename = cand.name or input_path
        query_parts = _path_components(input_path)

        with self._lock:
            paths = set(self.alias_registry.get(basename) or ())
            if not paths:
                lower = basename.lower()
                for name, regpaths in self.alias_registry.items():
                    if name.lower() == lower:
                        paths |= set(regpaths)

        searched = False
        if not paths and allow_search:
            searched = True
            paths = set(self._search_for_basename(basename, input_path, directory_hint))

        if not paths:
            return {
                "status": "miss",
                "suggestions": self.suggest_aliases(basename),
                "searched": searched,
            }

        if directory_hint:
            try:
                hint_key = os.path.normcase(str(Path(directory_hint).resolve()))
            except Exception:
                hint_key = os.path.normcase(directory_hint)
            narrowed = {p for p in paths if os.path.normcase(p).startswith(hint_key)}
            if narrowed:
                paths = narrowed

        ordered = sorted(paths)
        if len(ordered) == 1:
            return {
                "status": "open",
                "path": ordered[0],
                "how": "on-disk search" if searched else "unique filename",
                "searched": searched,
            }

        # Duplicate filenames: rank by trailing-path-component overlap so a query
        # like 'system/Mplayer.dll' beats 'Programs/Mplayer.dll'.
        scored = sorted(
            ordered, key=lambda p: _suffix_match_len(query_parts, p), reverse=True
        )
        top = _suffix_match_len(query_parts, scored[0])
        top_paths = [p for p in scored if _suffix_match_len(query_parts, p) == top]
        if len(top_paths) == 1 and top >= 2:
            return {
                "status": "open",
                "path": top_paths[0],
                "how": f"matched {top} trailing path components",
                "searched": searched,
            }
        return {
            "status": "ambiguous",
            "candidates": scored,
            "how": "duplicate filename; re-call with more path components to disambiguate",
            "searched": searched,
        }


# ---------------------------------------------------------------------------
# Database component discovery and lock probing
# ---------------------------------------------------------------------------


def database_component_paths(input_path: str) -> list[Path]:
    """Existing unpacked components for ``input_path`` (or its .i64/.idb).

    Covers both naming forms IDA uses: ``GAME.EXE.id0`` (database named after
    the full input filename) and ``GAME.id0`` (extension stripped, which is also
    what an ``.i64`` path itself maps to).
    """
    return _stale_idb_components(input_path)


def file_is_locked(path: Path) -> bool | None:
    """True if another process holds ``path`` open, False if not, None if unknown.

    Windows: open with share mode 0 (exclusive). IDA keeps its unpacked
    components open while a database is loaded, so a sharing violation means a
    live IDA (GUI, idat or idalib) owns them. POSIX has no mandatory locking,
    so the answer there is None and callers fall back to heuristics.
    """
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        GENERIC_READ = 0x80000000
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x80
        INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
        handle = kernel32.CreateFileW(
            str(path), GENERIC_READ, 0, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None
        )
        if handle == INVALID_HANDLE_VALUE or handle is None:
            err = ctypes.get_last_error()
            # 32 = ERROR_SHARING_VIOLATION, 33 = ERROR_LOCK_VIOLATION
            if err in (32, 33):
                return True
            return None
        kernel32.CloseHandle(handle)
        return False
    except Exception:
        return None


# Components touched this recently may belong to a live process on POSIX,
# where file_is_locked() cannot tell.
RECENT_COMPONENT_SEC = 120.0


def components_lock_state(components: list[Path]) -> str:
    """Classify unpacked components: "none", "locked", "possibly_open" or "stale".

    - ``none``: no components exist.
    - ``locked``: at least one component is held open by another process (Windows).
    - ``possibly_open``: lock state unknown (POSIX) and a component was modified
      within RECENT_COMPONENT_SEC -- treat as live, never clean it up.
    - ``stale``: components exist and nothing appears to hold them.
    """
    if not components:
        return "none"
    unknown = False
    for comp in components:
        locked = file_is_locked(comp)
        if locked:
            return "locked"
        if locked is None:
            unknown = True
    if unknown:
        now = time.time()
        for comp in components:
            try:
                if now - comp.stat().st_mtime < RECENT_COMPONENT_SEC:
                    return "possibly_open"
            except OSError:
                continue
    return "stale"


def quarantine_components(input_path: str, components: list[Path]) -> tuple[Path | None, list[str]]:
    """Public wrapper over the fork's quarantine helper."""
    return _quarantine_idb_components(input_path, components)


def hash_file_verify(path: Path) -> tuple[str, str]:
    """(sha256_hex, md5_hex) of ``path``."""
    return _hash_file_verify(path)
