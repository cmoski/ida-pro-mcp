"""Tests for api_core API functions."""

from ..framework import (
    test,
    skip_test,
    assert_has_keys,
    assert_valid_address,
    assert_non_empty,
    assert_is_list,
    assert_shape,
    assert_ok,
    assert_error,
    is_hex_address,
    list_of,
    optional,
    get_any_function,
    get_data_address,
)
from ..utils import Function, ConvertedNumber
from ..api_core import (
    lookup_funcs,
    int_convert,
    list_funcs,
    func_query,
    list_globals,
    entity_query,
    imports,
    imports_query,
    server_health,
    server_warmup,
    find_regex,
    search_text,
    _build_text_matcher,
    _maybe_search_text_fast,
    _prime_search_meta_cache,
    _get_search_meta_cache,
    submit_job,
    job_status,
    job_list,
    job_cancel,
    idb_save,
    invalidate_strings_cache,
)
from .. import _objdump_search


CRACKME_MAIN = "0x123e"
CRACKME_CHECK_PW = "0x11a9"
CRACKME_FORMAT = "0x201f"
CRACKME_PRINTF = "0x4040"


@test()
def test_lookup_funcs_by_address():
    """lookup_funcs resolves a valid function address to a complete function object."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = lookup_funcs(fn_addr)
    assert_shape(
        result,
        [
            {
                "query": str,
                "fn": optional(Function),
                "error": optional(str),
            }
        ],
    )
    assert_ok(result[0], "fn")
    fn = result[0]["fn"]
    assert_typed = fn is not None
    assert assert_typed
    assert fn["addr"] == fn_addr
    assert_valid_address(fn["addr"])
    assert_non_empty(fn["name"])


@test(binary="crackme03.elf")
def test_lookup_funcs_known_crackme_symbols():
    """lookup_funcs resolves known crackme symbols to their expected entry addresses."""
    results = lookup_funcs(["main", "check_pw"])
    assert len(results) == 2

    by_query = {item["query"]: item for item in results}
    assert_ok(by_query["main"], "fn")
    assert_ok(by_query["check_pw"], "fn")
    assert by_query["main"]["fn"]["addr"] == CRACKME_MAIN
    assert by_query["check_pw"]["fn"]["addr"] == CRACKME_CHECK_PW


@test()
def test_lookup_funcs_invalid():
    """lookup_funcs reports an error for an invalid address."""
    result = lookup_funcs("0xDEADBEEFDEADBEEF")
    assert_is_list(result, min_length=1)
    assert result[0]["fn"] is None
    assert_error(result[0])


@test()
def test_lookup_funcs_wildcard_returns_non_empty_function_list():
    """lookup_funcs('*') returns a non-empty list of valid functions."""
    result = lookup_funcs("*")
    assert_is_list(result, min_length=1)
    for item in result:
        assert item["query"] == "*"
        assert_ok(item, "fn")
        assert_shape(item["fn"], Function)


@test()
def test_lookup_funcs_empty_returns_non_empty_function_list():
    """lookup_funcs('') behaves like an all-functions query and must not be empty."""
    result = lookup_funcs("")
    assert_is_list(result, min_length=1)
    for item in result:
        assert item["query"] == "*"
        assert_ok(item, "fn")


@test()
def test_lookup_funcs_malformed_hex():
    """lookup_funcs rejects malformed hexadecimal strings."""
    result = lookup_funcs("0xZZZZ")
    assert_is_list(result, min_length=1)
    assert result[0]["fn"] is None
    assert_error(result[0])


@test()
def test_lookup_funcs_data_address():
    """lookup_funcs reports a non-function address as an error."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    result = lookup_funcs(data_addr)
    assert_is_list(result, min_length=1)
    assert result[0]["fn"] is None
    assert_error(result[0])


@test()
def test_lookup_funcs_interior_address():
    """lookup_funcs maps an interior address back to its function entry point."""
    import idaapi
    import idc

    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    ea = int(fn_addr, 16)
    func = idaapi.get_func(ea)
    if not func:
        skip_test("IDA could not retrieve the function object")

    interior = idc.next_head(func.start_ea, func.end_ea)
    if interior == idaapi.BADADDR or interior == func.start_ea:
        skip_test("function has no interior instruction")

    result = lookup_funcs(hex(interior))
    assert len(result) == 1
    assert_ok(result[0], "fn")
    assert result[0]["fn"]["addr"] == hex(func.start_ea)
    assert result[0]["fn"]["addr"] != hex(interior)


@test()
def test_int_convert():
    """int_convert returns the expected canonical representations for 0x41."""
    result = int_convert({"text": "0x41"})
    assert_is_list(result, min_length=1)
    assert_shape(
        result,
        [{"input": str, "result": optional(ConvertedNumber), "error": optional(str)}],
    )
    assert_ok(result[0], "result")
    conv = result[0]["result"]
    assert conv["decimal"] == "65"
    assert conv["hexadecimal"] == "0x41"
    assert conv["ascii"] == "A"
    assert conv["bytes"] == "41"


@test()
def test_int_convert_invalid_text():
    """int_convert reports invalid numeric text."""
    result = int_convert({"text": "not_a_number"})
    assert_is_list(result, min_length=1)
    assert result[0]["result"] is None
    assert_error(result[0], contains="Invalid number")


@test()
def test_int_convert_overflow():
    """int_convert reports overflow when the requested size is too small."""
    result = int_convert({"text": "0xFFFF", "size": 1})
    assert_is_list(result, min_length=1)
    assert result[0]["result"] is None
    assert_error(result[0], contains="too big")


@test()
def test_int_convert_non_ascii():
    """int_convert returns ascii=None for non-printable bytes."""
    result = int_convert({"text": "0x01"})
    assert_is_list(result, min_length=1)
    assert_ok(result[0], "result")
    assert result[0]["result"]["ascii"] is None


@test()
def test_list_funcs_returns_non_empty_page_of_functions():
    """list_funcs returns a non-empty page and every function round-trips through lookup_funcs."""
    result = list_funcs({"offset": 0, "count": 10})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_shape(
        page, {"data": list_of(Function, min_length=1), "next_offset": optional(int)}
    )

    for fn in page["data"][:5]:
        resolved = lookup_funcs(fn["addr"])
        assert_ok(resolved[0], "fn")
        assert resolved[0]["fn"]["addr"] == fn["addr"]
        assert resolved[0]["fn"]["name"] == fn["name"]


@test(binary="crackme03.elf")
def test_list_funcs_contains_known_crackme_functions():
    """list_funcs includes the known crackme functions main and check_pw."""
    page = list_funcs({"filter": "*", "offset": 0, "count": 100})[0]
    names = {fn["name"]: fn["addr"] for fn in page["data"]}
    assert names.get("main") == CRACKME_MAIN
    assert names.get("check_pw") == CRACKME_CHECK_PW


@test()
def test_list_funcs_pagination():
    """list_funcs enforces count limits and returns a usable next_offset."""
    page = list_funcs({"offset": 0, "count": 5})[0]
    assert len(page["data"]) <= 5
    if page["next_offset"] is not None:
        next_page = list_funcs({"offset": page["next_offset"], "count": 5})[0]
        assert next_page["data"] != page["data"]


@test()
def test_func_query():
    """func_query returns richer function entries"""
    result = func_query({})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset")
    if page["data"]:
        assert_has_keys(page["data"][0], "addr", "name", "size", "has_type")


@test()
def test_func_query_filters():
    """func_query supports size/type filters"""
    result = func_query({"min_size": 0, "max_size": 0xFFFFFFFF, "has_type": False})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset")
    for fn in page["data"]:
        assert fn["has_type"] is False


@test()
def test_list_globals_returns_non_empty_results_for_all_query():
    """list_globals('*') returns at least one global item."""
    import idaapi
    import idautils

    if not any(not idaapi.get_func(ea) for ea, _ in idautils.Names()):
        skip_test("binary has no named non-function items")
    page = list_globals({"filter": "*", "offset": 0, "count": 50})[0]
    assert_shape(
        page,
        {
            "data": list_of({"addr": is_hex_address, "name": str}, min_length=1),
            "next_offset": optional(int),
        },
    )


@test(binary="crackme03.elf")
def test_list_globals_filter_matches_known_symbol():
    """list_globals can find the known crackme format string symbol."""
    page = list_globals({"filter": "format", "offset": 0, "count": 10})[0]
    assert_is_list(page["data"], min_length=1)
    first = page["data"][0]
    assert first["name"] == "format"
    assert first["addr"] == CRACKME_FORMAT


@test()
def test_imports_returns_non_empty_page():
    """imports returns a non-empty page of typed import objects."""
    import ida_nalt

    if ida_nalt.get_import_module_qty() == 0:
        skip_test("binary has no imports (static image)")
    page = imports(0, 50)
    assert_shape(
        page,
        {
            "data": list_of(
                {"addr": is_hex_address, "imported_name": str, "module": str},
                min_length=1,
            ),
            "next_offset": optional(int),
        },
    )


@test(binary="crackme03.elf")
def test_imports_contains_printf():
    """imports contains the expected printf import for the crackme fixture."""
    page = imports(0, 50)
    matches = [item for item in page["data"] if item["addr"] == CRACKME_PRINTF]
    assert matches, "expected to find printf import at 0x4040"
    assert "printf" in matches[0]["imported_name"]


@test(binary="crackme03.elf")
def test_find_regex_matches_known_correct_strings():
    """find_regex('correct') returns the two known crackme result strings."""
    result = find_regex("correct")
    assert_shape(
        result,
        {
            "n": int,
            "matches": list_of({"addr": is_hex_address, "string": str}, min_length=1),
            "cursor": dict,
        },
    )
    by_addr = {item["addr"]: item["string"] for item in result["matches"]}
    assert by_addr.get("0x201f") == "Yes, %s is correct!\n"
    assert by_addr.get("0x2034") == "No, %s is not correct.\n"
    assert result["n"] >= 2


@test()
def test_func_query():
    """func_query returns richer function entries"""
    result = func_query({})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset")
    if page["data"]:
        assert_has_keys(page["data"][0], "addr", "name", "size", "has_type")


@test()
def test_func_query_filters():
    """func_query supports size/type filters"""
    result = func_query({"min_size": 0, "max_size": 0xFFFFFFFF, "has_type": False})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset")
    for fn in page["data"]:
        assert fn["has_type"] is False


@test()
def test_func_query_multi_query_preserves_size_sort_state():
    """func_query should not mutate shared rows across multiple queries in one call."""
    result = func_query(
        [
            {"offset": 0, "count": 1},
            {"offset": 0, "count": 10, "sort_by": "size", "descending": True},
        ]
    )
    assert_is_list(result, min_length=2)
    second_page = result[1]
    assert_has_keys(second_page, "data", "next_offset")
    sizes = [int(str(item["size"]), 0) for item in second_page["data"]]
    assert sizes == sorted(sizes, reverse=True)


# ============================================================================
# Tests for entity_query / health / warmup
# ============================================================================


@test()
def test_entity_query_functions_projection():
    """entity_query supports generic function query + field projection"""
    result = entity_query(
        {
            "kind": "functions",
            "filter": "*",
            "fields": ["addr", "name"],
            "offset": 0,
            "count": 5,
        }
    )
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "kind", "data", "next_offset", "total", "error")
    if page["data"]:
        assert_has_keys(page["data"][0], "kind", "addr", "name")


@test()
def test_entity_query_functions_sort_by_size():
    """entity_query sorts function rows by numeric size, including hex string sizes."""
    result = entity_query(
        {
            "kind": "functions",
            "filter": "*",
            "sort_by": "size",
            "descending": True,
            "offset": 0,
            "count": 10,
        }
    )
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "kind", "data", "next_offset", "total", "error")
    sizes = [int(str(item["size"]), 0) for item in page["data"]]
    assert sizes == sorted(sizes, reverse=True)


@test(binary="typed_fixture.elf")
def test_entity_query_count_zero_returns_all():
    """count=0 returns every row, as the schema documents."""
    page = entity_query({"kind": "functions", "count": 0})[0]
    assert page["total"] > 100
    assert len(page["data"]) == page["total"]
    assert page["next_offset"] is None


@test()
def test_server_health():
    """server_health returns readiness payload"""
    result = server_health()
    assert_has_keys(
        result,
        "status",
        "uptime_sec",
        "module",
        "imagebase",
        "strings_cache_ready",
        "hexrays_ready",
    )


@test()
def test_server_warmup():
    """server_warmup runs warmup steps and returns health"""
    result = server_warmup(
        wait_auto_analysis=False, build_caches=False, init_hexrays=False
    )
    assert_has_keys(result, "ok", "steps", "health")
    assert_is_list(result["steps"])
@test()
def test_imports():
    """imports returns import list with proper structure"""
    page = imports(0, 100)
    assert_has_keys(page, "data", "next_offset")
    if page["data"]:
        assert_has_keys(page["data"][0], "addr", "imported_name", "module")


@test()
def test_imports_pagination():
    """imports respects pagination parameters"""
    page = imports(0, 5)
    assert len(page["data"]) <= 5


@test()
def test_imports_query():
    """imports_query supports filtered import listing"""
    result = imports_query({"filter": "*", "offset": 0, "count": 10})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset")
    if page["data"]:
        assert_has_keys(page["data"][0], "addr", "imported_name", "module")


# ============================================================================
# Tests for find_regex
# ============================================================================


@test()
def test_find_regex():
    """find_regex can search for patterns"""
    result = find_regex(".*")
    assert_has_keys(result, "matches", "cursor")


@test()
def test_find_regex_strings_cache_includes_wide_strings():
    """Strings cache is built with UTF-16 (strtype 1) included (#263).

    Smoke test: invalidate the cache, rebuild, and confirm find_regex still
    returns a well-formed result. The cache setup now passes
    ``strtypes=[0, 1]`` to ``idautils.Strings().setup()`` so wide-char strings
    are scanned alongside ASCII. Verifying actual UTF-16 hits requires a binary
    with known wide strings (e.g. a UE4/Windows binary).
    """
    invalidate_strings_cache()
    result = find_regex(".*")
    assert_has_keys(result, "matches", "cursor")


# ============================================================================
# Tests for search_text
# ============================================================================


@test()
def test_search_text_smoke():
    """search_text returns a well-formed envelope even for no matches."""
    result = search_text("___definitely_no_such_token___")
    assert_has_keys(result, "n", "hits", "cursor")
    assert result["n"] == 0
    assert result["hits"] == []
    assert result["cursor"].get("done") is True


@test()
def test_search_text_invalid_regex_returns_error():
    """Bad regex surfaces as `error`, not a raised exception."""
    result = search_text("(unclosed", regex=True)
    assert "error" in result
    assert result["n"] == 0


@test()
def test_search_text_invalid_include_returns_error():
    result = search_text("call", include="garbage")
    assert "error" in result


@test()
def test_search_text_hits_have_required_shape():
    """Hit records carry addr/matches; matches carry kind/text."""
    result = search_text("call", limit=5)
    if result["n"] == 0:
        skip_test("binary produced no matches for 'call'")
    for h in result["hits"]:
        assert_has_keys(h, "addr", "matches")
        assert is_hex_address(h["addr"]), f"bad addr: {h['addr']!r}"
        assert h["matches"], f"hit at {h['addr']} has no matches"
        for m in h["matches"]:
            assert_has_keys(m, "kind", "text")
            assert m["kind"] in ("disasm", "comment")
            assert isinstance(m["text"], str) and m["text"]


@test()
def test_search_text_disasm_only_excludes_comments():
    """include='disasm' should never return comment-kind lines."""
    result = search_text("call", include="disasm", limit=10)
    if result["n"] == 0:
        skip_test("no 'call' in binary")
    for h in result["hits"]:
        for m in h["matches"]:
            assert m["kind"] == "disasm", f"unexpected kind {m['kind']} at {h['addr']}"


@test()
def test_search_text_pagination_uses_addr_cursor():
    """Cursor is an address; the second page must not re-emit the first page's hits."""
    page1 = search_text("call", limit=2)
    if page1["n"] < 2 or page1["cursor"].get("done"):
        skip_test("not enough matches to paginate")
    next_addr = page1["cursor"]["next"]
    assert is_hex_address(next_addr), f"cursor.next not hex: {next_addr!r}"
    page2 = search_text("call", limit=2, start=next_addr)
    addrs1 = {h["addr"] for h in page1["hits"]}
    addrs2 = {h["addr"] for h in page2["hits"]}
    assert not (addrs1 & addrs2), f"duplicate hits across pages: {addrs1 & addrs2}"


@test()
def test_search_text_limit_respected():
    result = search_text("call", limit=2)
    assert len(result["hits"]) <= 2


@test()
def test_search_text_regex_mode():
    """regex=True accepts regex syntax and finds matches."""
    result = search_text(r"call|jmp", regex=True, limit=5)
    if result["n"] == 0:
        skip_test("no call/jmp in binary")
    for h in result["hits"]:
        assert h["matches"]


# ============================================================================
# Tests for the objdump fast path (search_text when IDA is busy)
# ============================================================================


def _require_objdump():
    od = _objdump_search.find_objdump()
    if not od:
        skip_test("objdump not available (bundled w64devkit or PATH)")
    return od


def _exec_seg_ranges():
    import idaapi
    import idautils

    ranges = []
    for ea in idautils.Segments():
        seg = idaapi.getseg(ea)
        if seg and (seg.perm & idaapi.SEGPERM_EXEC):
            ranges.append((seg.start_ea, seg.end_ea))
    return ranges


@test()
def test_fastpath_prime_caches_input_path_and_imagebase():
    """The IDA path primes the off-thread cache with a usable path + base."""
    import idaapi

    _prime_search_meta_cache()
    cache = _get_search_meta_cache()
    assert cache is not None, "cache not primed"
    assert_has_keys(cache, "input_path", "imagebase")
    assert cache["input_path"], "empty input path"
    assert cache["imagebase"] == idaapi.get_imagebase()


@test()
def test_fastpath_objdump_base_matches_imagebase_for_unrebased_fixture():
    """objdump's assumed base == IDA imagebase here, so the address delta is 0."""
    import idaapi

    od = _require_objdump()
    _prime_search_meta_cache()
    cache = _get_search_meta_cache()
    base = _objdump_search.objdump_base(od, cache["input_path"])
    assert base is not None, "could not determine objdump base"
    # crackme03/typed_fixture are loaded at their preferred base (no rebase).
    assert idaapi.get_imagebase() - base == 0


@test()
def test_fastpath_disasm_hits_are_valid_code_addresses():
    """objdump fast-path hits carry the SearchText shape and land in exec segments."""
    od = _require_objdump()
    _prime_search_meta_cache()
    cache = _get_search_meta_cache()
    base = _objdump_search.objdump_base(od, cache["input_path"])
    matcher = _build_text_matcher("call", regex=False, case_sensitive=False)
    res = _objdump_search.search_disasm(
        od, cache["input_path"], matcher,
        delta=cache["imagebase"] - base, limit=10,
    )
    assert res.get("engine") == "objdump"
    if res["n"] == 0:
        skip_test("no 'call' found by objdump")
    ranges = _exec_seg_ranges()
    for h in res["hits"]:
        assert_has_keys(h, "addr", "matches")
        assert is_hex_address(h["addr"]), f"bad addr {h['addr']!r}"
        ea = int(h["addr"], 16)
        assert any(s <= ea < e for s, e in ranges), f"{h['addr']} not in any exec segment"
        for m in h["matches"]:
            assert m["kind"] == "disasm"
            assert isinstance(m["text"], str) and m["text"]


@test()
def test_fastpath_addresses_agree_with_ida_search():
    """For the same 'call' token, objdump hit addresses overlap IDA's listing scan."""
    od = _require_objdump()
    _prime_search_meta_cache()
    cache = _get_search_meta_cache()
    base = _objdump_search.objdump_base(od, cache["input_path"])
    matcher = _build_text_matcher("call", regex=False, case_sensitive=False)
    fast = _objdump_search.search_disasm(
        od, cache["input_path"], matcher,
        delta=cache["imagebase"] - base, limit=200,
    )
    ida = search_text("call", include="disasm", limit=200)
    if fast["n"] == 0 or ida["n"] == 0:
        skip_test("'call' not found by both engines")
    fast_addrs = {int(h["addr"], 16) for h in fast["hits"]}
    ida_addrs = {int(h["addr"], 16) for h in ida["hits"]}
    # Both scan the same code; their call-site addresses should overlap.
    assert fast_addrs & ida_addrs, "objdump and IDA found no common call sites"


@test()
def test_fastpath_resume_cursor_does_not_duplicate():
    """Resuming from cursor.next yields strictly later, non-overlapping hits."""
    od = _require_objdump()
    _prime_search_meta_cache()
    cache = _get_search_meta_cache()
    base = _objdump_search.objdump_base(od, cache["input_path"])
    delta = cache["imagebase"] - base
    matcher = _build_text_matcher("call", regex=False, case_sensitive=False)
    page1 = _objdump_search.search_disasm(od, cache["input_path"], matcher, delta=delta, limit=2)
    if page1["n"] < 2 or page1["cursor"].get("done"):
        skip_test("not enough matches to paginate")
    nxt = int(page1["cursor"]["next"], 16)
    page2 = _objdump_search.search_disasm(
        od, cache["input_path"], matcher, delta=delta, limit=2, start_ea=nxt
    )
    a1 = {h["addr"] for h in page1["hits"]}
    a2 = {h["addr"] for h in page2["hits"]}
    assert not (a1 & a2), f"duplicate hits across pages: {a1 & a2}"


@test()
def test_fastpath_declines_when_ida_not_busy():
    """With no in-flight @idasync calls, the fast path declines (returns None)."""
    # In the test harness nothing else is holding the main thread, so depth==0
    # and search_text should stay on the IDA engine.
    out = _maybe_search_text_fast(
        "call", 5, "", False, False, "all", True, 5.0
    )
    assert out is None


@test()
def test_fastpath_declines_unsupported_requests():
    """comments-only and data (code_only=False) searches never use objdump."""
    assert _maybe_search_text_fast("x", 5, "", False, False, "comments", True, 5.0) is None
    assert _maybe_search_text_fast("x", 5, "", False, False, "all", False, 5.0) is None


@test()
def test_fastpath_intel_syntax_matches_ida_mnemonics():
    """On x86, -M intel makes objdump emit Intel mnemonics/registers like IDA.

    A query written against IDA's Intel listing (e.g. 'call rax') matches under
    intel=True but not under objdump's AT&T default ('call *%rax').
    """
    import idaapi

    od = _require_objdump()
    _prime_search_meta_cache()
    cache = _get_search_meta_cache()
    if not _objdump_search.is_x86(od, cache["input_path"]):
        skip_test("non-x86 target; -M intel not applicable")
    base = _objdump_search.objdump_base(od, cache["input_path"])
    delta = cache["imagebase"] - base
    matcher = _build_text_matcher(r"call\s+rax", regex=True, case_sensitive=False)
    intel = _objdump_search.search_disasm(od, cache["input_path"], matcher, delta=delta, limit=20, intel=True)
    att = _objdump_search.search_disasm(od, cache["input_path"], matcher, delta=delta, limit=20, intel=False)
    if intel["n"] == 0:
        skip_test("no 'call rax' in this binary")
    assert intel["n"] > att["n"], "intel syntax should match Intel-style queries that AT&T does not"


# ============================================================================
# Tests for async jobs (submit_job / job_status / job_list / job_cancel)
#
# These exercise the job plumbing through the real MCP registry. To stay safe
# under the single-threaded headless test server, the round-trip uses a
# non-@idasync tool (server_liveness) so the job never needs main-thread pumping.
# ============================================================================


def _wait_job(job_id, status, timeout=5.0):
    """Poll job_status until `status` (or any terminal state if asking for
    'completed'); fail after timeout."""
    import time

    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = job_status(job_id)
        if last.get("status") == status:
            return last
        if last.get("status") in ("failed", "cancelled") and status == "completed":
            raise AssertionError(f"job ended {last['status']}: {last.get('error')}")
        time.sleep(0.01)
    raise AssertionError(f"job {job_id} did not reach {status!r} in {timeout}s (last={last})")


@test()
def test_submit_job_unknown_tool_returns_error():
    """submit_job rejects an unregistered tool name up front."""
    result = submit_job("___no_such_tool___", {})
    assert "error" in result
    assert "unknown tool" in result["error"]


@test()
def test_submit_job_rejects_job_control_tool():
    """Job-control tools cannot be scheduled as jobs (recursion/footgun guard)."""
    result = submit_job("job_status", {"job_id": "x"})
    assert "error" in result
    assert "cannot be run as a job" in result["error"]


@test()
def test_submit_job_roundtrip_completes_with_result():
    """A submitted job runs the target tool and its result is retrievable.

    Uses server_liveness (not @idasync) so this is safe on the single-threaded
    headless test server as well as the threaded GUI plugin.
    """
    submitted = submit_job("server_liveness", {})
    assert "error" not in submitted, submitted
    job_id = submitted["job_id"]
    assert submitted["tool"] == "server_liveness"

    done = _wait_job(job_id, "completed")
    assert "result" in done, done
    # server_liveness always reports alive=True.
    assert done["result"].get("alive") is True


@test()
def test_job_status_unknown_returns_error():
    result = job_status("does-not-exist")
    assert "error" in result
    assert "unknown job" in result["error"]


@test()
def test_job_list_contains_submitted_job():
    """A submitted job appears in job_list (no result payload there)."""
    submitted = submit_job("server_liveness", {})
    job_id = submitted["job_id"]
    _wait_job(job_id, "completed")

    listing = job_list()
    assert "jobs" in listing
    ids = [j["job_id"] for j in listing["jobs"]]
    assert job_id in ids
    # job_list entries never carry the result payload.
    entry = next(j for j in listing["jobs"] if j["job_id"] == job_id)
    assert "result" not in entry

    # Status filter narrows the set and never returns a non-matching status.
    completed = job_list(status="completed")
    assert all(j["status"] == "completed" for j in completed["jobs"])


@test()
def test_job_cancel_unknown_returns_false():
    result = job_cancel("does-not-exist")
    assert result["cancelled"] is False
    assert result["job_id"] == "does-not-exist"
@test()
def test_idb_save_keeps_working_files():
    """Repeated saves must not delete the open database's working files (#498)."""
    import os
    import ida_loader

    idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    base = os.path.splitext(idb)[0] if idb.lower().endswith((".i64", ".idb")) else idb
    parts = [base + ext for ext in (".id0", ".id1", ".id2", ".nam", ".til")]
    before = [p for p in parts if os.path.exists(p)]
    if not before:
        skip_test("no loose working files for this database")

    for _ in range(2):
        result = idb_save()
        assert result["ok"], result.get("error")
        missing = [p for p in before if not os.path.exists(p)]
        assert not missing, f"save removed working files: {missing}"

    assert_non_empty(list_funcs({"offset": 0, "count": 5})[0]["data"])


@test()
def test_deadline_paused_lets_a_cache_build_outlast_the_tool_deadline():
    """Work inside deadline_paused() doesn't count against the tool deadline."""
    import time
    from ..sync import deadline_paused, get_tool_deadline, idasync, tool_timeout

    @idasync
    @tool_timeout(0.3)
    def slow_cache_build():
        before = get_tool_deadline()
        with deadline_paused():
            time.sleep(0.8)  # longer than the whole 0.3s budget
        after = get_tool_deadline()
        # Plenty of ordinary Python calls after the pause: none may time out.
        total = sum(len(str(i)) for i in range(2000))
        return before, after, total

    before, after, total = slow_cache_build()
    assert total > 0
    assert after - before >= 0.7, "paused time must be added back to the deadline"


@test()
def test_cancelled_strings_build_is_not_cached():
    """A cancelled strings-list build is partial: raise, don't cache it."""
    import ida_kernwin
    from .. import api_core
    from ..sync import IDAError

    ida_kernwin.set_cancelled()
    observable = ida_kernwin.user_cancelled()
    ida_kernwin.clr_cancelled()
    if not observable:
        # idalib: user_cancelled() never reports set_cancelled(), so builds
        # can't be cut short there (only the GUI can produce a partial list).
        skip_test("user_cancelled() does not observe set_cancelled() here")

    api_core.invalidate_strings_cache()
    ida_kernwin.set_cancelled()
    try:
        try:
            api_core._get_strings_cache()
            raise AssertionError("expected IDAError for a cancelled build")
        except IDAError:
            pass
        assert api_core._strings_cache is None
    finally:
        ida_kernwin.clr_cancelled()
    strings = api_core._get_strings_cache()
    assert api_core._strings_cache is strings


@test()
def test_entity_query_lazy_columns_match_direct_lookups():
    """Lazily filled entity columns equal direct IDA lookups, with projection."""
    import ida_nalt
    import ida_typeinf
    import idaapi

    page = entity_query(
        {"kind": "functions", "count": 3, "fields": ["addr", "segment", "has_type"]}
    )[0]
    assert page["error"] is None and page["total"] >= len(page["data"]) > 0
    for row in page["data"]:
        assert set(row) == {"kind", "addr", "segment", "has_type"}
        ea = int(row["addr"], 16)
        assert row["segment"] == idaapi.get_segm_name(idaapi.getseg(ea))
        assert row["has_type"] == bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), ea))

    glob = entity_query({"kind": "globals", "count": 20})[0]
    for row in glob["data"]:
        assert idaapi.get_func(int(row["addr"], 16)) is None, row


# ---------------------------------------------------------------------------
# search_text listing index: results stay correct after edits
# ---------------------------------------------------------------------------


def _first_code_head():
    import ida_funcs
    import idautils

    for i in range(ida_funcs.get_func_qty()):
        fn = ida_funcs.getn_func(i)
        heads = list(idautils.Heads(fn.start_ea, fn.end_ea))
        if len(heads) >= 2:
            return heads[1]
    return None


@test()
def test_search_text_index_sees_comment_edits():
    """Comments added/removed after indexing are found/forgotten at once."""
    import ida_bytes
    import ida_lines

    ea = _first_code_head()
    if ea is None:
        skip_test("no function with two heads")
    token = "zqIdxCmtToken"
    search_text("___warm_the_index___", time_budget_sec=0)  # build the index
    old_cmt = ida_bytes.get_cmt(ea, False)
    try:
        ida_bytes.set_cmt(ea, f"note {token}", False)
        hits = search_text(token)["hits"]
        assert [h["addr"] for h in hits] == [hex(ea)], hits
        assert hits[0]["matches"][0]["kind"] == "comment"
        assert search_text(token, include="disasm")["n"] == 0
        assert search_text(token, include="comments")["n"] == 1

        ida_lines.add_extra_cmt(ea, True, f"anterior {token}x")
        hits = search_text(f"{token}x")["hits"]
        assert [h["addr"] for h in hits] == [hex(ea)], hits
        assert hits[0]["matches"][0]["kind"] == "comment"
    finally:
        ida_bytes.set_cmt(ea, old_cmt or "", False)
        ida_lines.del_extra_cmt(ea, ida_lines.E_PREV)
    assert search_text(token)["n"] == 0


@test()
def test_search_text_index_sees_renames_at_call_sites():
    """Renaming a callee updates the indexed text of its callers' windows."""
    import ida_funcs
    import ida_name
    import idautils
    import ida_xref

    target = None
    for callee_ea in idautils.Functions():
        callee = ida_funcs.get_func(callee_ea)
        if callee is None or callee.flags & ida_funcs.FUNC_THUNK:
            continue
        sites = [
            x.frm
            for x in idautils.XrefsTo(callee_ea)
            if x.type in (ida_xref.fl_CN, ida_xref.fl_CF)
        ]
        if sites:
            target = (callee_ea, sites)
            break
    if target is None:
        skip_test("no direct calls")
    callee_ea, sites = target
    old_name = ida_name.get_name(callee_ea)
    new_name = "zqIdxRenamedFunc"
    search_text("___warm_the_index___", time_budget_sec=0)
    try:
        assert ida_name.set_name(callee_ea, new_name, ida_name.SN_NOWARN)
        found = {h["addr"] for h in search_text(new_name, limit=500)["hits"]}
        assert {hex(s) for s in sites} <= found, (sites, found)
    finally:
        ida_name.set_name(callee_ea, old_name, ida_name.SN_NOWARN)
    assert search_text(new_name)["n"] == 0


@test()
def test_search_text_reports_index_coverage():
    result = search_text("___coverage_probe___", time_budget_sec=0)
    assert 0.0 < result["index"]["coverage"] <= 1.0


@test()
def test_listing_index_background_build_completes():
    """build_step (the headless background builder) indexes every window."""
    from ..listing_index import ListingIndex

    index = ListingIndex()
    try:
        for _ in range(100000):
            if index.build_step(0.05):
                break
        else:
            raise AssertionError("build_step never completed")
        status = index.status()
        assert status["coverage"] == 1.0 and status["indexed"] == status["windows"] > 0
        # Indexed text agrees with a live render.
        from ..listing_index import WINDOW, render_head
        w = next(iter(index.windows))
        text, eas, _kinds = index.windows[w].unpack()
        first_ea = eas[0]
        assert text.split("\n")[0] == render_head(first_ea)[0][1]
        assert all(w <= ea < w + WINDOW for ea in eas)
    finally:
        index.reset()
