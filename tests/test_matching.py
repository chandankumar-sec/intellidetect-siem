import pytest

from intellidetect.matching import Context, compile_selection
from intellidetect.models import is_public_ip

from .conftest import make_event


def match(selection, ev, ctx=None):
    return compile_selection(selection)(ev, ctx or Context())


def test_equality_is_case_insensitive_and_supports_wildcards():
    ev = make_event(kind="process_create", host="WS-ALICE")
    assert match({"host": "ws-alice"}, ev)
    assert match({"host": "WS-*"}, ev)
    assert not match({"host": "srv-*"}, ev)


def test_string_modifiers():
    ev = make_event(kind="process_create", data={"command_line": "powershell.exe -ENC abc"})
    assert match({"CommandLine|contains": " -enc "}, ev)
    assert match({"CommandLine|startswith": "powershell"}, ev)
    assert match({"CommandLine|endswith": "abc"}, ev)
    assert not match({"CommandLine|contains": "mimikatz"}, ev)


def test_list_is_or_and_all_modifier_is_and():
    ev = make_event(data={"command_line": "curl http://x | bash"})
    assert match({"CommandLine|contains": ["wget", "curl"]}, ev)
    assert match({"CommandLine|contains|all": ["curl", "| bash"]}, ev)
    assert not match({"CommandLine|contains|all": ["curl", "wget"]}, ev)


def test_regex_and_numeric():
    ev = make_event(kind="fw_allow", dst_port=445, data={"bytes": 5000})
    assert match({"dst_port|gte": 445, "bytes|gt": 4999}, ev)
    assert not match({"bytes|lt": 10}, ev)
    assert match({"kind|re": "^fw_(allow|deny)$"}, ev)


def test_missing_field_does_not_match_but_null_does():
    ev = make_event()
    assert not match({"CommandLine|contains": "x"}, ev)
    assert match({"CommandLine": None}, ev)


def test_is_public_and_in_list():
    ctx = Context(lists={"scanners": {"10.0.5.5"}})
    assert match({"dst_ip|is_public": True}, make_event(dst_ip="8.8.8.8"))
    assert match({"dst_ip|is_public": False}, make_event(dst_ip="10.1.2.3"))
    assert match({"src_ip|in_list": "scanners"}, make_event(src_ip="10.0.5.5"), ctx)
    assert not match({"src_ip|in_list": "scanners"}, make_event(src_ip="10.0.5.6"), ctx)


def test_documentation_ranges_count_as_external():
    assert is_public_ip("203.0.113.5") and is_public_ip("198.51.100.1") and is_public_ip("192.0.2.9")
    assert not is_public_ip("10.0.0.1") and not is_public_ip("192.168.1.1")
    assert not is_public_ip("not-an-ip")


def test_selection_list_means_or():
    sel = [{"host": "a"}, {"host": "b"}]
    assert match(sel, make_event(host="b")) and not match(sel, make_event(host="c"))


def test_unknown_modifier_raises():
    with pytest.raises(ValueError):
        compile_selection({"host|bogus": "x"})
