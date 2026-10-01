from datetime import datetime, timezone

from intellidetect.parsers import (
    parse_apache,
    parse_auth,
    parse_firewall,
    parse_lines,
    parse_sysmon,
)


def test_ssh_failed_password():
    ev = parse_auth(
        "Mar 10 08:00:01 bastion01 sshd[123]: Failed password for root from 1.2.3.4 port 5555 ssh2",
        year=2026,
    )
    assert (ev.kind, ev.user, ev.src_ip, ev.host) == ("auth_failure", "root", "1.2.3.4", "bastion01")
    assert ev.ts == datetime(2026, 3, 10, 8, 0, 1, tzinfo=timezone.utc)


def test_ssh_invalid_user_is_failure():
    ev = parse_auth(
        "Mar 10 08:00:01 h sshd[1]: Failed password for invalid user git from 9.9.9.9 port 22 ssh2",
        year=2026,
    )
    assert ev.kind == "auth_failure" and ev.user == "git"
    ev = parse_auth("Mar 10 08:00:01 h sshd[1]: Invalid user oracle from 9.9.9.9 port 22", year=2026)
    assert ev.kind == "auth_failure" and ev.user == "oracle"


def test_ssh_accepted_with_padded_day():
    ev = parse_auth(
        "Mar  5 08:00:01 h sshd[1]: Accepted publickey for alice from 10.0.0.5 port 2222 ssh2", year=2026
    )
    assert ev.kind == "auth_success" and ev.data["method"] == "publickey" and ev.ts.day == 5


def test_sudo_command():
    ev = parse_auth(
        "Mar 10 08:00:01 h sudo:     ops : TTY=pts/0 ; PWD=/home/ops ; USER=root ; "
        "COMMAND=/usr/bin/apt update",
        year=2026,
    )
    assert ev.kind == "sudo" and ev.user == "ops" and ev.data["command"] == "/usr/bin/apt update"


def test_syslog_year_rollover():
    # A December line seen in early January belongs to the previous year.
    now = datetime(2026, 1, 2, tzinfo=timezone.utc)
    ev = parse_auth("Dec 31 23:59:59 h sshd[1]: Accepted password for a from 1.1.1.1 port 1 ssh2", now=now)
    assert ev.ts.year == 2025


def test_auth_ignores_unrelated_lines():
    assert parse_auth("Mar 10 08:00:01 h CRON[1]: pam_unix(cron:session): session opened") is None
    assert parse_auth("garbage") is None


def test_sysmon_process_create():
    line = (
        "2026-03-10 08:00:01.123 UTC;EventID 1;ProcessCreate;Computer=WS-ALICE;User=CORP\\alice;"
        "Image=C:\\Windows\\System32\\cmd.exe;ParentImage=C:\\x\\WINWORD.EXE;"
        "CommandLine=cmd.exe /c a=b;ProcessId=4"
    )
    ev = parse_sysmon(line)
    assert ev.kind == "process_create" and ev.host == "WS-ALICE" and ev.user == "CORP\\alice"
    assert ev.get("Image").endswith("cmd.exe") and ev.get("ParentImage").endswith("WINWORD.EXE")
    assert ev.get("CommandLine") == "cmd.exe /c a=b"
    assert ev.ts.microsecond == 123000


def test_sysmon_network_dns_and_access():
    net = parse_sysmon(
        "2026-03-10 08:00:01.000 UTC;EventID 3;NetworkConnect;Computer=H;User=CORP\\u;"
        "Image=a.exe;SourceIp=10.0.0.1;DestinationIp=8.8.8.8;DestinationPort=443;Protocol=tcp"
    )
    assert (net.kind, net.src_ip, net.dst_ip, net.dst_port) == ("network_connect", "10.0.0.1", "8.8.8.8", 443)
    dns = parse_sysmon(
        "2026-03-10 08:00:01.000 UTC;EventID 22;DNSQuery;Computer=H;User=CORP\\u;QueryName=a.top"
    )
    assert dns.kind == "dns_query" and dns.get("QueryName") == "a.top"
    acc = parse_sysmon(
        "2026-03-10 08:00:01.000 UTC;EventID 10;ProcessAccess;Computer=H;User=CORP\\u;"
        "SourceImage=C:\\t\\p.exe;TargetImage=C:\\Windows\\System32\\lsass.exe;GrantedAccess=0x1410"
    )
    assert acc.kind == "process_access" and acc.get("GrantedAccess") == "0x1410"
    assert acc.get("Image") == "C:\\t\\p.exe"


def test_sysmon_rejects_bad_lines():
    assert parse_sysmon("nonsense") is None
    assert parse_sysmon("2026-03-10 08:00:01.000 UTC;EventID 99;Other;Computer=H") is None
    assert parse_sysmon("not-a-date;EventID 1;ProcessCreate") is None


def test_firewall():
    ev = parse_firewall("2026-03-10 08:00:01 DROP TCP 1.2.3.4:5555 -> 10.0.3.10:22 BYTES=0")
    assert (ev.kind, ev.src_ip, ev.dst_ip, ev.dst_port) == ("fw_deny", "1.2.3.4", "10.0.3.10", 22)
    ok = parse_firewall("2026-03-10 08:00:01 ACCEPT TCP 10.0.0.1:1 -> 8.8.8.8:443 BYTES=2048")
    assert ok.kind == "fw_allow" and ok.get("bytes") == 2048
    assert parse_firewall("bad") is None


def test_firewall_sensor_is_not_an_entity():
    ev = parse_firewall("2026-03-10 08:00:01 DROP TCP 1.2.3.4:5555 -> 10.0.3.10:22 BYTES=0")
    assert ev.host == ""


def test_apache_combined():
    line = '1.2.3.4 - bob [10/Mar/2026:08:00:01 +0000] "GET /a/b?x=1 HTTP/1.1" 404 512 "-" "curl/8"'
    ev = parse_apache(line)
    assert (ev.kind, ev.src_ip, ev.user) == ("http_request", "1.2.3.4", "bob")
    assert ev.get("status") == 404 and ev.get("uri_path") == "/a/b" and ev.get("uri_query") == "x=1"
    assert ev.get("url") == "/a/b?x=1" and ev.get("user_agent") == "curl/8"


def test_apache_timezone_normalised_to_utc():
    ev = parse_apache('1.1.1.1 - - [10/Mar/2026:10:00:00 +0200] "GET / HTTP/1.1" 200 1 "-" "x"')
    assert ev.ts.hour == 8


def test_parse_lines_reports_stats():
    events, stats = parse_lines(
        "firewall", ["2026-03-10 08:00:01 DROP TCP 1.1.1.1:1 -> 2.2.2.2:2 BYTES=0", "oops", ""]
    )
    assert len(events) == 1 and (stats.total, stats.parsed, stats.skipped) == (2, 1, 1)
    assert stats.samples == ["oops"]
