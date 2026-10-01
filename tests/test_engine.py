from intellidetect.engine import BeaconRule, Detector, SequenceRule, WindowRule, load_native_rules
from intellidetect.matching import Context

from .conftest import make_event


def fails(n, ip="1.2.3.4", gap=2, users=None, start=0):
    return [make_event(start + i * gap, "auth_failure", src_ip=ip, host="bastion01",
                       user=(users[i % len(users)] if users else "root")) for i in range(n)]


def threshold_rule(**over):
    spec = {"id": "T-1", "title": "bf", "type": "threshold", "severity": "high",
            "match": {"kind": "auth_failure"}, "group_by": "src_ip", "count": 5, "window": 60, **over}
    return WindowRule(spec)


def test_threshold_fires_at_count_and_only_once_per_burst():
    alerts = threshold_rule().evaluate(fails(40), Context())
    assert len(alerts) == 1
    a = alerts[0]
    assert a.src_ip == "1.2.3.4" and a.count == 40 and a.host == "bastion01"
    assert a.last_seen > a.first_seen


def test_threshold_below_count_is_silent():
    assert threshold_rule().evaluate(fails(4), Context()) == []


def test_threshold_respects_window():
    # 5 failures but spread over far more than 60 seconds -> never 5 inside one window
    assert threshold_rule().evaluate(fails(5, gap=30), Context()) == []


def test_separate_bursts_make_separate_alerts():
    events = fails(6) + fails(6, start=3600)
    assert len(threshold_rule().evaluate(events, Context())) == 2


def test_groups_are_independent():
    events = sorted(fails(3, ip="1.1.1.1") + fails(3, ip="2.2.2.2"), key=lambda e: e.ts)
    assert threshold_rule().evaluate(events, Context()) == []


def test_uses_event_time_not_wall_clock():
    # The simulated events are weeks old; they must still alert.
    assert len(threshold_rule().evaluate(fails(10), Context())) == 1


def test_exclude_allowlist_suppresses_alert():
    rule = threshold_rule(exclude={"src_ip|in_list": "scanners"})
    ctx = Context(lists={"scanners": {"1.2.3.4"}})
    assert rule.evaluate(fails(10), ctx) == []
    assert len(rule.evaluate(fails(10, ip="5.6.7.8"), ctx)) == 1


def test_distinct_counts_unique_values():
    rule = WindowRule({"id": "D", "title": "spray", "type": "distinct", "match": {"kind": "auth_failure"},
                       "group_by": "src_ip", "distinct": "user", "count": 3, "window": 60})
    assert rule.evaluate(fails(10, users=["a", "b"]), Context()) == []
    assert len(rule.evaluate(fails(10, users=["a", "b", "c"]), Context())) == 1


def test_sum_metric_triggers_on_volume():
    rule = WindowRule({"id": "S", "title": "big", "type": "threshold", "match": {"kind": "fw_allow"},
                       "group_by": "src_ip", "sum": "bytes", "count": 100, "window": 60})
    small = [make_event(i, "fw_allow", source="firewall", src_ip="10.0.0.1", data={"bytes": 10}) for i in range(5)]
    big = [make_event(i, "fw_allow", source="firewall", src_ip="10.0.0.1", data={"bytes": 30}) for i in range(5)]
    assert rule.evaluate(small, Context()) == []
    assert len(rule.evaluate(big, Context())) == 1


def test_burst_entities_come_from_whole_burst():
    rule = WindowRule({"id": "X", "title": "sweep", "type": "distinct", "match": {"kind": "fw_allow"},
                       "group_by": "src_ip", "distinct": "dst_ip", "count": 3, "window": 120})
    evs = [make_event(i, "fw_allow", source="firewall", src_ip="10.0.0.1", dst_ip=f"10.0.1.{i}") for i in range(3)]
    evs += [make_event(10 + i, "fw_allow", source="firewall", src_ip="10.0.0.1", dst_ip="10.0.2.10") for i in range(6)]
    (alert,) = rule.evaluate(evs, Context())
    assert alert.dst_ip == "10.0.2.10"


def sequence_rule(prior=5):
    return SequenceRule({"id": "Q", "title": "ok after bf", "type": "sequence", "severity": "critical",
                         "match": {"kind": "auth_success"}, "preceded_by": {"match": {"kind": "auth_failure"},
                                                                            "count": prior},
                         "group_by": "src_ip", "window": 600})


def test_sequence_fires_after_enough_failures():
    events = fails(5) + [make_event(30, "auth_success", src_ip="1.2.3.4", user="deploy", host="bastion01")]
    (alert,) = sequence_rule().evaluate(events, Context())
    assert alert.user == "deploy" and alert.severity == "critical"


def test_sequence_silent_with_four_failures_or_other_source_or_too_late():
    ok = make_event(30, "auth_success", src_ip="1.2.3.4", user="u")
    assert sequence_rule().evaluate(fails(4) + [ok], Context()) == []
    assert sequence_rule().evaluate(fails(5, ip="9.9.9.9") + [ok], Context()) == []
    late = make_event(5000, "auth_success", src_ip="1.2.3.4", user="u")
    assert sequence_rule().evaluate(fails(5) + [late], Context()) == []


def beacon_events(intervals, dst="192.0.2.77", host="WS-A"):
    t, out = 0.0, []
    for gap in intervals:
        out.append(make_event(t, "network_connect", source="sysmon", host=host, dst_ip=dst, dst_port=443))
        t += gap
    return out


def beacon_rule(**over):
    spec = {"id": "B", "title": "beacon", "type": "beacon", "match": {"kind": "network_connect"},
            "count": 8, "window": 1800, "max_jitter": 0.25, "min_interval": 10, "max_interval": 900, **over}
    return BeaconRule(spec)


def test_beacon_detects_regular_interval():
    (alert,) = beacon_rule().evaluate(beacon_events([60, 61, 59, 60, 62, 58, 60, 60, 61, 59]), Context())
    assert alert.dst_ip == "192.0.2.77" and "jitter" in alert.description


def test_beacon_ignores_irregular_traffic_and_too_few_connections():
    irregular = [3, 200, 15, 400, 7, 90, 600, 20, 5, 250]
    assert beacon_rule().evaluate(beacon_events(irregular), Context()) == []
    assert beacon_rule().evaluate(beacon_events([60] * 4), Context()) == []


def test_beacon_respects_interval_bounds_and_allowlist():
    assert beacon_rule().evaluate(beacon_events([1] * 12), Context()) == []  # too fast
    rule = beacon_rule(exclude={"dst_ip|in_list": "good"})
    ctx = Context(lists={"good": {"192.0.2.77"}})
    assert rule.evaluate(beacon_events([60] * 12), ctx) == []


def test_sigma_alerts_are_folded_within_cooldown():
    det = Detector(native=[], ctx=Context())
    cmd = "powershell.exe -w hidden -enc AAAA"
    evs = [make_event(i * 5, "process_create", source="sysmon", host="WS-A", user="CORP\\a",
                      data={"image": "C:\\x\\powershell.exe", "command_line": cmd}) for i in range(6)]
    alerts = det.run(evs)
    sg1 = [a for a in alerts if a.rule_id == "IDT-SG-001"]
    assert len(sg1) == 1 and sg1[0].count == 6


def test_detector_assigns_sequential_ids_in_time_order():
    det = Detector(ctx=Context())
    evs = fails(10) + [make_event(500, "auth_success", src_ip="1.2.3.4", user="x", host="h")]
    alerts = det.run(sorted(evs, key=lambda e: e.ts))
    assert [a.id for a in alerts] == [f"ALR-{i:04d}" for i in range(1, len(alerts) + 1)]
    assert alerts == sorted(alerts, key=lambda a: a.first_seen)


def test_native_rule_file_loads_and_is_consistent():
    rules = load_native_rules()
    assert len(rules) >= 8
    assert len({r.id for r in rules}) == len(rules)
    assert all(r.tactic and r.technique for r in rules)


def test_sum_alert_starts_at_the_first_contributing_event():
    rule = WindowRule({"id": "S", "title": "big", "type": "threshold", "match": {"kind": "fw_allow"},
                       "group_by": "src_ip", "sum": "bytes", "count": 100, "window": 600})
    noise = [make_event(i, "fw_allow", source="firewall", src_ip="10.0.0.1", data={"bytes": 5}) for i in range(3)]
    big = [make_event(100 + i * 10, "fw_allow", source="firewall", src_ip="10.0.0.1", data={"bytes": 60})
           for i in range(3)]
    (alert,) = rule.evaluate(noise + big, Context())
    assert alert.first_seen == big[0].ts
