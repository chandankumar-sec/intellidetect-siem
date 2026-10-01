from datetime import timedelta

from intellidetect.correlate import alert_entities, correlate
from intellidetect.enrich import IntelFeed, load_environment, load_intel
from intellidetect.models import Alert
from intellidetect.scoring import priority_for, score_incident

from .conftest import T0

CTX, INV = load_environment()


def alert(offset=0, rule="R", sev="medium", tactic="Execution", tech="T1059.001", dur=0, **kw):
    return Alert(id=f"A{offset}{rule}", rule_id=rule, rule_title=f"title {rule}", severity=sev,
                 tactic=tactic, technique=tech, description="d",
                 first_seen=T0 + timedelta(seconds=offset), last_seen=T0 + timedelta(seconds=offset + dur), **kw)


def test_alerts_sharing_a_host_are_merged():
    incidents = correlate([alert(0, host="WS-ALICE"), alert(60, "R2", host="ws-alice")], INV)
    assert len(incidents) == 1 and len(incidents[0].alerts) == 2


def test_ip_is_mapped_to_inventory_host():
    # Firewall alert only knows the IP; the Sysmon alert knows the hostname.
    incidents = correlate([alert(0, host="WS-ALICE"), alert(30, "R2", src_ip="10.0.10.21")], INV)
    assert len(incidents) == 1


def test_unrelated_alerts_stay_separate():
    incidents = correlate([alert(0, host="WS-ALICE"), alert(5, "R2", host="WS-BOB")], INV)
    assert len(incidents) == 2


def test_time_gap_splits_incidents():
    incidents = correlate([alert(0, host="WS-ALICE"), alert(7200, "R2", host="WS-ALICE")], INV, gap=1800)
    assert len(incidents) == 2


def test_generic_users_do_not_link_alerts():
    a, b = alert(0, host="h1", user="root"), alert(10, "R2", host="h2", user="root")
    assert len(correlate([a, b], INV)) == 2
    assert not any(e.startswith("user:") for e in alert_entities(a, INV))
    c, d = alert(0, host="h1", user="CORP\\alice"), alert(10, "R2", host="h2", user="alice")
    assert len(correlate([c, d], INV)) == 1


def test_transitive_linking():
    a = alert(0, host="h1", src_ip="203.0.113.5")
    b = alert(10, "R2", src_ip="203.0.113.5", host="h2")
    c = alert(20, "R3", host="h2", user="alice")
    assert len(correlate([a, b, c], INV)) == 1


def test_incident_properties_and_naming():
    chain = [alert(0, "R1", tactic="Initial Access", tech="T1078", host="WS-ALICE"),
             alert(10, "R2", tactic="Execution", host="WS-ALICE", dur=30),
             alert(20, "R3", tactic="Exfiltration", tech="T1048", host="WS-ALICE", dst_ip="192.0.2.99")]
    (inc,) = correlate(chain, INV)
    assert inc.tactics == ["Initial Access", "Execution", "Exfiltration"]
    assert inc.name.startswith("Multi-stage intrusion (Initial Access to Exfiltration)")
    assert inc.entities["hosts"] == ["WS-ALICE"] and inc.entities["external_ips"] == ["192.0.2.99"]
    assert inc.first_seen == T0 and inc.last_seen == T0 + timedelta(seconds=40)
    assert inc.id == "INC-001"


def test_single_alert_incident_name():
    (inc,) = correlate([alert(0, host="WS-DAVE")], INV)
    assert inc.name == "title R on WS-DAVE"


def test_priority_thresholds():
    assert [priority_for(s) for s in (0, 34, 35, 59, 60, 79, 80, 100)] == [
        "P4", "P4", "P3", "P3", "P2", "P2", "P1", "P1"]


def test_full_kill_chain_reaches_the_maximum_score():
    chain = [alert(i * 10, f"R{i}", sev="critical", tactic=t, host="FILESRV01", dur=70, src_ip="192.0.2.77",
                   indicators=["192.0.2.77"], count=20)
             for i, t in enumerate(["Initial Access", "Execution", "Persistence", "Credential Access",
                                    "Discovery", "Lateral Movement", "Command and Control", "Exfiltration"])]
    (inc,) = correlate(chain, INV)
    score_incident(inc, INV, load_intel())
    # severity 40 + kill chain 24 + critical asset 12 + intel 15 + volume 5
    assert inc.score == 96 == sum(p for _, p in inc.score_breakdown)
    assert inc.priority == "P1" and inc.intel[0]["indicator"] == "192.0.2.77"


def test_low_severity_incident_scores_low():
    (inc,) = correlate([alert(0, sev="low", host="WS-DAVE")], INV)
    score_incident(inc, INV, IntelFeed())
    assert inc.score == 5 and inc.priority == "P4"
    assert inc.score_breakdown[0][0].startswith("Highest alert severity")


def test_critical_asset_adds_points():
    (a,) = correlate([alert(0, sev="high", host="DC01")], INV)
    (b,) = correlate([alert(0, sev="high", host="WS-DAVE")], INV)
    score_incident(a, INV, IntelFeed())
    score_incident(b, INV, IntelFeed())
    assert a.score - b.score == 12


def test_inventory_lookups():
    assert INV.host_for_ip("10.0.2.5") == "dc01"
    assert INV.ip_for_host("WS-ALICE") == "10.0.10.21"
    assert INV.criticality("unknown-host") == "low"
    assert CTX.in_list("trusted_scanners", "10.0.5.5")
