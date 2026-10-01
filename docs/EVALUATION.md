# Evaluation

## What this measures (and what it does not)

The simulator (`src/intellidetect/simulator.py`) generates about 5,537 log lines over 8 hours: normal workday traffic, five deliberately tricky benign cases, and four labeled attack scenarios. `intellidetect evaluate` runs the full pipeline and checks the result against `ground_truth.json`.

**This is a regression and sanity test, not a claim of real-world accuracy.** The same person wrote the attacks and the detections, the data is synthetic, and the rules are tuned to this environment. Real logs are messier. Treat the numbers as proof that the pipeline behaves as designed (and a safety net when changing rules), not as a benchmark.

## Results (seed 1337)

| Metric | Result |
|---|---|
| Attack scenarios fully detected and correlated into one incident | **4 / 4** |
| Expected detections that fired (rule-level recall) | **100%** |
| Benign / tricky cases handled correctly | **5 / 5** |
| Alerts with no matching scenario (unexplained) | **0** |
| Events ingested -> alerts -> incidents | 5,537 -> 21 -> **5** |

| Scenario | Type | Expected detections | Fired | Missing | Incidents | Result |
|---|---|---|---|---|---|---|
| N1 Authorized vulnerability scan | benign | silent | 0 | - | - | PASS |
| N2 Scheduled off-site backup | benign | silent | 0 | - | - | PASS |
| N3 Teams telemetry heartbeat | benign | silent | 0 | - | - | PASS |
| N4 Mistyped password, then success | benign | silent | 0 | - | - | PASS |
| N5 Help-desk privilege check | benign | 1 | 1 | - | INC-003 | PASS |
| S1 SSH brute force leading to account takeover | attack | 4 | 4 | - | INC-001 | PASS |
| S2 Phishing document to exfiltration (multi-stage intrusion) | attack | 11 | 11 | - | INC-002 | PASS |
| S3 Port scan followed by directory brute forcing | attack | 2 | 2 | - | INC-004 | PASS |
| S4 Web application exploitation and web shell | attack | 3 | 3 | - | INC-005 | PASS |

## Why the tuning matters

With the environment allow-lists disabled (authorized scanner, backup target, known-good telemetry destination) the same data produces **25 alerts instead of 21**: 4 extra alerts that are all benign. The tricky cases:

| Case | What it looks like | How it is handled |
|---|---|---|
| N1 Authorized vulnerability scan | Port scan plus SMB sweep | `trusted_scanners` allow-list |
| N2 Scheduled backup | 400 MB sent to an external IP | `backup_destinations` allow-list |
| N3 Teams telemetry | Connection every 30 s (beacon-shaped) | `known_good_destinations` allow-list |
| N4 Mistyped password | 4 failures then success | Below the 5-failure sequence threshold |
| N5 Help-desk `whoami /priv` | Real detection, benign cause | Fires as a low-risk P4 incident to close |

## Reproduce

```bash
intellidetect simulate --out data --start 2026-03-10T08:00:00
intellidetect evaluate --logs data
```

## Known limitations

- Allow-lists are static YAML; a production deployment needs them fed from a CMDB.
- Correlation links alerts by shared host, user or IP inside a 30-minute gap. It does not follow process trees or network flows between hosts.
- The bundled threat-intel feed is synthetic. Bring your own CSV with `--intel`.
- Sigma support covers the subset documented in `src/intellidetect/sigma.py` (no `near`, `count()` aggregations or field-mapping pipelines).
- Log formats are fixed (OpenSSH/sudo syslog, Sysmon key=value, iptables-style, Apache combined).
