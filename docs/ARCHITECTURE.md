# Architecture

## Data flow

```text
raw logs --> parsers --> Event --> Detector --> Alert --> correlate --> Incident --> score --> outputs
                                     ^                                        ^
                       Sigma + native rules                    asset inventory + threat intel
```

| Stage | Module | Notes |
|---|---|---|
| Parse | `parsers.py` | One function per format. Unparsable lines are counted and surfaced, never silently dropped. |
| Normalize | `models.py` | `Event` has a fixed set of attributes (`host`, `user`, `src_ip`, `dst_ip`, `dst_port`) plus a `data` dict. Sigma field names (`Image`, `CommandLine`, `DestinationIp`) resolve through `FIELD_ALIASES`. |
| Match | `matching.py` | Sigma-style modifiers: `contains`, `startswith`, `endswith`, `re`, `all`, `gt/gte/lt/lte`, plus `is_public` and `in_list` for allow-lists. |
| Detect | `engine.py`, `sigma.py` | Stateless Sigma rules and four stateful rule types. |
| Correlate | `correlate.py` | Union-find over shared entities, split by a time gap. |
| Score | `scoring.py` | Additive, every point has a reason. |
| Output | `reporting.py`, `dashboard.py` | Markdown reports, JSON, ATT&CK Navigator layer, static HTML. |

## Design decisions

**Event time, not wall-clock time.** Every window uses `Event.ts`. A rule evaluated on last week's
logs behaves exactly like it would have live, which makes detections testable and replayable. (The
v1 prototype compared event times to `datetime.now()`, so historical logs silently produced nothing.)

**One alert per burst.** A brute-force attack with 60 failed logins is one alert with `count=60`,
not 52 alerts. The open alert is extended while the burst continues, and entities (host, user, IPs)
are recomputed from the whole burst when it ends.

**Sigma for single events, native rules for state.** Sigma is portable and well known but cannot
express "5 failures then a success" or "regular intervals". Native rules fill that gap in a small
YAML schema that reuses the same matching modifiers.

**Allow-lists are data, not code.** Scanners, backup targets and known-good destinations live in
`environment.yml` and are referenced from rules with `field|in_list: name`. The evaluation doc
shows how many benign alerts this removes.

**Explainable scoring.** An analyst should be able to argue with a score. Each component is listed
in the incident report and dashboard:

| Component | Points |
|---|---|
| Highest alert severity (low / medium / high / critical) | 5 / 15 / 30 / 40 |
| Kill-chain progression (6 per extra tactic) | up to 24 |
| Asset criticality (medium / high / critical) | 3 / 7 / 12 |
| Threat-intel match (confidence >= 85 / lower) | 15 / 8 |
| Sustained activity (50+ underlying detections) | 5 |

Priority: P1 >= 80, P2 >= 60, P3 >= 35, otherwise P4.

## Adding a detection

Sigma (single event): add a `.yml` file to `src/intellidetect/rules/sigma/`. Supported
`logsource.category` values: `process_creation`, `process_access`, `network_connection`,
`dns_query`, `file_event`, `webserver`, and `service: sudo`. Add a positive and a negative case
to `tests/test_sigma.py`.

Stateful: add an entry to `src/intellidetect/rules/native.yml`:

| Type | Required keys |
|---|---|
| `threshold` | `match`, `group_by`, `count`, `window` (optionally `sum: <field>`) |
| `distinct` | `match`, `group_by`, `distinct`, `count`, `window` |
| `sequence` | `match`, `preceded_by: {match, count}`, `group_by`, `window` |
| `beacon` | `match`, `count`, `window`, `max_jitter`, `min_interval`, `max_interval` |

Every rule needs `id`, `title`, `severity`, `tactic` and `technique`. Run `python scripts/make_docs.py`
afterwards to refresh the catalog and evaluation numbers.

## Testing strategy

- Unit tests for each parser, matcher modifier, rule type and scoring component.
- Every bundled Sigma rule has a positive and (where meaningful) a negative case.
- End-to-end test: the simulator's labeled scenarios must be detected and correlated, the benign
  look-alikes must stay quiet, and two runs on the same seed must produce identical output.
- The dashboard test checks that embedded data cannot break out of its `<script>` tag.
