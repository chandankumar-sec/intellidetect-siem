"""Self-contained HTML dashboard (no external assets, works offline)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from . import __version__
from .pipeline import Result
from .reporting import narrative, recommended_actions, summary

TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IntelliDetect: SOC triage console</title>
<style>
:root{--bg:#0b1220;--panel:#111a2e;--panel2:#16213a;--line:#1f2d4b;--text:#e6edf7;--muted:#8da2c0;
--accent:#4f8cff;--critical:#ff4d6d;--high:#ff9f43;--medium:#f2cf3d;--low:#4cc9f0;--ok:#3ddc97}
@media (prefers-color-scheme:light){:root{--bg:#f3f6fb;--panel:#fff;--panel2:#f6f8fc;--line:#dbe3f0;
--text:#13203a;--muted:#5b6b86;--accent:#2563eb;--critical:#d6264a;--high:#e07b12;--medium:#b58f00;--low:#0b86a8;--ok:#16a06a}}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text)}
header{display:flex;align-items:center;gap:14px;padding:16px 28px;border-bottom:1px solid var(--line)}
.logo{width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,var(--accent),#7c5cff);display:grid;place-items:center;font-weight:800;color:#fff}
h1{font-size:17px;margin:0}header small{color:var(--muted)}header .sp{flex:1}
main{padding:22px 28px;max-width:1500px;margin:0 auto}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.kpi .v{font-size:30px;font-weight:700;letter-spacing:-.5px}.kpi .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.kpi .s{color:var(--muted);font-size:12px;margin-top:2px}
.grid{display:grid;grid-template-columns:minmax(380px,5fr) 7fr;gap:18px;align-items:start}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin:0 0 12px}
.inc{display:grid;grid-template-columns:44px 1fr;gap:12px;padding:12px;border:1px solid transparent;border-radius:10px;cursor:pointer}
.inc:hover{background:var(--panel2)}.inc.sel{background:var(--panel2);border-color:var(--accent)}
.badge{display:inline-grid;place-items:center;min-width:34px;height:24px;padding:0 7px;border-radius:6px;font-size:12px;font-weight:700;color:#fff}
.P1{background:var(--critical)}.P2{background:var(--high)}.P3{background:var(--medium);color:#241c00}.P4{background:#51617f}
.inc .t{font-weight:600}.inc .m{color:var(--muted);font-size:12px;margin-top:3px}
.bar{height:6px;border-radius:4px;background:var(--line);overflow:hidden;margin-top:7px}.bar i{display:block;height:100%}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.chip{font-size:11px;padding:2px 8px;border-radius:99px;background:var(--panel2);border:1px solid var(--line);color:var(--muted)}
.chip.k{color:var(--text)}
.detail h3{margin:0 0 4px;font-size:18px}.detail .meta{color:var(--muted);margin-bottom:12px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:16px}
.tl{position:relative;margin:6px 0 0 8px;padding-left:20px;border-left:2px solid var(--line)}
.tl .e{position:relative;margin-bottom:14px}.tl .e:before{content:"";position:absolute;left:-27px;top:5px;width:12px;height:12px;border-radius:50%;background:var(--c);border:2px solid var(--panel)}
.tl .tm{color:var(--muted);font-size:12px;font-variant-numeric:tabular-nums}.tl .rt{font-weight:600}.tl .sub{color:var(--muted);font-size:12px}
code{font:12px ui-monospace,Menlo,Consolas,monospace;background:var(--panel2);padding:1px 5px;border-radius:4px}
.row{display:grid;grid-template-columns:1fr auto;gap:10px;font-size:13px;padding:5px 0;border-bottom:1px dashed var(--line)}
ol{padding-left:20px;margin:6px 0}li{margin-bottom:6px}
.bottom{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-top:18px}
.hb{display:grid;grid-template-columns:150px 1fr 38px;gap:10px;align-items:center;margin:7px 0;font-size:12px}
.hb .b{height:9px;border-radius:5px;background:var(--line);overflow:hidden}.hb .b i{display:block;height:100%;background:var(--accent)}
.funnel{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.funnel .n{font-size:26px;font-weight:700}.funnel .a{color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:12px}td,th{padding:5px 4px;text-align:left;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:600}
footer{color:var(--muted);font-size:12px;text-align:center;padding:24px}
@media(max-width:1000px){.grid,.two,.bottom,.kpis{grid-template-columns:1fr}.kpis{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<header><div class="logo">ID</div><div><h1>IntelliDetect</h1><small>SOC triage console</small></div><div class="sp"></div>
<small id="gen"></small></header>
<main>
<section class="kpis" id="kpis"></section>
<section class="grid">
  <div class="card"><h2>Incident queue (ranked by risk)</h2><div id="queue"></div></div>
  <div class="card detail" id="detail"></div>
</section>
<section class="bottom">
  <div class="card"><h2>Alert reduction</h2><div id="funnel"></div></div>
  <div class="card"><h2>ATT&amp;CK tactics detected</h2><div id="tactics"></div></div>
  <div class="card"><h2>Log ingestion health</h2><table id="parse"></table></div>
</section>
</main>
<footer>Generated by IntelliDetect v__VERSION__ on synthetic demo data. Detections are mapped to MITRE ATT&amp;CK.</footer>
<script id="data" type="application/json">__DATA__</script>
<script>
const D = JSON.parse(document.getElementById('data').textContent);
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const css = n => getComputedStyle(document.documentElement).getPropertyValue('--' + n).trim();
const sevColor = s => css(s) || css('low');
const fmt = t => t.replace('T', ' ').slice(0, 19);
const scoreColor = s => s >= 80 ? css('critical') : s >= 60 ? css('high') : s >= 35 ? css('medium') : css('low');

$('gen').textContent = 'Generated ' + D.generated + ' UTC';
const S = D.summary;
$('kpis').innerHTML = [
  ['Events ingested', S.events.toLocaleString(), 'across ' + Object.keys(S.parse).length + ' log sources'],
  ['Detections raised', S.alerts, 'after de-duplication'],
  ['Incidents to triage', S.incidents, 'P1: ' + S.priorities.P1 + ' · P2: ' + S.priorities.P2 + ' · P3: ' + S.priorities.P3 + ' · P4: ' + S.priorities.P4],
  ['Noise reduction', S.reduction_events_to_incidents_pct + '%', 'events → incidents']
].map(k => `<div class="card kpi"><div class="l">${k[0]}</div><div class="v">${k[1]}</div><div class="s">${k[2]}</div></div>`).join('');

let sel = 0;
function renderQueue() {
  $('queue').innerHTML = D.incidents.map((i, n) => `
   <div class="inc ${n === sel ? 'sel' : ''}" data-n="${n}">
     <div><span class="badge ${i.priority}">${i.priority}</span></div>
     <div><div class="t">${esc(i.name)}</div>
       <div class="m">${i.id} · score ${i.score}/100 · ${i.alerts.length} detection(s) · ${fmt(i.first_seen)} UTC</div>
       <div class="bar"><i style="width:${i.score}%;background:${scoreColor(i.score)}"></i></div>
       <div class="chips">${i.tactics.map(t => `<span class="chip k">${esc(t)}</span>`).join('')}</div></div>
   </div>`).join('');
  document.querySelectorAll('.inc').forEach(el => el.onclick = () => { sel = +el.dataset.n; renderQueue(); renderDetail(); });
}
function renderDetail() {
  const i = D.incidents[sel];
  const ents = [['Hosts', 'hosts'], ['Users', 'users'], ['External IPs', 'external_ips'], ['Internal IPs', 'internal_ips']]
    .filter(e => (i.entities[e[1]] || []).length)
    .map(e => `<div class="row"><span>${e[0]}</span><span>${i.entities[e[1]].map(v => `<code>${esc(v)}</code>`).join(' ')}</span></div>`).join('');
  const intel = i.intel.map(h => `<div class="row"><span><code>${esc(h.indicator)}</code> ${esc(h.threat)}</span><span>conf. ${h.confidence}</span></div>`).join('');
  $('detail').innerHTML = `
   <div style="display:flex;gap:10px;align-items:center;margin-bottom:6px"><span class="badge ${i.priority}">${i.priority}</span><small style="color:var(--muted)">${i.id} · ${esc(i.severity)} severity</small></div>
   <h3>${esc(i.name)}</h3>
   <div class="meta">${esc(i.narrative)}</div>
   <div class="two">
     <div><h2>Kill-chain timeline</h2><div class="tl">${i.alerts.map(a => `
       <div class="e" style="--c:${sevColor(a.severity)}"><div class="tm">${fmt(a.first_seen)} UTC · ${esc(a.tactic)}${a.technique ? ' · ' + esc(a.technique) : ''}</div>
       <div class="rt">${esc(a.rule_title)}</div><div class="sub">${esc(a.host || a.src_ip || a.user)}${a.count > 1 ? ' · ' + a.count + ' events' : ''} · <code>${esc(a.rule_id)}</code></div></div>`).join('')}</div></div>
     <div>
       <h2>Why this score: ${i.score}/100</h2>
       ${i.score_breakdown.map(b => `<div class="row"><span>${esc(b.reason)}</span><b>+${b.points}</b></div>`).join('')}
       <h2 style="margin-top:18px">Entities</h2>${ents}${intel}
       <h2 style="margin-top:18px">Recommended response</h2>
       <ol>${i.actions.map(a => `<li>${esc(a)}</li>`).join('')}</ol>
     </div>
   </div>`;
}
function renderBottom() {
  $('funnel').innerHTML = `<div class="funnel"><div><div class="n">${S.events.toLocaleString()}</div><small>events</small></div><span class="a">→</span>
    <div><div class="n">${S.alerts}</div><small>detections</small></div><span class="a">→</span>
    <div><div class="n" style="color:var(--ok)">${S.incidents}</div><small>incidents</small></div></div>
    <p style="color:var(--muted);font-size:12px">Repeated hits are folded into one alert, and related alerts are merged into one incident per investigation.</p>`;
  const tmax = Math.max(1, ...Object.values(S.alerts_by_tactic));
  $('tactics').innerHTML = Object.entries(S.alerts_by_tactic).map(([t, c]) =>
    `<div class="hb"><span>${esc(t)}</span><div class="b"><i style="width:${100 * c / tmax}%"></i></div><b>${c}</b></div>`).join('');
  $('parse').innerHTML = '<tr><th>Source</th><th>Lines</th><th>Parsed</th><th>Skipped</th></tr>' +
    Object.entries(S.parse).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${v.total.toLocaleString()}</td><td>${v.parsed.toLocaleString()}</td><td>${v.skipped}</td></tr>`).join('');
}
renderQueue(); renderDetail(); renderBottom();
</script>
</body>
</html>
"""


def build_dashboard(result: Result) -> str:
    incidents = []
    for inc in result.ranked_incidents:
        row = inc.to_dict()
        row["narrative"] = narrative(inc)
        row["actions"] = recommended_actions(inc)
        incidents.append(row)
    data = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
        "summary": summary(result),
        "incidents": incidents,
    }
    payload = json.dumps(data).replace("</", "<\\/")
    return TEMPLATE.replace("__VERSION__", __version__).replace("__DATA__", payload)
