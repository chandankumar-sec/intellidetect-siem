"""Flask REST API and Dashboard for IntelliDetect SIEM."""
from flask import Flask, render_template_string, jsonify, request
from flask_cors import CORS
import json
from pathlib import Path
from datetime import datetime

app = Flask(__name__)
CORS(app)

# In-memory storage (in production, use a database)
alerts_store = []
incidents_store = []

def load_latest_data():
    """Load latest alerts and incidents from output files."""
    global alerts_store, incidents_store
    
    output_dir = Path('data/output')
    if not output_dir.exists():
        return
    
    # Load latest alerts file
    alert_files = sorted(output_dir.glob('alerts_*.json'))
    if alert_files:
        with open(alert_files[-1], 'r') as f:
            data = json.load(f)
            alerts_store = data.get('alerts', [])
    
    # Load latest incidents file
    incident_files = sorted(output_dir.glob('incidents_*.json'))
    if incident_files:
        with open(incident_files[-1], 'r') as f:
            data = json.load(f)
            incidents_store = data.get('incidents', [])

load_latest_data()

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IntelliDetect SIEM Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #eee; }
        .header { background: linear-gradient(135deg, #16213e, #0f3460); padding: 20px; text-align: center; }
        .header h1 { color: #e94560; font-size: 2em; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 20px; }
        .stat-card { background: #16213e; border-radius: 10px; padding: 20px; text-align: center; border-left: 4px solid #e94560; }
        .stat-card.critical { border-color: #ff4757; }
        .stat-card.high { border-color: #ffa502; }
        .stat-card.medium { border-color: #ffdd59; }
        .stat-card.low { border-color: #7bed9f; }
        .stat-number { font-size: 2.5em; font-weight: bold; color: #fff; }
        .stat-label { color: #aaa; margin-top: 5px; }
        .content { padding: 20px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #e94560; margin-bottom: 15px; border-bottom: 2px solid #e94560; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; background: #16213e; border-radius: 10px; overflow: hidden; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #0f3460; }
        th { background: #0f3460; color: #e94560; font-weight: 600; }
        tr:hover { background: #1f4068; }
        .severity { padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: 600; }
        .severity.CRITICAL { background: #ff4757; color: white; }
        .severity.HIGH { background: #ffa502; color: black; }
        .severity.MEDIUM { background: #ffdd59; color: black; }
        .severity.LOW { background: #7bed9f; color: black; }
        .risk-score { font-weight: bold; color: #e94560; }
        .refresh-btn { background: #e94560; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin-bottom: 15px; }
        .refresh-btn:hover { background: #ff6b81; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ IntelliDetect SIEM Dashboard</h1>
        <p>Real-time Security Operations Center</p>
    </div>
    
    <div class="stats">
        <div class="stat-card"><div class="stat-number" id="total-alerts">0</div><div class="stat-label">Total Alerts</div></div>
        <div class="stat-card critical"><div class="stat-number" id="critical-incidents">0</div><div class="stat-label">Critical Incidents</div></div>
        <div class="stat-card high"><div class="stat-number" id="high-incidents">0</div><div class="stat-label">High Incidents</div></div>
        <div class="stat-card medium"><div class="stat-number" id="medium-incidents">0</div><div class="stat-label">Medium Incidents</div></div>
        <div class="stat-card low"><div class="stat-number" id="low-incidents">0</div><div class="stat-label">Low Incidents</div></div>
    </div>
    
    <div class="content">
        <div class="section">
            <h2>🚨 Top Risk Incidents</h2>
            <button class="refresh-btn" onclick="loadData()">🔄 Refresh Data</button>
            <table>
                <thead><tr><th>Incident ID</th><th>Name</th><th>Severity</th><th>Risk Score</th><th>Alerts</th><th>Source IPs</th></tr></thead>
                <tbody id="incidents-table"></tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>⚠️ Recent Alerts</h2>
            <table>
                <thead><tr><th>Alert ID</th><th>Name</th><th>Severity</th><th>Source IP</th><th>Category</th></tr></thead>
                <tbody id="alerts-table"></tbody>
            </table>
        </div>
    </div>
    
    <script>
        async function loadData() {
            try {
                const [alertsRes, incidentsRes] = await Promise.all([
                    fetch('/api/alerts'),
                    fetch('/api/incidents')
                ]);
                const alerts = await alertsRes.json();
                const incidents = await incidentsRes.json();
                
                document.getElementById('total-alerts').textContent = alerts.length;
                
                const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
                incidents.forEach(i => { severityCounts[i.severity] = (severityCounts[i.severity] || 0) + 1; });
                
                document.getElementById('critical-incidents').textContent = severityCounts.CRITICAL;
                document.getElementById('high-incidents').textContent = severityCounts.HIGH;
                document.getElementById('medium-incidents').textContent = severityCounts.MEDIUM;
                document.getElementById('low-incidents').textContent = severityCounts.LOW;
                
                const sortedIncidents = incidents.sort((a, b) => b.risk_score - a.risk_score).slice(0, 10);
                document.getElementById('incidents-table').innerHTML = sortedIncidents.map(i => 
                    `<tr><td>${i.id}</td><td>${i.name}</td><td><span class="severity ${i.severity}">${i.severity}</span></td><td class="risk-score">${i.risk_score}</td><td>${i.alert_count}</td><td>${i.source_ips.slice(0,2).join(', ')}</td></tr>`
                ).join('');
                
                const recentAlerts = alerts.slice(0, 15);
                document.getElementById('alerts-table').innerHTML = recentAlerts.map(a => 
                    `<tr><td>${a.id.substring(0,20)}...</td><td>${a.name}</td><td><span class="severity ${a.severity}">${a.severity}</span></td><td>${a.source_ip || 'N/A'}</td><td>${a.category || 'N/A'}</td></tr>`
                ).join('');
            } catch (e) { console.error('Error loading data:', e); }
        }
        loadData();
        setInterval(loadData, 30000);
    </script>
</body>
</html>
'''

@app.route('/')
def dashboard():
    """Render the main dashboard."""
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get all alerts."""
    load_latest_data()
    return jsonify(alerts_store)

@app.route('/api/alerts/<alert_id>', methods=['GET'])
def get_alert(alert_id):
    """Get a specific alert by ID."""
    load_latest_data()
    for alert in alerts_store:
        if alert.get('id') == alert_id:
            return jsonify(alert)
    return jsonify({'error': 'Alert not found'}), 404

@app.route('/api/incidents', methods=['GET'])
def get_incidents():
    """Get all incidents."""
    load_latest_data()
    return jsonify(incidents_store)

@app.route('/api/incidents/<incident_id>', methods=['GET'])
def get_incident(incident_id):
    """Get a specific incident by ID."""
    load_latest_data()
    for incident in incidents_store:
        if incident.get('id') == incident_id:
            return jsonify(incident)
    return jsonify({'error': 'Incident not found'}), 404

@app.route('/api/incidents/<incident_id>', methods=['PUT'])
def update_incident(incident_id):
    """Update an incident status or assignment."""
    data = request.get_json()
    # In production, this would update a database
    return jsonify({'message': f'Incident {incident_id} updated', 'data': data})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get summary statistics."""
    load_latest_data()
    
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for inc in incidents_store:
        sev = inc.get('severity', 'LOW')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    return jsonify({
        'total_alerts': len(alerts_store),
        'total_incidents': len(incidents_store),
        'by_severity': severity_counts,
        'generated_at': datetime.now().isoformat()
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'service': 'IntelliDetect SIEM API'})

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️  IntelliDetect SIEM API Server Starting...")
    print("="*60)
    print("Dashboard URL: http://localhost:5000")
    print("API Endpoints:")
    print("  GET  /api/alerts      - List all alerts")
    print("  GET  /api/incidents   - List all incidents")
    print("  GET  /api/stats       - Get statistics")
    print("  GET  /api/health      - Health check")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=True)
