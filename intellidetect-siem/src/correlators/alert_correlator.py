"""Alert Correlation Engine for grouping related alerts into incidents."""
from typing import List, Dict, Any
from datetime import datetime, timedelta
import json
from pathlib import Path

class Incident:
    """Represents a security incident (grouped alerts)."""
    def __init__(self, incident_id: str, name: str, severity: str):
        self.id = incident_id
        self.name = name
        self.severity = severity.upper()
        self.status = 'new'
        self.alerts = []
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
        self.assigned_to = None
        self.risk_score = 0
        self.source_ips = set()
        self.dest_ips = set()
        self.users = set()
        self.mitre_attack_ids = []
        self.threat_intel = None
        self.geo_info = None
    
    def add_alert(self, alert):
        """Add an alert to this incident."""
        self.alerts.append(alert)
        self.updated_at = datetime.now()
        
        if hasattr(alert, 'source_ip') and alert.source_ip:
            self.source_ips.add(alert.source_ip)
        if hasattr(alert, 'dest_ip') and alert.dest_ip:
            self.dest_ips.add(alert.dest_ip)
        if hasattr(alert, 'user') and alert.user:
            self.users.add(alert.user)
        if hasattr(alert, 'mitre_attack_id') and alert.mitre_attack_id:
            if alert.mitre_attack_id not in self.mitre_attack_ids:
                self.mitre_attack_ids.append(alert.mitre_attack_id)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'severity': self.severity,
            'status': self.status,
            'risk_score': self.risk_score,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'assigned_to': self.assigned_to,
            'alert_count': len(self.alerts),
            'source_ips': list(self.source_ips),
            'dest_ips': list(self.dest_ips),
            'users': list(self.users),
            'mitre_attack_ids': self.mitre_attack_ids,
            'alerts': [a.to_dict() if hasattr(a, 'to_dict') else str(a) for a in self.alerts[:5]]
        }


class AlertCorrelator:
    """Correlate related alerts into incidents."""
    
    def __init__(self, time_window: int = 300):
        self.time_window = time_window  # seconds
        self.incidents = []
    
    def correlate(self, alerts: List) -> List[Incident]:
        """Group alerts into incidents based on correlation rules."""
        if not alerts:
            return []
        
        # Sort alerts by timestamp
        sorted_alerts = sorted(alerts, key=lambda x: getattr(x, 'timestamp', datetime.min))
        
        # Group by source IP
        by_source_ip = {}
        for alert in sorted_alerts:
            src_ip = getattr(alert, 'source_ip', '')
            if src_ip:
                if src_ip not in by_source_ip:
                    by_source_ip[src_ip] = []
                by_source_ip[src_ip].append(alert)
        
        # Create incidents from grouped alerts
        incidents = []
        incident_counter = 1
        
        for src_ip, ip_alerts in by_source_ip.items():
            if len(ip_alerts) >= 1:
                # Determine incident severity (highest among alerts)
                severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
                max_severity = max(ip_alerts, key=lambda x: severity_order.get(getattr(x, 'severity', 'LOW'), 0)).severity
                
                incident = Incident(
                    incident_id=f"INC_{datetime.now().strftime('%Y%m%d%H%M%S')}_{incident_counter:03d}",
                    name=f"Suspicious Activity from {src_ip}",
                    severity=max_severity
                )
                
                for alert in ip_alerts:
                    incident.add_alert(alert)
                
                incidents.append(incident)
                incident_counter += 1
        
        # Also group by user if multiple IPs target same user
        by_user = {}
        for alert in sorted_alerts:
            user = getattr(alert, 'user', '')
            if user and user != 'unknown':
                if user not in by_user:
                    by_user[user] = []
                by_user[user].append(alert)
        
        for user, user_alerts in by_user.items():
            if len(user_alerts) >= 3:  # At least 3 alerts for user-based correlation
                severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
                max_severity = max(user_alerts, key=lambda x: severity_order.get(getattr(x, 'severity', 'LOW'), 0)).severity
                
                incident = Incident(
                    incident_id=f"INC_{datetime.now().strftime('%Y%m%d%H%M%S')}_{incident_counter:03d}",
                    name=f"Targeted Attack Against User: {user}",
                    severity=max_severity
                )
                
                for alert in user_alerts:
                    if alert not in [a for inc in incidents for a in inc.alerts]:
                        incident.add_alert(alert)
                
                if incident.alerts:
                    incidents.append(incident)
                    incident_counter += 1
        
        self.incidents = incidents
        return incidents
    
    def save_incidents(self, incidents: List[Incident], output_path: str):
        """Save incidents to JSON file."""
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'generated_at': datetime.now().isoformat(),
            'incident_count': len(incidents),
            'incidents': [i.to_dict() for i in incidents]
        }
        
        with open(output, 'w') as f:
            json.dump(data, f, indent=2)
