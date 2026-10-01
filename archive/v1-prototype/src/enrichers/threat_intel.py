"""Threat Intelligence Enrichment Module."""
from typing import Dict, Any, Optional

class ThreatIntelInfo:
    """Container for threat intel data."""
    def __init__(self):
        self.is_malicious = False
        self.is_suspicious = False
        self.score = 0
        self.category = ''
        self.tags = []
        self.provider = 'IntelliDetect-Mock'
        self.max_score = 0
        self.indicators = []


class ThreatIntelEnricher:
    """Enrich alerts with threat intelligence data."""
    
    # Mock threat intelligence database for demo
    KNOWN_MALICIOUS_IPS = {
        '185.220.101.45': {'score': 95, 'category': 'Tor Exit Node', 'tags': ['anonymizer', 'c2']},
        '45.33.32.156': {'score': 90, 'category': 'Known Scanner', 'tags': ['scanning', 'recon']},
        '198.51.100.99': {'score': 85, 'category': 'Botnet C2', 'tags': ['botnet', 'malware']},
        '203.0.113.50': {'score': 80, 'category': 'Spam Source', 'tags': ['spam', 'phishing']},
    }
    
    def __init__(self, api_key: str = None, mock_mode: bool = True):
        self.api_key = api_key
        self.mock_mode = mock_mode
    
    def enrich_alert(self, alert) -> Any:
        """Enrich an alert with threat intel."""
        if not hasattr(alert, 'threat_intel') or alert.threat_intel is None:
            alert.threat_intel = ThreatIntelInfo()
        
        ti = alert.threat_intel
        
        # Check source IP
        src_ip = getattr(alert, 'source_ip', '') or ''
        if src_ip in self.KNOWN_MALICIOUS_IPS:
            info = self.KNOWN_MALICIOUS_IPS[src_ip]
            ti.is_malicious = True
            ti.score = info['score']
            ti.category = info['category']
            ti.tags = info.get('tags', [])
        
        return alert
    
    def enrich_incident(self, incident) -> Any:
        """Enrich an incident with threat intel."""
        if not hasattr(incident, 'threat_intel') or incident.threat_intel is None:
            incident.threat_intel = ThreatIntelInfo()
        
        ti = incident.threat_intel
        
        # Check all source IPs in incident
        for src_ip in incident.source_ips:
            if src_ip in self.KNOWN_MALICIOUS_IPS:
                info = self.KNOWN_MALICIOUS_IPS[src_ip]
                ti.is_malicious = True
                if info['score'] > ti.max_score:
                    ti.max_score = info['score']
                ti.indicators.append({
                    'type': 'ip',
                    'value': src_ip,
                    'score': info['score'],
                    'category': info['category']
                })
        
        return incident
    
    def lookup_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Look up threat intel for an IP address."""
        if ip in self.KNOWN_MALICIOUS_IPS:
            return {
                'ip': ip,
                **self.KNOWN_MALICIOUS_IPS[ip],
                'found': True
            }
        return {'ip': ip, 'found': False}
