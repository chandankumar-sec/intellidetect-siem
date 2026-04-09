"""Risk Scoring Module for calculating incident priority."""
from typing import Dict, Any

class RiskScorer:
    """Calculate risk scores for alerts and incidents."""
    
    SEVERITY_WEIGHTS = {
        'CRITICAL': 40,
        'HIGH': 30,
        'MEDIUM': 20,
        'LOW': 10,
        'INFO': 5
    }
    
    def __init__(self):
        pass
    
    def calculate_score(self, incident) -> int:
        """Calculate risk score for an incident (0-100)."""
        score = 0
        
        # Base severity score
        severity = getattr(incident, 'severity', 'MEDIUM')
        score += self.SEVERITY_WEIGHTS.get(severity.upper(), 20)
        
        # Alert count bonus
        alert_count = len(getattr(incident, 'alerts', []))
        score += min(alert_count * 2, 20)
        
        # Enrichment bonuses
        if hasattr(incident, 'threat_intel'):
            ti = incident.threat_intel
            if getattr(ti, 'is_malicious', False):
                score += 20
            elif getattr(ti, 'is_suspicious', False):
                score += 10
        
        # MITRE ATT&CK coverage
        mitre_tags = getattr(incident, 'mitre_attack_ids', [])
        score += min(len(mitre_tags) * 3, 15)
        
        return min(score, 100)
