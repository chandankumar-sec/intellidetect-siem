"""Detection Rule Engine for threat detection."""
import yaml
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path

class Alert:
    """Represents a security alert."""
    def __init__(self, rule_id: str, name: str, description: str, severity: str, **kwargs):
        self.id = f"ALERT_{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity.upper()
        self.timestamp = datetime.now()
        self.events = kwargs.get('events', [])
        self.source_ip = kwargs.get('source_ip', '') or ''
        self.dest_ip = kwargs.get('dest_ip', '') or ''
        self.user = kwargs.get('user', '') or ''
        self.mitre_attack_id = kwargs.get('mitre_attack_id', '') or ''
        self.category = kwargs.get('category', '') or ''
        self.confidence = kwargs.get('confidence', 70)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'user': self.user,
            'mitre_attack_id': self.mitre_attack_id,
            'category': self.category,
            'confidence': self.confidence,
            'event_count': len(self.events)
        }


class DetectionEngine:
    """Rule-based detection engine."""
    
    def __init__(self, config_path: str = 'config/detection_rules.yaml'):
        self.rules = []
        self.settings = {}
        self.load_rules(config_path)
    
    def load_rules(self, config_path: str):
        """Load detection rules from YAML config."""
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        
        with open(path, 'r') as f:
            config = yaml.safe_load(f)
        
        self.rules = config.get('rules', [])
        self.settings = config.get('settings', {})
    
    def detect(self, events: List) -> List[Alert]:
        """Run detection against list of events."""
        alerts = []
        
        # Group events by type
        events_by_type = {}
        for event in events:
            source_type = getattr(event, 'source_type', 'unknown')
            if source_type not in events_by_type:
                events_by_type[source_type] = []
            events_by_type[source_type].append(event)
        
        # Run each rule
        for rule in self.rules:
            if not rule.get('enabled', True):
                continue
            
            rule_alerts = self._evaluate_rule(rule, events_by_type)
            alerts.extend(rule_alerts)
        
        return alerts
    
    def _evaluate_rule(self, rule: Dict, events_by_type: Dict) -> List[Alert]:
        """Evaluate a single rule against events."""
        alerts = []
        log_sources = rule.get('log_sources', [])
        
        # Get relevant events
        relevant_events = []
        for source in log_sources:
            relevant_events.extend(events_by_type.get(source, []))
        
        if not relevant_events:
            return alerts
        
        # Check threshold-based rules
        if 'threshold' in rule:
            threshold_alerts = self._check_threshold_rule(rule, relevant_events)
            alerts.extend(threshold_alerts)
        
        # Check condition-based rules
        if 'conditions' in rule:
            condition_alerts = self._check_condition_rule(rule, relevant_events)
            alerts.extend(condition_alerts)
        
        return alerts
    
    def _check_threshold_rule(self, rule: Dict, events: List) -> List[Alert]:
        """Check threshold-based detection rules."""
        alerts = []
        threshold = rule.get('threshold', 1)
        time_window = rule.get('time_window', 300)
        fields = rule.get('fields', {})
        
        # Group events by key field
        grouped = {}
        for event in events:
            key_field = fields.get('source_ip', 'src_ip')
            key = event.fields.get(key_field, 'unknown')
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(event)
        
        # Check thresholds
        now = datetime.now()
        for key, group_events in grouped.items():
            recent = [e for e in group_events if e.timestamp and (now - e.timestamp).total_seconds() < time_window]
            
            if len(recent) >= threshold:
                alert = Alert(
                    rule_id=rule.get('id'),
                    name=rule.get('name'),
                    description=rule.get('description'),
                    severity=rule.get('severity', 'MEDIUM'),
                    events=recent,
                    source_ip=key,
                    mitre_attack_id=rule.get('mitre_attack_id', ''),
                    category=rule.get('category', ''),
                    confidence=min(95, 60 + len(recent))
                )
                alerts.append(alert)
        
        return alerts
    
    def _check_condition_rule(self, rule: Dict, events: List) -> List[Alert]:
        """Check condition-based detection rules."""
        alerts = []
        conditions = rule.get('conditions', [])
        
        for event in events:
            if self._match_conditions(event, conditions):
                alert = Alert(
                    rule_id=rule.get('id'),
                    name=rule.get('name'),
                    description=rule.get('description'),
                    severity=rule.get('severity', 'MEDIUM'),
                    events=[event],
                    source_ip=event.fields.get('src_ip', '') or '',
                    dest_ip=event.fields.get('dest_ip', '') or '',
                    user=event.fields.get('user', '') or '',
                    mitre_attack_id=rule.get('mitre_attack_id', ''),
                    category=rule.get('category', ''),
                    confidence=80
                )
                alerts.append(alert)
        
        return alerts
    
    def _match_conditions(self, event, conditions: List[Dict]) -> bool:
        """Check if event matches all conditions."""
        for cond in conditions:
            field = cond.get('field', '')
            operator = cond.get('operator', 'equals')
            value = cond.get('value')
            values = cond.get('values', [])
            pattern = cond.get('pattern', '')
            
            event_value = event.fields.get(field, '')
            if event_value is None:
                event_value = ''
            event_value = str(event_value)
            
            if operator == 'equals':
                if value is not None and event_value != str(value):
                    return False
            elif operator == 'contains':
                search_values = values if values else ([value] if value else [])
                if not any(str(v) in event_value for v in search_values):
                    return False
            elif operator == 'in':
                if event_value not in values:
                    return False
            elif operator == 'regex':
                import re
                if pattern and not re.search(pattern, event_value, re.IGNORECASE):
                    return False
            elif operator == 'greater_than':
                try:
                    if float(event_value) <= float(value):
                        return False
                except (ValueError, TypeError):
                    return False
            elif operator == 'exists':
                if value and field not in event.fields:
                    return False
        
        return True
    
    def save_alerts(self, alerts: List[Alert], output_path: str):
        """Save alerts to JSON file."""
        import json
        from pathlib import Path
        
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'generated_at': datetime.now().isoformat(),
            'alert_count': len(alerts),
            'alerts': [a.to_dict() for a in alerts]
        }
        
        with open(output, 'w') as f:
            json.dump(data, f, indent=2)
