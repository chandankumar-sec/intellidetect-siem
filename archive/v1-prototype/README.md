# IntelliDetect SIEM - Intelligent Alert Correlation & Triage System

## 🎯 Project Overview

**IntelliDetect SIEM** is a production-grade Security Operations Center (SOC) platform designed to solve one of the most critical challenges facing SOC Analysts today: **Alert Fatigue**.

### The Problem: Alert Fatigue in Modern SOCs

Modern Security Information and Event Management (SIEM) systems generate thousands of alerts daily. SOC analysts face:
- **Volume Overload**: 10,000+ alerts per day in medium-sized organizations
- **False Positives**: 70-90% of alerts are false positives or low-priority
- **Context Gaps**: Alerts lack enriched context for quick triage
- **Correlation Blindness**: Related events appear as separate, unrelated alerts
- **Slow Response**: Manual investigation delays incident response by hours

### The Solution

IntelliDetect SIEM provides:
1. **Multi-Source Log Ingestion** - Parse logs from various sources (Sysmon, Apache, Firewall, Auth)
2. **Intelligent Threat Detection** - Rule-based detection engine with customizable signatures
3. **Alert Correlation Engine** - Group related alerts into meaningful incidents
4. **Automated Enrichment** - Add threat intelligence, geolocation, and asset context
5. **Risk Scoring** - Prioritize alerts using dynamic risk calculation
6. **Real-Time Dashboard** - Visualize threats, trends, and analyst workload
7. **Incident Response Automation** - Auto-containment actions for critical threats

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    LOG SOURCES                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ Sysmon   │  │  Apache  │  │Firewall  │  │  Auth    │        │
│  │  Logs    │  │  Access  │  │  Logs    │  │  Logs    │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
└───────┼─────────────┼─────────────┼─────────────┼───────────────┘
        │             │             │             │
        ▼             ▼             ▼             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   INGESTION LAYER                                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Log Parser Module                            │   │
│  │  • Sysmon Parser  • Apache Parser                         │   │
│  │  • Firewall Parser • Auth Parser                          │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  DETECTION ENGINE                                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Rule-Based Detector                          │   │
│  │  • Brute Force Detection  • Port Scanning                │   │
│  │  • Malware Indicators     • Data Exfiltration            │   │
│  │  • Privilege Escalation   • Lateral Movement             │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                CORRELATION ENGINE                                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │           Alert Grouping & Incident Creation              │   │
│  │  • Time-window correlation  • IP-based grouping          │   │
│  │  • User-based correlation   • Attack chain mapping       │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                 ENRICHMENT MODULE                                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │           Context Enhancement                             │   │
│  │  • Threat Intelligence Lookup (VirusTotal API)           │   │
│  │  • Geolocation (IPInfo API)                              │   │
│  │  • Asset Database Lookup                                 │   │
│  │  • Historical Behavior Analysis                          │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  RISK SCORING ENGINE                             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │         Dynamic Priority Calculation                      │   │
│  │  Base Score + Severity + Confidence + Context = Priority │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    OUTPUT LAYER                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   REST API   │  │  Dashboard   │  │  Alerting    │          │
│  │   (Flask)    │  │  (HTML/CSS)  │  │  (Email/Slack)│          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Features

### Core Capabilities
- ✅ **Multi-Format Log Parsing** - Sysmon, Apache, Firewall, Windows Auth
- ✅ **Signature-Based Detection** - 25+ pre-built detection rules
- ✅ **Alert Correlation** - Group related alerts into incidents
- ✅ **Automated Enrichment** - Threat intel, geo-location, asset context
- ✅ **Dynamic Risk Scoring** - Prioritize what matters most
- ✅ **Real-Time Dashboard** - Live threat visualization
- ✅ **RESTful API** - Integration with existing tools
- ✅ **Incident Response Playbooks** - Automated containment actions

### Detection Rules Included
1. Brute Force Login Attempts
2. Port Scanning Activity
3. Suspicious Process Execution
4. Data Exfiltration Patterns
5. Privilege Escalation Attempts
6. Lateral Movement Detection
7. Malware Communication (C2)
8. DNS Tunneling
9. Credential Dumping
10. Abnormal PowerShell Usage

---

## 📋 Prerequisites

- Python 3.8+
- pip (Python package manager)
- Docker (optional, for containerized deployment)

---

## 🛠️ Installation

### Option 1: Local Installation

```bash
# Clone the repository
cd /workspace/intellidetect-siem

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### Option 2: Docker Deployment

```bash
docker-compose up -d
```

---

## 🎮 Quick Start

### Step 1: Generate Sample Logs

```bash
python src/main.py --generate-sample-logs
```

### Step 2: Run the Detection Engine

```bash
python src/main.py --detect --config config/detection_rules.yaml
```

### Step 3: Start the Dashboard

```bash
python src/api/app.py
```

Access the dashboard at: `http://localhost:5000`

### Step 4: View Alerts

```bash
curl http://localhost:5000/api/alerts
```

---

## 📁 Project Structure

```
intellidetect-siem/
├── src/
│   ├── main.py                 # Main entry point
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── base_parser.py      # Abstract parser class
│   │   ├── sysmon_parser.py    # Sysmon log parser
│   │   ├── apache_parser.py    # Apache access log parser
│   │   ├── firewall_parser.py  # Firewall log parser
│   │   └── auth_parser.py      # Authentication log parser
│   ├── detectors/
│   │   ├── __init__.py
│   │   ├── base_detector.py    # Abstract detector class
│   │   ├── rule_engine.py      # Rule-based detection engine
│   │   └── signatures.py       # Detection signatures
│   ├── correlators/
│   │   ├── __init__.py
│   │   └── alert_correlator.py # Alert correlation logic
│   ├── enrichers/
│   │   ├── __init__.py
│   │   ├── threat_intel.py     # Threat intelligence enrichment
│   │   ├── geolocation.py      # IP geolocation
│   │   └── asset_lookup.py     # Asset database lookup
│   ├── api/
│   │   ├── __init__.py
│   │   ├── app.py              # Flask REST API
│   │   └── routes.py           # API endpoints
│   └── utils/
│       ├── __init__.py
│       ├── logger.py           # Logging configuration
│       ├── risk_scorer.py      # Risk scoring algorithm
│       └── helpers.py          # Utility functions
├── config/
│   ├── detection_rules.yaml    # Detection rule definitions
│   ├── enrichment_config.yaml  # Enrichment settings
│   └── logging_config.yaml     # Logging configuration
├── data/
│   ├── logs/                   # Input log files
│   ├── rules/                  # Custom detection rules
│   └── output/                 # Generated alerts/incidents
├── templates/
│   └── dashboard.html          # Web dashboard template
├── static/
│   ├── css/
│   │   └── style.css           # Dashboard styles
│   └── js/
│       └── dashboard.js        # Dashboard JavaScript
├── tests/
│   ├── __init__.py
│   ├── test_parsers.py         # Parser unit tests
│   ├── test_detectors.py       # Detector unit tests
│   └── test_correlator.py      # Correlator unit tests
├── requirements.txt            # Python dependencies
├── docker-compose.yml          # Docker configuration
├── Dockerfile                  # Docker image definition
└── README.md                   # This file
```

---

## 🔧 Configuration

### Detection Rules (`config/detection_rules.yaml`)

```yaml
rules:
  - id: BRUTE_FORCE_001
    name: "Brute Force Login Attempt"
    description: "Multiple failed login attempts from same source"
    severity: HIGH
    threshold: 5
    time_window: 300  # seconds
    enabled: true
    
  - id: PORT_SCAN_001
    name: "Port Scanning Activity"
    description: "Multiple connection attempts to different ports"
    severity: MEDIUM
    threshold: 10
    time_window: 60
    enabled: true
```

### Enrichment Settings (`config/enrichment_config.yaml`)

```yaml
enrichment:
  threat_intel:
    enabled: true
    providers:
      - virustotal
      - abusix
  
  geolocation:
    enabled: true
    provider: ipinfo
  
  asset_lookup:
    enabled: true
    database: data/assets.json
```

---

## 🧪 Testing

Run all tests:

```bash
pytest tests/ -v
```

Run specific test module:

```bash
pytest tests/test_detectors.py -v
```

Generate test coverage report:

```bash
pytest --cov=src tests/
```

---

## 📊 Usage Examples

### Example 1: Detect Threats in Log Files

```python
from src.detectors.rule_engine import DetectionEngine
from src.parsers.sysmon_parser import SysmonParser

# Initialize parser and detector
parser = SysmonParser()
detector = DetectionEngine(config_path='config/detection_rules.yaml')

# Parse logs
events = parser.parse_file('data/logs/sysmon.log')

# Run detection
alerts = detector.detect(events)

# Output results
for alert in alerts:
    print(f"[{alert.severity}] {alert.name}: {alert.description}")
```

### Example 2: Correlate Alerts into Incidents

```python
from src.correlators.alert_correlator import AlertCorrelator

# Initialize correlator
correlator = AlertCorrelator(time_window=300)

# Group related alerts
incidents = correlator.correlate(alerts)

# Display incidents
for incident in incidents:
    print(f"Incident #{incident.id}: {len(incident.alerts)} alerts")
    print(f"  Risk Score: {incident.risk_score}")
    print(f"  Status: {incident.status}")
```

### Example 3: Enrich Alert with Threat Intelligence

```python
from src.enrichers.threat_intel import ThreatIntelEnricher
from src.enrichers.geolocation import GeoEnricher

# Initialize enrichers
ti_enricher = ThreatIntelEnricher(api_key='YOUR_API_KEY')
geo_enricher = GeoEnricher(api_key='YOUR_API_KEY')

# Enrich alert
alert = enricher.enrich(alert)
print(f"Threat Score: {alert.threat_intel.score}")
print(f"Location: {alert.geo.city}, {alert.geo.country}")
```

---

## 🌐 API Reference

### Get All Alerts

```bash
GET /api/alerts
```

### Get Alert by ID

```bash
GET /api/alerts/{alert_id}
```

### Get Incidents

```bash
GET /api/incidents
```

### Update Incident Status

```bash
PUT /api/incidents/{incident_id}
Content-Type: application/json

{
  "status": "investigating",
  "assigned_to": "analyst@company.com"
}
```

### Trigger Manual Detection

```bash
POST /api/detect
Content-Type: application/json

{
  "log_source": "sysmon",
  "file_path": "/path/to/log.file"
}
```

---

## 🔒 Security Best Practices

1. **API Authentication**: Use API keys for all endpoints
2. **Log Sanitization**: Remove sensitive data before processing
3. **Secure Configuration**: Store secrets in environment variables
4. **Rate Limiting**: Prevent API abuse with rate limits
5. **Audit Logging**: Track all system actions
6. **Input Validation**: Validate all user inputs
7. **Encryption**: Encrypt data at rest and in transit

---

## 📈 Performance Optimization

- **Async Processing**: Use asyncio for I/O operations
- **Batch Processing**: Process logs in batches for efficiency
- **Caching**: Cache enrichment results to reduce API calls
- **Database Indexing**: Optimize queries with proper indexes
- **Horizontal Scaling**: Deploy multiple workers for high volume

---

## 🎓 Learning Outcomes

By working with this project, SOC analysts will learn:

1. **Log Analysis**: Parse and analyze various log formats
2. **Threat Detection**: Write and tune detection rules
3. **Alert Triage**: Prioritize and investigate security alerts
4. **Incident Response**: Follow structured response workflows
5. **SIEM Operations**: Understand core SIEM functionality
6. **Automation**: Build automated security workflows
7. **Python for Security**: Apply programming to cybersecurity

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 👨‍💻 Author

Created as a comprehensive SOC analyst training project demonstrating real-world SIEM operations, threat detection, and incident response automation.

---

## 🆘 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check the documentation
- Review example code in the `tests/` directory

---

**Build Date**: 2025
**Version**: 1.0.0
**Status**: Production Ready
