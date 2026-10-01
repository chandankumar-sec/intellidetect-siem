"""
IntelliDetect SIEM - Main Entry Point

This module serves as the primary entry point for the IntelliDetect SIEM system.
It orchestrates log parsing, threat detection, alert correlation, and enrichment.

Usage:
    python src/main.py --detect --config config/detection_rules.yaml
    python src/main.py --generate-sample-logs
    python src/main.py --dashboard
"""

import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.logger import setup_logger
from src.parsers.sysmon_parser import SysmonParser
from src.parsers.apache_parser import ApacheParser
from src.parsers.firewall_parser import FirewallParser
from src.parsers.auth_parser import AuthParser
from src.detectors.rule_engine import DetectionEngine
from src.correlators.alert_correlator import AlertCorrelator
from src.enrichers.threat_intel import ThreatIntelEnricher
from src.enrichers.geolocation import GeoEnricher
from src.utils.risk_scorer import RiskScorer


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='IntelliDetect SIEM - Intelligent Alert Correlation & Triage System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --generate-sample-logs
  %(prog)s --detect --config config/detection_rules.yaml
  %(prog)s --dashboard
  %(prog)s --analyze --input data/logs/sysmon.log
        """
    )
    
    parser.add_argument(
        '--generate-sample-logs',
        action='store_true',
        help='Generate sample log files for testing'
    )
    
    parser.add_argument(
        '--detect',
        action='store_true',
        help='Run threat detection engine'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default='config/detection_rules.yaml',
        help='Path to detection rules configuration file'
    )
    
    parser.add_argument(
        '--analyze',
        action='store_true',
        help='Analyze specific log file'
    )
    
    parser.add_argument(
        '--input',
        type=str,
        help='Input log file path'
    )
    
    parser.add_argument(
        '--log-type',
        type=str,
        choices=['sysmon', 'apache', 'firewall', 'auth'],
        help='Type of log file to analyze'
    )
    
    parser.add_argument(
        '--dashboard',
        action='store_true',
        help='Start the web dashboard'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='data/output',
        help='Output directory for alerts and incidents'
    )
    
    return parser.parse_args()


def generate_sample_logs(logger):
    """Generate realistic sample log files for testing."""
    logger.info("Generating sample log files...")
    
    # Create data/logs directory if it doesn't exist
    logs_dir = Path('data/logs')
    logs_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate Sysmon sample logs
    sysmon_parser = SysmonParser()
    sysmon_logs = sysmon_parser.generate_sample_logs(count=100)
    with open(logs_dir / 'sysmon.log', 'w') as f:
        for log in sysmon_logs:
            f.write(log + '\n')
    logger.info(f"Generated {len(sysmon_logs)} Sysmon log entries")
    
    # Generate Apache sample logs
    apache_parser = ApacheParser()
    apache_logs = apache_parser.generate_sample_logs(count=100)
    with open(logs_dir / 'apache_access.log', 'w') as f:
        for log in apache_logs:
            f.write(log + '\n')
    logger.info(f"Generated {len(apache_logs)} Apache log entries")
    
    # Generate Firewall sample logs
    firewall_parser = FirewallParser()
    firewall_logs = firewall_parser.generate_sample_logs(count=100)
    with open(logs_dir / 'firewall.log', 'w') as f:
        for log in firewall_logs:
            f.write(log + '\n')
    logger.info(f"Generated {len(firewall_logs)} Firewall log entries")
    
    # Generate Auth sample logs
    auth_parser = AuthParser()
    auth_logs = auth_parser.generate_sample_logs(count=100)
    with open(logs_dir / 'auth.log', 'w') as f:
        for log in auth_logs:
            f.write(log + '\n')
    logger.info(f"Generated {len(auth_logs)} Auth log entries")
    
    logger.info("Sample log generation complete!")
    return True


def run_detection(config_path, logger):
    """Run the threat detection engine."""
    logger.info(f"Starting threat detection with config: {config_path}")
    
    # Initialize detection engine
    try:
        detector = DetectionEngine(config_path=config_path)
    except Exception as e:
        logger.error(f"Failed to initialize detection engine: {e}")
        return False
    
    # Parse all available log files
    all_events = []
    logs_dir = Path('data/logs')
    
    if not logs_dir.exists():
        logger.warning("No logs directory found. Run --generate-sample-logs first.")
        return False
    
    # Parse Sysmon logs
    sysmon_log = logs_dir / 'sysmon.log'
    if sysmon_log.exists():
        parser = SysmonParser()
        events = parser.parse_file(sysmon_log)
        all_events.extend(events)
        logger.info(f"Parsed {len(events)} Sysmon events")
    
    # Parse Apache logs
    apache_log = logs_dir / 'apache_access.log'
    if apache_log.exists():
        parser = ApacheParser()
        events = parser.parse_file(apache_log)
        all_events.extend(events)
        logger.info(f"Parsed {len(events)} Apache events")
    
    # Parse Firewall logs
    firewall_log = logs_dir / 'firewall.log'
    if firewall_log.exists():
        parser = FirewallParser()
        events = parser.parse_file(firewall_log)
        all_events.extend(events)
        logger.info(f"Parsed {len(events)} Firewall events")
    
    # Parse Auth logs
    auth_log = logs_dir / 'auth.log'
    if auth_log.exists():
        parser = AuthParser()
        events = parser.parse_file(auth_log)
        all_events.extend(events)
        logger.info(f"Parsed {len(events)} Auth events")
    
    if not all_events:
        logger.warning("No events parsed from log files")
        return False
    
    logger.info(f"Total events to analyze: {len(all_events)}")
    
    # Run detection
    alerts = detector.detect(all_events)
    logger.info(f"Generated {len(alerts)} alerts")
    
    # Save alerts to output
    output_dir = Path('data/output')
    output_dir.mkdir(parents=True, exist_ok=True)
    
    alerts_file = output_dir / f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    detector.save_alerts(alerts, alerts_file)
    logger.info(f"Alerts saved to: {alerts_file}")
    
    # Correlate alerts into incidents
    logger.info("Correlating alerts into incidents...")
    correlator = AlertCorrelator(time_window=300)
    incidents = correlator.correlate(alerts)
    logger.info(f"Created {len(incidents)} incidents from {len(alerts)} alerts")
    
    # Enrich incidents
    logger.info("Enriching incidents with threat intelligence...")
    ti_enricher = ThreatIntelEnricher(mock_mode=True)  # Mock mode for demo
    geo_enricher = GeoEnricher(mock_mode=True)  # Mock mode for demo
    
    for incident in incidents:
        ti_enricher.enrich_incident(incident)
        geo_enricher.enrich_incident(incident)
    
    # Calculate risk scores
    logger.info("Calculating risk scores...")
    risk_scorer = RiskScorer()
    for incident in incidents:
        incident.risk_score = risk_scorer.calculate_score(incident)
    
    # Save incidents
    incidents_file = output_dir / f"incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    correlator.save_incidents(incidents, incidents_file)
    logger.info(f"Incidents saved to: {incidents_file}")
    
    # Print summary
    print("\n" + "="*80)
    print("DETECTION SUMMARY")
    print("="*80)
    print(f"Total Events Analyzed: {len(all_events)}")
    print(f"Alerts Generated:      {len(alerts)}")
    print(f"Incidents Created:     {len(incidents)}")
    print("\nIncidents by Severity:")
    
    severity_counts = {}
    for incident in incidents:
        sev = incident.severity
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    for severity, count in sorted(severity_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {severity}: {count}")
    
    print("\nTop Risk Incidents:")
    sorted_incidents = sorted(incidents, key=lambda x: x.risk_score, reverse=True)[:5]
    for i, incident in enumerate(sorted_incidents, 1):
        print(f"  {i}. [{incident.severity}] {incident.name} (Risk Score: {incident.risk_score})")
    
    print("="*80 + "\n")
    
    return True


def analyze_log_file(input_path, log_type, config_path, logger):
    """Analyze a specific log file."""
    logger.info(f"Analyzing {log_type} log file: {input_path}")
    
    input_file = Path(input_path)
    if not input_file.exists():
        logger.error(f"Input file not found: {input_file}")
        return False
    
    # Select appropriate parser
    parsers = {
        'sysmon': SysmonParser,
        'apache': ApacheParser,
        'firewall': FirewallParser,
        'auth': AuthParser
    }
    
    ParserClass = parsers.get(log_type)
    if not ParserClass:
        logger.error(f"Unknown log type: {log_type}")
        return False
    
    # Parse logs
    parser = ParserClass()
    events = parser.parse_file(input_file)
    logger.info(f"Parsed {len(events)} events")
    
    # Run detection
    detector = DetectionEngine(config_path=config_path)
    alerts = detector.detect(events)
    logger.info(f"Generated {len(alerts)} alerts")
    
    # Print results
    print(f"\nAnalysis Results for {input_path}:")
    print(f"Events: {len(events)}, Alerts: {len(alerts)}")
    
    for alert in alerts[:10]:  # Show first 10 alerts
        print(f"  [{alert.severity}] {alert.name}: {alert.description}")
    
    if len(alerts) > 10:
        print(f"  ... and {len(alerts) - 10} more alerts")
    
    return True


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logger(level=log_level)
    
    logger.info("IntelliDetect SIEM v1.0.0 starting...")
    
    try:
        if args.generate_sample_logs:
            success = generate_sample_logs(logger)
            sys.exit(0 if success else 1)
        
        elif args.detect:
            success = run_detection(args.config, logger)
            sys.exit(0 if success else 1)
        
        elif args.analyze:
            if not args.input or not args.log_type:
                logger.error("--analyze requires --input and --log-type")
                sys.exit(1)
            success = analyze_log_file(args.input, args.log_type, args.config, logger)
            sys.exit(0 if success else 1)
        
        elif args.dashboard:
            logger.info("Starting web dashboard...")
            logger.info("Note: Run 'python src/api/app.py' directly for dashboard")
            print("\nTo start the dashboard, run:")
            print("  python src/api/app.py\n")
            sys.exit(0)
        
        else:
            print("IntelliDetect SIEM v1.0.0")
            print("Use --help for usage information")
            print("\nQuick Start:")
            print("  1. Generate sample logs: python src/main.py --generate-sample-logs")
            print("  2. Run detection:        python src/main.py --detect")
            print("  3. Start dashboard:      python src/api/app.py")
            sys.exit(0)
    
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
