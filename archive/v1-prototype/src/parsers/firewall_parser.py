"""
Firewall Log Parser

Parses common firewall log formats (iptables, pfSense, Cisco ASA).
Useful for detecting network-based attacks, port scanning, and data exfiltration.

Example Format:
2024-01-15 10:30:45 ACCEPT TCP 192.168.1.100:54321 -> 10.0.0.50:443 IN=eth0 OUT= SRC=192.168.1.100 DST=10.0.0.50 LEN=60
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import random
import re

from src.parsers.base_parser import BaseParser, LogEvent


class FirewallParser(BaseParser):
    """Parser for firewall log files."""
    
    ACTIONS = ['ACCEPT', 'DROP', 'REJECT', 'DENY', 'ALLOW', 'BLOCK']
    PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP']
    
    # Common ports
    COMMON_PORTS = {
        22: 'SSH', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS',
        21: 'FTP', 25: 'SMTP', 110: 'POP3', 143: 'IMAP',
        3306: 'MySQL', 5432: 'PostgreSQL', 3389: 'RDP',
        445: 'SMB', 139: 'NetBIOS', 8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt', 4444: 'Metasploit', 5555: 'Android'
    }
    
    def __init__(self):
        super().__init__('firewall')
        self.log_pattern = re.compile(
            r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'  # Timestamp
            r'(\w+)\s+'                                      # Action
            r'(\w+)\s+'                                      # Protocol
            r'(\d+\.\d+\.\d+\.\d+):?(\d*)\s*'               # Source IP:Port
            r'->\s*'                                         # Arrow
            r'(\d+\.\d+\.\d+\.\d+):?(\d*)\s*'               # Dest IP:Port
            r'(?:IN=(\w+)\s*)?'                              # In interface
            r'(?:OUT=(\w*)\s*)?'                             # Out interface
            r'(?:SRC=(\d+\.\d+\.\d+\.\d+)\s*)?'             # Source IP (alt)
            r'(?:DST=(\d+\.\d+\.\d+\.\d+)\s*)?'             # Dest IP (alt)
            r'(?:LEN=(\d+)\s*)?'                             # Packet length
            r'(?:BYTES=(\d+)\s*)?'                           # Bytes (alt)
        )
    
    def parse_line(self, line: str) -> Optional[LogEvent]:
        """Parse a single firewall log line."""
        if not line or not line.strip():
            return None
        
        try:
            match = self.log_pattern.match(line.strip())
            if not match:
                # Try simpler format
                return self._parse_simple_format(line)
            
            groups = match.groups()
            timestamp = self.parse_timestamp(groups[0])
            
            src_port = int(groups[4]) if groups[4] else 0
            dest_port = int(groups[6]) if groups[6] else 0
            
            # Use alternative SRC/DST if primary not available
            src_ip = groups[3] if groups[3] else (groups[10] if groups[10] else '')
            dest_ip = groups[5] if groups[5] else (groups[11] if groups[11] else '')
            
            bytes_sent = int(groups[12]) if groups[12] else (int(groups[13]) if groups[13] else 0)
            
            event = LogEvent(
                timestamp=timestamp or datetime.now(),
                source_type='firewall',
                raw_log=line,
                action=groups[1],
                protocol=groups[2],
                src_ip=src_ip,
                src_port=src_port,
                dest_ip=dest_ip,
                dest_port=dest_port,
                in_interface=groups[7] or '',
                out_interface=groups[8] or '',
                bytes_out=bytes_sent,
                is_allowed=groups[1].upper() in ['ACCEPT', 'ALLOW'],
                is_denied=groups[1].upper() in ['DROP', 'REJECT', 'DENY', 'BLOCK'],
            )
            
            # Add service name based on port
            if dest_port in self.COMMON_PORTS:
                event.fields['service'] = self.COMMON_PORTS[dest_port]
            
            return event
            
        except Exception as e:
            return None
    
    def _parse_simple_format(self, line: str) -> Optional[LogEvent]:
        """Parse simpler firewall log formats."""
        try:
            # Extract IPs using regex
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            ports = re.findall(r'\bport\s+(\d+)\b|:(\d+)\b', line, re.IGNORECASE)
            
            if len(ips) < 2:
                return None
            
            # Extract timestamp
            ts_match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)
            timestamp = self.parse_timestamp(ts_match.group(1)) if ts_match else datetime.now()
            
            # Extract action
            action = 'UNKNOWN'
            for a in self.ACTIONS:
                if a in line.upper():
                    action = a
                    break
            
            # Extract protocol
            protocol = 'TCP'
            for p in self.PROTOCOLS:
                if p in line.upper():
                    protocol = p
                    break
            
            src_port = int(ports[0][0] or ports[0][1]) if ports else 0
            dest_port = int(ports[1][0] or ports[1][1]) if len(ports) > 1 else 0
            
            event = LogEvent(
                timestamp=timestamp,
                source_type='firewall',
                raw_log=line,
                action=action,
                protocol=protocol,
                src_ip=ips[0],
                src_port=src_port,
                dest_ip=ips[1],
                dest_port=dest_port,
                is_allowed=action.upper() in ['ACCEPT', 'ALLOW'],
                is_denied=action.upper() in ['DROP', 'REJECT', 'DENY', 'BLOCK'],
            )
            
            return event
            
        except:
            return None
    
    def generate_sample_logs(self, count: int = 100) -> List[str]:
        """Generate realistic firewall logs including suspicious activity."""
        logs = []
        base_time = datetime.now() - timedelta(hours=2)
        
        internal_ips = [f"192.168.1.{i}" for i in range(1, 255)]
        external_ips = [
            "8.8.8.8", "1.1.1.1", "208.67.222.222",  # DNS
            "151.101.1.140", "151.101.65.140",  # Reddit
            "185.220.101.45", "45.33.32.156",  # Suspicious
            "198.51.100.99", "203.0.113.50",  # More external
        ]
        
        # Generate normal traffic (70%)
        normal_count = int(count * 0.7)
        for i in range(normal_count):
            timestamp = base_time + timedelta(seconds=i * 5)
            src_ip = random.choice(internal_ips)
            dest_ip = random.choice(external_ips[:5])  # Normal external IPs
            src_port = random.randint(49152, 65535)
            dest_port = random.choice([80, 443, 53, 22, 25])
            action = 'ACCEPT'
            protocol = random.choice(['TCP', 'TCP', 'TCP', 'UDP'])
            bytes_out = random.randint(100, 50000)
            
            ts_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            log = f"{ts_str} {action} {protocol} {src_ip}:{src_port} -> {dest_ip}:{dest_port} IN=eth0 OUT= SRC={src_ip} DST={dest_ip} LEN={bytes_out}"
            logs.append(log)
        
        # Generate suspicious traffic (30%)
        suspicious_count = count - normal_count
        attacker_ip = "185.220.101.45"
        c2_server = "45.33.32.156"
        
        for i in range(suspicious_count):
            timestamp = base_time + timedelta(seconds=(normal_count + i) * 3)
            attack_type = random.choice([
                'port_scan', 'c2_comm', 'data_exfil', 'blocked_attack', 'lateral'
            ])
            
            if attack_type == 'port_scan':
                src_ip = attacker_ip
                dest_ip = random.choice(internal_ips[:10])
                src_port = random.randint(49152, 65535)
                dest_port = random.randint(1, 65535)
                action = random.choice(['DROP', 'DROP', 'ACCEPT'])
                protocol = 'TCP'
                bytes_out = 60
            
            elif attack_type == 'c2_comm':
                src_ip = random.choice(internal_ips[:5])
                dest_ip = c2_server
                src_port = random.randint(49152, 65535)
                dest_port = random.choice([443, 8443, 4444, 5555])
                action = 'ACCEPT'
                protocol = 'TCP'
                bytes_out = random.randint(1000, 10000)
            
            elif attack_type == 'data_exfil':
                src_ip = random.choice(internal_ips[:5])
                dest_ip = random.choice(external_ips[-2:])
                src_port = random.randint(49152, 65535)
                dest_port = random.choice([443, 53, 8080])
                action = 'ACCEPT'
                protocol = 'TCP'
                bytes_out = random.randint(10000000, 100000000)  # Large transfer
            
            elif attack_type == 'blocked_attack':
                src_ip = attacker_ip
                dest_ip = random.choice(internal_ips)
                src_port = random.randint(49152, 65535)
                dest_port = random.choice([22, 3389, 445, 3306])
                action = 'DROP'
                protocol = 'TCP'
                bytes_out = 60
            
            elif attack_type == 'lateral':
                src_ip = random.choice(internal_ips[:5])
                dest_ip = random.choice(internal_ips[5:15])
                src_port = random.randint(49152, 65535)
                dest_port = random.choice([445, 139, 3389, 22])
                action = 'ACCEPT'
                protocol = 'TCP'
                bytes_out = random.randint(500, 5000)
            
            ts_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            log = f"{ts_str} {action} {protocol} {src_ip}:{src_port} -> {dest_ip}:{dest_port} IN=eth0 OUT= SRC={src_ip} DST={dest_ip} LEN={bytes_out}"
            logs.append(log)
        
        return logs
