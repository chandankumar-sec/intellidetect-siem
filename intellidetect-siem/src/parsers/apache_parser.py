"""
Apache Access Log Parser

Parses Apache HTTP Server access log format (Combined Log Format).
Useful for detecting web application attacks, scanning activity, and suspicious requests.

Apache Combined Log Format Example:
192.168.1.100 - john [15/Jan/2024:10:30:45 +0000] "GET /admin/login.php HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import random
import re

from src.parsers.base_parser import BaseParser, LogEvent


class ApacheParser(BaseParser):
    """Parser for Apache HTTP Server access logs."""
    
    # Common attack patterns for sample generation
    ATTACK_PATTERNS = {
        'sql_injection': [
            "/search?q=' OR '1'='1",
            "/login?user=admin'--&pass=x",
            "/products?id=1 UNION SELECT * FROM users",
            "/api/data?id=1; DROP TABLE users--",
        ],
        'xss': [
            "/search?q=<script>alert('XSS')</script>",
            "/comment?text=<img onerror=alert(1) src=x>",
            "/profile?name=<svg onload=alert('XSS')>",
        ],
        'path_traversal': [
            "/files?path=../../../etc/passwd",
            "/download?file=....//....//etc/shadow",
            "/static/%2e%2e%2f%2e%2e%2fetc/passwd",
        ],
        'web_shell': [
            "/uploads/shell.php?cmd=id",
            "/images/backdoor.asp?c=whoami",
            "/temp/cmd.jsp?exec=cat+/etc/passwd",
        ],
        'scanner': [
            "/.git/config",
            "/.env",
            "/wp-admin/",
            "/phpmyadmin/",
            "/.aws/credentials",
            "/backup.sql",
        ]
    }
    
    # Normal paths for sample generation
    NORMAL_PATHS = [
        "/",
        "/index.html",
        "/about",
        "/contact",
        "/products",
        "/services",
        "/api/v1/users",
        "/api/v1/products",
        "/static/css/style.css",
        "/static/js/app.js",
        "/images/logo.png",
        "/login",
        "/dashboard",
        "/profile",
        "/settings",
    ]
    
    # User agents
    NORMAL_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    ]
    
    SUSPICIOUS_USER_AGENTS = [
        "sqlmap/1.7",
        "nikto/2.1.6",
        "Nmap Scripting Engine",
        "curl/7.68.0",
        "python-requests/2.28.0",
        "Go-http-client/1.1",
    ]
    
    def __init__(self):
        super().__init__('apache')
        # Regex pattern for Combined Log Format
        self.log_pattern = re.compile(
            r'^(\S+)\s+'           # IP address
            r'(\S+)\s+'            # Identity
            r'(\S+)\s+'            # User
            r'\[([^\]]+)\]\s+'     # Timestamp
            r'"(\S+)\s+'           # Method
            r'([^"]*)\s+'          # Path
            r'([^"]+)"\s+'         # Protocol
            r'(\d+)\s+'            # Status code
            r'(\d+|-)\s*'          # Size
            r'(?:"([^"]*)"\s*)?'   # Referrer (optional)
            r'(?:"([^"]*)")?'      # User-Agent (optional)
        )
    
    def parse_line(self, line: str) -> Optional[LogEvent]:
        """Parse a single Apache access log line."""
        if not line or not line.strip():
            return None
        
        try:
            match = self.log_pattern.match(line.strip())
            if not match:
                return None
            
            groups = match.groups()
            
            # Parse timestamp
            timestamp_str = groups[3]
            timestamp = self.parse_timestamp(timestamp_str)
            
            # Extract path and query string
            full_path = groups[5]
            path_parts = full_path.split('?')
            path = path_parts[0]
            query_string = path_parts[1] if len(path_parts) > 1 else ''
            
            # Create LogEvent
            event = LogEvent(
                timestamp=timestamp or datetime.now(),
                source_type='apache',
                raw_log=line,
                src_ip=groups[0],
                identity=groups[1] if groups[1] != '-' else None,
                user=groups[2] if groups[2] != '-' else None,
                request_method=groups[4],
                request_uri=full_path,
                request_path=path,
                query_string=query_string,
                protocol=groups[6],
                status_code=int(groups[7]),
                response_size=int(groups[8]) if groups[8] != '-' else 0,
                referrer=groups[9] if groups[9] else None,
                user_agent=groups[10] if groups[10] else None,
            )
            
            # Add detection hints
            event.fields['is_error'] = int(groups[7]) >= 400
            event.fields['is_client_error'] = 400 <= int(groups[7]) < 500
            event.fields['is_server_error'] = int(groups[7]) >= 500
            
            return event
            
        except Exception as e:
            return None
    
    def generate_sample_logs(self, count: int = 100) -> List[str]:
        """Generate realistic Apache access logs including attack attempts."""
        logs = []
        base_time = datetime.now() - timedelta(hours=2)
        
        ips = [
            "192.168.1.100", "192.168.1.101", "10.0.0.50",
            "172.16.0.25", "203.0.113.45",  # External IP
            "198.51.100.78",  # Another external
        ]
        
        users = ["-", "-", "-", "john", "alice", "admin"]
        methods = ["GET", "GET", "GET", "POST", "PUT", "DELETE"]
        
        # Generate normal traffic (75%)
        normal_count = int(count * 0.75)
        for i in range(normal_count):
            timestamp = base_time + timedelta(seconds=i * 5)
            ip = random.choice(ips)
            user = random.choice(users)
            method = random.choice(["GET", "GET", "GET", "POST"])
            path = random.choice(self.NORMAL_PATHS)
            status = random.choice([200, 200, 200, 200, 301, 304, 404])
            size = random.randint(500, 50000)
            referrer = random.choice(["-", "https://google.com/", "https://example.com/"])
            ua = random.choice(self.NORMAL_USER_AGENTS)
            
            ts_str = timestamp.strftime('%d/%b/%Y:%H:%M:%S +0000')
            log = f'{ip} - {user} [{ts_str}] "{method} {path} HTTP/1.1" {status} {size} "{referrer}" "{ua}"'
            logs.append(log)
        
        # Generate attack traffic (25%)
        attack_count = count - normal_count
        attacker_ips = ["185.220.101.45", "45.33.32.156", "198.51.100.99"]
        
        for i in range(attack_count):
            timestamp = base_time + timedelta(seconds=(normal_count + i) * 3)
            ip = random.choice(attacker_ips)
            attack_type = random.choice(list(self.ATTACK_PATTERNS.keys()))
            payload = random.choice(self.ATTACK_PATTERNS[attack_type])
            method = "POST" if attack_type == 'web_shell' else "GET"
            status = random.choice([200, 403, 404, 500])
            size = random.randint(100, 5000)
            ua = random.choice(self.SUSPICIOUS_USER_AGENTS)
            
            ts_str = timestamp.strftime('%d/%b/%Y:%H:%M:%S +0000')
            log = f'{ip} - - [{ts_str}] "{method} {payload} HTTP/1.1" {status} {size} "-" "{ua}"'
            logs.append(log)
        
        return logs
