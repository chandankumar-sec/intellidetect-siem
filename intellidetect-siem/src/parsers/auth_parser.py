"""
Authentication Log Parser

Parses authentication logs from Linux (auth.log, secure) and Windows (Security Event Log).
Useful for detecting brute force attacks, privilege escalation, and unauthorized access.

Linux auth.log Example:
Jan 15 10:30:45 server01 sshd[12345]: Failed password for john from 192.168.1.100 port 54321 ssh2

Windows Security Event Example:
2024-01-15 10:30:45;EventID 4625;An account failed to log on.;Account Name: john;Source IP: 192.168.1.100;Logon Type: 3
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import random
import re

from src.parsers.base_parser import BaseParser, LogEvent


class AuthParser(BaseParser):
    """Parser for authentication log files."""
    
    # Event types
    EVENT_TYPES = {
        'failed_login': 'Failed login attempt',
        'successful_login': 'Successful login',
        'logout': 'User logout',
        'sudo': 'Sudo command execution',
        'su': 'Su command execution',
        'password_change': 'Password change',
        'account_lockout': 'Account lockout',
        'privilege_escalation': 'Privilege escalation',
    }
    
    # Common usernames
    USERNAMES = [
        'root', 'admin', 'administrator', 'john', 'alice', 'bob',
        'webadmin', 'dbadmin', 'backup', 'service_account',
        'test', 'guest', 'oracle', 'postgres', 'mysql'
    ]
    
    def __init__(self):
        super().__init__('auth')
        
        # Linux SSH failed login pattern
        self.ssh_failed_pattern = re.compile(
            r'^(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'  # Timestamp
            r'(\S+)\s+'                              # Hostname
            r'sshd\[(\d+)\]:\s+'                     # Process
            r'Failed\s+password\s+for\s+'            # Message
            r'(?:invalid\s+user\s+)?'                # Optional "invalid user"
            r'(\S+)\s+'                              # Username
            r'from\s+(\d+\.\d+\.\d+\.\d+)\s+'       # Source IP
            r'port\s+(\d+)'                          # Port
        )
        
        # Linux SSH successful login pattern
        self.ssh_success_pattern = re.compile(
            r'^(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
            r'(\S+)\s+'
            r'sshd\[(\d+)\]:\s+'
            r'Accepted\s+\w+\s+for\s+'
            r'(\S+)\s+from\s+'
            r'(\d+\.\d+\.\d+\.\d+)\s+'
            r'port\s+(\d+)'
        )
        
        # Windows Security Event pattern
        self.windows_event_pattern = re.compile(
            r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2});'  # Timestamp
            r'EventID\s+(\d+);'                            # Event ID
            r'([^;]+);'                                    # Description
            r'(?:Account Name:\s*(\S+);)?'                 # Account Name (optional)
            r'(?:Source Network Address:\s*(\d+\.\d+\.\d+\.\d+);)?'  # Source IP
            r'(?:Logon Type:\s*(\d+))?'                    # Logon Type
        )
    
    def parse_line(self, line: str) -> Optional[LogEvent]:
        """Parse a single authentication log line."""
        if not line or not line.strip():
            return None
        
        # Try Windows format first
        event = self._parse_windows_format(line)
        if event:
            return event
        
        # Try Linux SSH failed login
        event = self._parse_linux_ssh_failed(line)
        if event:
            return event
        
        # Try Linux SSH successful login
        event = self._parse_linux_ssh_success(line)
        if event:
            return event
        
        # Try generic auth pattern
        event = self._parse_generic_auth(line)
        
        return event
    
    def _parse_windows_format(self, line: str) -> Optional[LogEvent]:
        """Parse Windows Security Event format."""
        match = self.windows_event_pattern.match(line.strip())
        if not match:
            return None
        
        groups = match.groups()
        timestamp = self.parse_timestamp(groups[0])
        event_id = groups[1]
        description = groups[2]
        username = groups[3] if groups[3] else 'unknown'
        src_ip = groups[4] if groups[4] else ''
        logon_type = groups[5] if groups[5] else '0'
        
        # Determine event type based on Event ID
        event_type = 'unknown'
        is_failed = False
        
        if event_id == '4625':  # Failed login
            event_type = 'failed_login'
            is_failed = True
        elif event_id == '4624':  # Successful login
            event_type = 'successful_login'
        elif event_id == '4634':  # Logout
            event_type = 'logout'
        elif event_id == '4672':  # Special privileges
            event_type = 'privilege_escalation'
        elif event_id == '4720':  # Account created
            event_type = 'account_created'
        elif event_id == '4740':  # Account locked
            event_type = 'account_lockout'
        
        event = LogEvent(
            timestamp=timestamp or datetime.now(),
            source_type='auth',
            raw_log=line,
            event_id=event_id,
            event_type=event_type,
            user=username,
            src_ip=src_ip,
            hostname=groups[0] if groups[0] else '',
            logon_type=int(logon_type) if logon_type.isdigit() else 0,
            is_failed=is_failed,
            os_type='windows',
        )
        
        return event
    
    def _parse_linux_ssh_failed(self, line: str) -> Optional[LogEvent]:
        """Parse Linux SSH failed login format."""
        match = self.ssh_failed_pattern.match(line.strip())
        if not match:
            return None
        
        groups = match.groups()
        timestamp = self.parse_timestamp(groups[0], formats=['%b %d %H:%M:%S'])
        
        # Add current year if not present
        if timestamp and timestamp.year == 1900:
            timestamp = timestamp.replace(year=datetime.now().year)
        
        event = LogEvent(
            timestamp=timestamp or datetime.now(),
            source_type='auth',
            raw_log=line,
            event_id='SSH_FAILED',
            event_type='failed_login',
            user=groups[3],
            src_ip=groups[4],
            src_port=int(groups[5]) if groups[5].isdigit() else 0,
            hostname=groups[1],
            process='sshd',
            process_id=int(groups[2]) if groups[2].isdigit() else 0,
            is_failed=True,
            os_type='linux',
        )
        
        return event
    
    def _parse_linux_ssh_success(self, line: str) -> Optional[LogEvent]:
        """Parse Linux SSH successful login format."""
        match = self.ssh_success_pattern.match(line.strip())
        if not match:
            return None
        
        groups = match.groups()
        timestamp = self.parse_timestamp(groups[0], formats=['%b %d %H:%M:%S'])
        
        if timestamp and timestamp.year == 1900:
            timestamp = timestamp.replace(year=datetime.now().year)
        
        event = LogEvent(
            timestamp=timestamp or datetime.now(),
            source_type='auth',
            raw_log=line,
            event_id='SSH_SUCCESS',
            event_type='successful_login',
            user=groups[3],
            src_ip=groups[4],
            src_port=int(groups[5]) if groups[5].isdigit() else 0,
            hostname=groups[1],
            process='sshd',
            process_id=int(groups[2]) if groups[2].isdigit() else 0,
            is_failed=False,
            os_type='linux',
        )
        
        return event
    
    def _parse_generic_auth(self, line: str) -> Optional[LogEvent]:
        """Parse generic authentication log format."""
        try:
            # Extract timestamp
            ts_match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)
            if ts_match:
                timestamp = self.parse_timestamp(ts_match.group(1))
            else:
                ts_match = re.search(r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
                timestamp = self.parse_timestamp(ts_match.group(1), formats=['%b %d %H:%M:%S']) if ts_match else datetime.now()
            
            # Extract IP
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            src_ip = ip_match.group(0) if ip_match else ''
            
            # Extract username
            user_match = re.search(r'(?:user|for|User)\s+[=:]\s*(\S+)', line, re.IGNORECASE)
            user = user_match.group(1) if user_match else 'unknown'
            
            # Determine event type
            event_type = 'unknown'
            is_failed = False
            
            line_lower = line.lower()
            if 'failed' in line_lower or 'failure' in line_lower or 'invalid' in line_lower:
                event_type = 'failed_login'
                is_failed = True
            elif 'accepted' in line_lower or 'success' in line_lower or 'opened' in line_lower:
                event_type = 'successful_login'
            elif 'logout' in line_lower or 'closed' in line_lower or 'disconnected' in line_lower:
                event_type = 'logout'
            elif 'sudo' in line_lower:
                event_type = 'sudo'
            
            event = LogEvent(
                timestamp=timestamp,
                source_type='auth',
                raw_log=line,
                event_type=event_type,
                user=user,
                src_ip=src_ip,
                is_failed=is_failed,
            )
            
            return event
            
        except:
            return None
    
    def generate_sample_logs(self, count: int = 100) -> List[str]:
        """Generate realistic authentication logs including attack attempts."""
        logs = []
        base_time = datetime.now() - timedelta(hours=2)
        
        hostnames = ['server01', 'server02', 'dc01', 'web01']
        users = ['john', 'alice', 'bob', 'admin', 'root', 'webadmin']
        ips = [f"192.168.1.{i}" for i in range(1, 50)]
        
        # Generate normal activity (60%)
        normal_count = int(count * 0.6)
        for i in range(normal_count):
            timestamp = base_time + timedelta(seconds=i * 10)
            
            log_type = random.choice(['success', 'success', 'success', 'logout', 'sudo'])
            user = random.choice(users)
            ip = random.choice(ips)
            hostname = random.choice(hostnames)
            pid = random.randint(1000, 65000)
            
            if log_type == 'success':
                port = random.randint(49152, 65535)
                ts_str = timestamp.strftime('%b %d %H:%M:%S')
                log = f"{ts_str} {hostname} sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2"
            elif log_type == 'logout':
                ts_str = timestamp.strftime('%b %d %H:%M:%S')
                log = f"{ts_str} {hostname} sshd[{pid}]: Disconnected from user {user} {ip} port {random.randint(49152, 65535)}"
            elif log_type == 'sudo':
                ts_str = timestamp.strftime('%b %d %H:%M:%S')
                cmd = random.choice(['/usr/bin/apt update', '/bin/systemctl restart nginx', '/usr/bin/docker ps'])
                log = f"{ts_str} {hostname} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"
            
            logs.append(log)
        
        # Generate attack activity (40%)
        attack_count = count - normal_count
        attacker_ip = "185.220.101.45"
        target_users = ['root', 'admin', 'administrator', 'test', 'oracle']
        
        for i in range(attack_count):
            timestamp = base_time + timedelta(seconds=(normal_count + i) * 2)
            attack_type = random.choice(['brute_force', 'spray', 'priv_esc', 'lockout'])
            
            if attack_type == 'brute_force':
                # Multiple failed logins from same IP
                user = random.choice(target_users)
                port = random.randint(49152, 65535)
                ts_str = timestamp.strftime('%b %d %H:%M:%S')
                log = f"{ts_str} {hostname} sshd[{pid}]: Failed password for {user} from {attacker_ip} port {port} ssh2"
            
            elif attack_type == 'spray':
                # Same password tried against multiple accounts
                user = random.choice(target_users)
                port = random.randint(49152, 65535)
                ts_str = timestamp.strftime('%b %d %H:%M:%S')
                log = f"{ts_str} {hostname} sshd[{pid}]: Failed password for invalid user {user} from {attacker_ip} port {port} ssh2"
            
            elif attack_type == 'priv_esc':
                # Windows privilege escalation event
                ts_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                log = f"{ts_str};EventID 4672;Special privileges assigned to new logon.;Account Name: admin;Source Network Address: {attacker_ip};Logon Type: 3"
            
            elif attack_type == 'lockout':
                # Account lockout after multiple failures
                user = random.choice(users)
                ts_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                log = f"{ts_str};EventID 4740;A user account was locked out.;Account Name: {user};Source Network Address: {attacker_ip};Logon Type: 3"
            
            logs.append(log)
        
        return logs
