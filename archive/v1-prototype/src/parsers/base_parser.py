"""
Base Parser Module

Abstract base class for all log parsers in the IntelliDetect SIEM system.
Defines the common interface and shared functionality for parsing different log formats.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
import re


class LogEvent:
    """
    Represents a parsed log event with standardized fields.
    
    Attributes:
        timestamp: When the event occurred
        source_type: Type of log source (sysmon, apache, firewall, auth)
        raw_log: Original raw log line
        fields: Dictionary of parsed fields
    """
    
    def __init__(
        self,
        timestamp: datetime,
        source_type: str,
        raw_log: str,
        **kwargs
    ):
        self.timestamp = timestamp
        self.source_type = source_type
        self.raw_log = raw_log
        self.fields: Dict[str, Any] = kwargs
        self.event_id: Optional[str] = None
        self.severity: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary representation."""
        return {
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_type': self.source_type,
            'raw_log': self.raw_log,
            'event_id': self.event_id,
            'severity': self.severity,
            **self.fields
        }
    
    def get_field(self, field_name: str, default: Any = None) -> Any:
        """Get a field value by name."""
        return self.fields.get(field_name, default)
    
    def __repr__(self) -> str:
        return f"LogEvent(timestamp={self.timestamp}, source={self.source_type})"


class BaseParser(ABC):
    """
    Abstract base class for log parsers.
    
    All specific parsers (Sysmon, Apache, Firewall, Auth) must inherit
    from this class and implement the required methods.
    """
    
    def __init__(self, source_type: str):
        """
        Initialize the base parser.
        
        Args:
            source_type: Type identifier for this parser (e.g., 'sysmon', 'apache')
        """
        self.source_type = source_type
        self.parse_errors: List[Dict[str, Any]] = []
        self.stats = {
            'total_lines': 0,
            'parsed_successfully': 0,
            'parse_failures': 0
        }
    
    @abstractmethod
    def parse_line(self, line: str) -> Optional[LogEvent]:
        """
        Parse a single log line into a LogEvent object.
        
        Args:
            line: Raw log line to parse
            
        Returns:
            LogEvent object if parsing successful, None otherwise
        """
        pass
    
    @abstractmethod
    def generate_sample_logs(self, count: int = 100) -> List[str]:
        """
        Generate sample log lines for testing.
        
        Args:
            count: Number of sample log lines to generate
            
        Returns:
            List of sample log strings
        """
        pass
    
    def parse_file(self, file_path: str) -> List[LogEvent]:
        """
        Parse an entire log file.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            List of parsed LogEvent objects
        """
        events = []
        self.stats = {'total_lines': 0, 'parsed_successfully': 0, 'parse_failures': 0}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    self.stats['total_lines'] += 1
                    line = line.strip()
                    
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        event = self.parse_line(line)
                        if event:
                            events.append(event)
                            self.stats['parsed_successfully'] += 1
                        else:
                            self.stats['parse_failures'] += 1
                    except Exception as e:
                        self.parse_errors.append({
                            'line_number': line_num,
                            'line': line[:100],  # First 100 chars
                            'error': str(e)
                        })
                        self.stats['parse_failures'] += 1
                        
        except FileNotFoundError:
            raise FileNotFoundError(f"Log file not found: {file_path}")
        except Exception as e:
            raise Exception(f"Error reading log file: {e}")
        
        return events
    
    def parse_string(self, log_content: str) -> List[LogEvent]:
        """
        Parse log content from a string.
        
        Args:
            log_content: String containing log lines
            
        Returns:
            List of parsed LogEvent objects
        """
        events = []
        lines = log_content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            event = self.parse_line(line)
            if event:
                events.append(event)
        
        return events
    
    def get_stats(self) -> Dict[str, Any]:
        """Get parsing statistics."""
        return {
            **self.stats,
            'error_count': len(self.parse_errors),
            'source_type': self.source_type
        }
    
    def reset_stats(self):
        """Reset parsing statistics."""
        self.stats = {'total_lines': 0, 'parsed_successfully': 0, 'parse_failures': 0}
        self.parse_errors = []
    
    @staticmethod
    def parse_timestamp(timestamp_str: str, formats: List[str] = None) -> Optional[datetime]:
        """
        Parse a timestamp string into a datetime object.
        
        Args:
            timestamp_str: Timestamp string to parse
            formats: List of date formats to try
            
        Returns:
            datetime object if parsing successful, None otherwise
        """
        if formats is None:
            formats = [
                '%Y-%m-%d %H:%M:%S.%f',
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%SZ',
                '%d/%b/%Y:%H:%M:%S %z',
                '%b %d %H:%M:%S',
                '%Y/%m/%d %H:%M:%S',
            ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        # Try ISO format as fallback
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except:
            pass
        
        return None
    
    @staticmethod
    def extract_ip(text: str) -> Optional[str]:
        """Extract IP address from text using regex."""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, text)
        return match.group(0) if match else None
    
    @staticmethod
    def extract_port(text: str) -> Optional[int]:
        """Extract port number from text."""
        port_pattern = r'\b(\d{2,5})\b'
        matches = re.findall(port_pattern, text)
        for match in matches:
            port = int(match)
            if 1 <= port <= 65535:
                return port
        return None
