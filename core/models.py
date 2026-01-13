from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import re

@dataclass
class Alert:
    timestamp: datetime
    alert_type: str  # e.g., "Network", "System"
    severity: str    # "Info", "Low", "Medium", "High", "Critical"
    source: str      # Source of the alert (e.g., "Packet Sniffer", "Event Log")
    message: str     # Human readable description
    
    # Optional fields depending on alert type
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    country: Optional[str] = None
    count: int = 1  # For temporal aggregation
    
    def __post_init__(self):
        """Validate and sanitize alert data."""
        # Validate severity
        valid_severities = ["Info", "Low", "Medium", "High", "Warning", "Critical"]
        if self.severity not in valid_severities:
            self.severity = "Info"
        
        # Validate and sanitize alert_type
        if self.alert_type:
            self.alert_type = self._sanitize_string(self.alert_type)[:50]
        else:
            self.alert_type = "Unknown"
        
        # Validate and sanitize source
        if self.source:
            self.source = self._sanitize_string(self.source)[:50]
        else:
            self.source = "Unknown"
        
        # Validate and sanitize message
        if self.message:
            self.message = self._sanitize_string(self.message)[:500]
        else:
            self.message = "No message"
        
        # Validate IP addresses
        if self.src_ip and not self._is_valid_ip(self.src_ip):
            self.src_ip = None
        if self.dst_ip and not self._is_valid_ip(self.dst_ip):
            self.dst_ip = None
        
        # Validate port
        if self.dst_port is not None:
            if not isinstance(self.dst_port, int) or not (0 <= self.dst_port <= 65535):
                self.dst_port = None
        
        # Validate process ID
        if self.process_id is not None:
            if not isinstance(self.process_id, int) or self.process_id <= 0:
                self.process_id = None
        
        # Sanitize process name
        if self.process_name:
            self.process_name = self._sanitize_string(self.process_name)[:100]
        
        # Sanitize country
        if self.country:
            self.country = self._sanitize_string(self.country)[:10]
        
        # Validate count
        if not isinstance(self.count, int) or self.count <= 0:
            self.count = 1
    
    def _sanitize_string(self, text: str) -> str:
        """Remove control characters and limit special characters."""
        if not text:
            return ""
        # Remove control characters except newlines and tabs
        sanitized = ''.join(char for char in text if char.isprintable() or char in '\t\n\r')
        # Remove potential SQL injection patterns
        sanitized = re.sub(r'[\'";\\]', '', sanitized)
        return sanitized.strip()
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Basic IP address validation."""
        if not ip:
            return False
        # Simple IPv4 validation
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ipv4_pattern, ip))
    
    @property
    def flow_hash(self):
        """Unique ID for deduplication."""
        return f"{self.process_name}|{self.dst_ip}|{self.dst_port}|{self.alert_type}"

    def __str__(self):
        cnt_str = f" [x{self.count}]" if self.count > 1 else ""
        return f"[{self.timestamp}] [{self.severity}] {self.alert_type}: {self.message}{cnt_str}"
