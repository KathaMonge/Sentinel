from dataclasses import dataclass
from datetime import datetime
from typing import Optional

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
    
    def __str__(self):
        return f"[{self.timestamp}] [{self.severity}] {self.alert_type}: {self.message}"
