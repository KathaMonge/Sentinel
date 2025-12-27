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
    count: int = 1  # For temporal aggregation
    
    @property
    def flow_hash(self):
        """Unique ID for deduplication."""
        return f"{self.process_name}|{self.dst_ip}|{self.dst_port}|{self.alert_type}"

    def __str__(self):
        cnt_str = f" [x{self.count}]" if self.count > 1 else ""
        return f"[{self.timestamp}] [{self.severity}] {self.alert_type}: {self.message}{cnt_str}"
