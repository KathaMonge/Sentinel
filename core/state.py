import threading

class AppState:
    def __init__(self):
        self.show_all_traffic = False
        self.hide_local_noise = True  # Hide mDNS, SSDP, etc.
        self.aggregation_enabled = True # Use temporal aggregation
        self.monitoring_active = False  # Start paused
        
        # Statistics
        self.pkt_count = 0
        self.noise_count = 0
        self.alert_count = 0
        
        # Thread safety
        self._lock = threading.Lock()
    
    def increment_packet_count(self):
        with self._lock:
            self.pkt_count += 1
    
    def increment_noise_count(self):
        with self._lock:
            self.noise_count += 1
    
    def increment_alert_count(self):
        with self._lock:
            self.alert_count += 1
    
    def get_stats(self):
        """Get current stats in a thread-safe manner."""
        with self._lock:
            return {
                'pkt_count': self.pkt_count,
                'noise_count': self.noise_count,
                'alert_count': self.alert_count
            }
