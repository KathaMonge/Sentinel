import psutil
import time
import threading

class ProcessMapper:
    def __init__(self, refresh_interval=2.0):
        self.refresh_interval = refresh_interval
        self.last_refresh = 0
        self.connection_cache = {} # Key: (local_port, protocol), Value: (pid, name)
        self.lock = threading.Lock()
        
    def _refresh_cache(self):
        """Snapshots current network connections."""
        current_time = time.time()
        if current_time - self.last_refresh < self.refresh_interval:
            return

        new_cache = {}
        try:
            # kind='inet' covers IPv4 and IPv6, TCP and UDP
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.laddr and conn.pid:
                    # conn.type is socket.SOCK_STREAM (TCP) or socket.SOCK_DGRAM (UDP)
                    # We map based on local port
                    protocol = 'TCP' if conn.type == 1 else 'UDP' # socket.SOCK_STREAM=1
                    key = (conn.laddr.port, protocol)
                    
                    try:
                        proc = psutil.Process(conn.pid)
                        name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        name = "Unknown"
                        
                    new_cache[key] = (conn.pid, name)
                    
        except Exception as e:
            print(f"[!] ProcessMapper refresh failed: {e}")
            
        with self.lock:
            self.connection_cache = new_cache
            self.last_refresh = current_time

    def get_process(self, local_port: int, protocol: str = 'TCP'):
        """
        Returns (pid, process_name) for a given local port/protocol.
        Triggers a cache refresh if stale.
        """
        # Optimistic check first
        with self.lock:
            if (local_port, protocol) in self.connection_cache:
                return self.connection_cache[(local_port, protocol)]
        
        # If not found or stale context needed (though we rely on background refresh or on-demand)
        # For simplicity, we refresh on miss or timeout inside _refresh_cache logic
        self._refresh_cache()
        
        with self.lock:
            return self.connection_cache.get((local_port, protocol), (None, None))
