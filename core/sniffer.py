import threading
import pyshark
import time
from datetime import datetime
from core.models import Alert
import queue
import asyncio

from core.process_mapper import ProcessMapper
from core.geoip_manager import GeoIPManager

from core.state import AppState
from core.database import DatabaseManager

class SnifferThread(threading.Thread):
    def __init__(self, interface: str, alert_queue: queue.Queue, app_state: AppState, db_manager: DatabaseManager):
        super().__init__()
        self.interface = interface
        self.alert_queue = alert_queue
        self.app_state = app_state
        self.db_manager = db_manager
        self.running = True
        self.daemon = True 
        
        # Initialize Intelligence Modules
        self.process_mapper = ProcessMapper()
        self.geoip_manager = GeoIPManager()
        
        # Deduplication Cache: { flow_hash: Alert }
        self.flow_cache = {}
        self.cache_lock = threading.Lock()

    def run(self):
        print(f"[*] Starting network sniffer on {self.interface}...")
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            self.capture = pyshark.LiveCapture(interface=self.interface, display_filter='ip')
            
            # Send an initial alert to confirm sniffer is working
            self.alert_queue.put(Alert(
                timestamp=datetime.now(),
                alert_type="System",
                severity="Info",
                source="Sniffer",
                message=f"Network monitoring active on {self.interface}"
            ))
            
            # Also send to Network Intelligence view for visual confirmation
            self.alert_queue.put(Alert(
                timestamp=datetime.now(),
                alert_type="Network",
                severity="Info",
                source="Sniffer",
                message=f"Sniffer capture loop started on {self.interface}"
            ))

            for packet in self.capture.sniff_continuously():
                if not self.running:
                    break
                
                self.process_packet(packet)
                
        except Exception as e:
            print(f"[!] Sniffer thread error: {e}")
            err_alert = Alert(
                timestamp=datetime.now(),
                alert_type="System",
                severity="Critical",
                source="Sniffer",
                message=f"Sniffer crashed: {e}"
            )
            self.alert_queue.put(err_alert)
        finally:
            if hasattr(self, 'capture'):
                try:
                    self.capture.close()
                except:
                    pass
            self.geoip_manager.close()

    def is_noise(self, dst_ip, dst_port, protocol):
        """Identifies mDNS, SSDP, Broadcast, and Multicast traffic."""
        # SSDP specific
        if dst_ip == "239.255.255.250":
            return True
            
        # Broadcast/Multicast IPs
        if dst_ip == "255.255.255.255" or dst_ip.startswith("224.") or dst_ip.startswith("239."):
            return True
        
        # Local Noise Ports
        noise_ports = {5353, 5355, 1900, 67, 68} # mDNS, LLMNR, SSDP, DHCP
        # 6667 often seen in local noise in sample
        if dst_port in noise_ports:
            return True
        
        # Filter "Unknown Outbound None" often seen
        if protocol is None or protocol == "None":
            return True
            
        return False

    def emit_alert(self, alert: Alert):
        """Handles temporal aggregation before pushing to queue and database."""
        if not self.app_state.aggregation_enabled:
            self.alert_queue.put(alert)
            self.db_manager.save_alert(alert)
            return

        h = alert.flow_hash
        with self.cache_lock:
            if h in self.flow_cache:
                stored = self.flow_cache[h]
                # Check window (5 seconds)
                if (alert.timestamp - stored.timestamp).total_seconds() < 5:
                    stored.count += 1
                    # In this simple implementation, we push the updated alert
                    # The UI will recognize the hash and update the line instead of adding
                    self.alert_queue.put(alert)
                    # For performance, we don't save every deduplicated packet to DB 
                    # unless it's a significant milestone or when flushed.
                    # For now, we'll just save the initial one.
                    return
            
            self.flow_cache[h] = alert
            self.alert_queue.put(alert)
            self.db_manager.save_alert(alert)

    def process_packet(self, packet):
        if not self.app_state.monitoring_active:
            return
        try:
            if 'IP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                
                if src_ip == "127.0.0.1" or src_ip == "::1":
                    return

                protocol = packet.transport_layer 
                dst_port = 0
                src_port = 0
                
                if protocol == 'TCP':
                    dst_port = int(packet.tcp.dstport)
                    src_port = int(packet.tcp.srcport)
                elif protocol == 'UDP':
                    dst_port = int(packet.udp.dstport)
                    src_port = int(packet.udp.srcport)
                
                # Counters
                self.app_state.pkt_count += 1
                if self.app_state.show_all_traffic:
                    print(f"[*] Processed packet: {src_ip} -> {dst_ip}:{dst_port} ({protocol})")
                
                # Noise Filtering
                is_noise_packet = self.is_noise(dst_ip, dst_port, protocol)
                if is_noise_packet:
                    self.app_state.noise_count += 1
                    
                if self.app_state.hide_local_noise and is_noise_packet:
                    return

                # Get Intelligence
                pid, process_name = self.process_mapper.get_process(src_port, protocol)
                process_name = process_name or "System"
                country = self.geoip_manager.lookup(dst_ip)
                
                timestamp = datetime.now()
                severity = "Info"
                alert_type = "Traffic"
                message = f"Outbound {protocol}"

                # Security Rule: Port 80
                if dst_port == 80:
                    severity = "Warning"
                    alert_type = "Network"
                    message = "Unencrypted HTTP"
                    self.app_state.alert_count += 1 # Security Alert
                
                alert = Alert(
                    timestamp=timestamp,
                    alert_type=alert_type,
                    severity=severity,
                    source="Sniffer",
                    message=message,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    process_name=process_name,
                    process_id=pid,
                    country=country
                )

                if self.app_state.show_all_traffic or alert_type == "Network":
                    self.emit_alert(alert)
                    
        except Exception as e:
            print(f"[!] Error processing packet: {e}")

    def stop(self):
        self.running = False
