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

class SnifferThread(threading.Thread):
    def __init__(self, interface: str, alert_queue: queue.Queue, app_state: AppState):
        super().__init__()
        self.interface = interface
        self.alert_queue = alert_queue
        self.app_state = app_state
        self.running = True
        self.daemon = True 
        
        # Initialize Intelligence Modules
        self.process_mapper = ProcessMapper()
        self.geoip_manager = GeoIPManager()

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

    def process_packet(self, packet):
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
                
                # Get Process Info (We look up the LOCAL source port for outbound)
                # Important: packet capture sees traffic. Outbound traffic has ephemeral source port.
                pid, process_name = self.process_mapper.get_process(src_port, protocol)
                
                # Get GeoIP Info
                country = self.geoip_manager.lookup(dst_ip)
                
                # Check for Port 80 (HTTP)
                if dst_port == 80:
                    sender = f"{process_name} ({pid})" if pid else "Unknown Process"
                    country_str = f" to {country}" if country != "Unknown" else ""
                    
                    alert = Alert(
                        timestamp=datetime.now(),
                        alert_type="Network",
                        severity="Medium",
                        source="Sniffer",
                        message=f"Unencrypted HTTP traffic from {sender}{country_str}",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        process_name=process_name,
                        process_id=pid,
                        country=country
                    )
                    self.alert_queue.put(alert)
                    return # Avoid double logging if streaming is on

                # Real-time Streaming (if enabled)
                if self.app_state.show_all_traffic:
                    sender = f"{process_name} ({pid})" if pid else "Unknown"
                    msg = f"Traffic: {sender} -> {dst_ip} ({country}) [{protocol}/{dst_port}]"
                    
                    alert = Alert(
                        timestamp=datetime.now(),
                        alert_type="Traffic",
                        severity="Info",
                        source="Sniffer",
                        message=msg,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        process_name=process_name,
                        process_id=pid,
                        country=country
                    )
                    self.alert_queue.put(alert)
                    
        except Exception as e:
            pass

    def stop(self):
        self.running = False
