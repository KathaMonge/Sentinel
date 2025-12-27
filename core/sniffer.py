import threading
import pyshark
import time
from datetime import datetime
from core.models import Alert
import queue
import asyncio

class SnifferThread(threading.Thread):
    def __init__(self, interface: str, alert_queue: queue.Queue):
        super().__init__()
        self.interface = interface
        self.alert_queue = alert_queue
        self.running = True
        self.daemon = True # Daemonize to kill when main exits

    def run(self):
        print(f"[*] Starting network sniffer on {self.interface}...")
        
        # PyShark LiveCapture uses asyncio. In a new thread, there is no default loop.
        # We must create and set one.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # display_filter to capture only interesting traffic (TCP/UDP)
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

    def process_packet(self, packet):
        try:
            # Basic info extraction
            # This depends heavily on packet layers present (IP, TCP, UDP, etc.)
            
            if 'IP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                
                # Filter out loopback for now if desired
                if src_ip == "127.0.0.1" or src_ip == "::1":
                    return

                # Check layers
                protocol = packet.transport_layer # e.g. TCP or UDP
                dst_port = 0
                
                if protocol == 'TCP':
                    dst_port = int(packet.tcp.dstport)
                elif protocol == 'UDP':
                    dst_port = int(packet.udp.dstport)
                
                # Check for Port 80 (HTTP) as per requirements
                if dst_port == 80:
                    alert = Alert(
                        timestamp=datetime.now(),
                        alert_type="Network",
                        severity="Medium",
                        source="Sniffer",
                        message=f"Unencrypted HTTP traffic detected to {dst_ip}",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port
                    )
                    self.alert_queue.put(alert)
                    
                # TODO: GeoIP lookup here
                # TODO: Process mapping here
                
        except Exception as e:
            # Packet parsing error, ignore
            pass

    def stop(self):
        self.running = False
