import sys
import threading
import queue
import time
from datetime import datetime
import psutil
from core.models import Alert
from core.sniffer import SnifferThread
from core.log_watcher import LogWatcherThread
from ui.dashboard import start_gui
import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_active_interface():
    """Simple heuristic to find an active interface (has an IP)."""
    # This is broad; for PyShark on Windows, we often need the name like 'Ethernet' or 'Wi-Fi'.
    # psutil keys are usually friendly names on Windows.
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    
    for iface, addr_list in addrs.items():
        if iface in stats and getattr(stats[iface], "isup", False):
            for addr in addr_list:
                if addr.family == 2: # AF_INET (IPv4)
                    if not addr.address.startswith("127."):
                        return iface
    return None

def main():
    print(f"[{datetime.now()}] SentinelHIDS starting...")
    
    if not is_admin():
        print("[!] WARNING: Not running as Administrator. Packet capture and Security Log reading will likely fail.")
        print("[!] Please run this terminal as Administrator.")
    
    # 1. Initialize the thread-safe queue for alerts
    alert_queue = queue.Queue()
    
    # 2. Setup Background Threads
    # Find interface
    interface = get_active_interface()
    sniffer_thread = None
    log_thread = None
    
    if interface:
        print(f"[*] Detected active interface: {interface}")
        # Note: PyShark on Windows sometimes needs specific adapter names. 
        # If 'Ethernet' fails, might need to list from tshark -D.
        sniffer_thread = SnifferThread(interface=interface, alert_queue=alert_queue)
        sniffer_thread.start()
    else:
        print("[!] No active non-loopback interface found. Sniffer will not start.")
        # Send a system alert to GUI
        alert_queue.put(Alert(datetime.now(), "System", "Warning", "Main", "No network interface detected."))

    # Start Log Watcher
    log_thread = LogWatcherThread(alert_queue)
    log_thread.start()

    # Diagnostic alert
    alert_queue.put(Alert(datetime.now(), "System", "Info", "Main", "Queue-to-GUI communication test."))

    # 3. Start GUI (Blocks this thread until closed)
    print("Starting GUI...")
    try:
        start_gui(alert_queue)
    except KeyboardInterrupt:
        print("[*] Keyboard Interrupt received.")
    except Exception as e:
        print(f"[!] GUI Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("Stopping threads...")
        if sniffer_thread:
            sniffer_thread.stop()
            sniffer_thread.join(timeout=2)
        if log_thread:
            log_thread.stop()
            log_thread.join(timeout=3)
        print("SentinelHIDS stopped.")

if __name__ == "__main__":
    main()
