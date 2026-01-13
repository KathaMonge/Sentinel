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

from core.state import AppState
from core.database import DatabaseManager

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
    
    # Check privileges and implement graceful degradation
    admin_mode = is_admin()
    if not admin_mode:
        print("[!] WARNING: Not running as Administrator. Some features will be limited.")
        print("[!] - Network packet capture will be disabled")
        print("[!] - Windows Security Event Log access will be limited")
        print("[!] - Run as Administrator for full functionality")
    
    # 1. Initialize the thread-safe queue for alerts
    alert_queue = queue.Queue()
    
    # 2. Shared Application State
    app_state = AppState()
    
    # 3. Setup Background Threads with privilege awareness
    interface = get_active_interface()
    sniffer_thread = None
    log_thread = None
    
    # Database Manager
    db_manager = DatabaseManager("data/alerts.db")
    
    # Network Sniffer - Requires admin privileges
    if interface and admin_mode:
        print(f"[*] Detected active interface: {interface}")
        try:
            sniffer_thread = SnifferThread(interface=interface, alert_queue=alert_queue, app_state=app_state, db_manager=db_manager)
            sniffer_thread.start()
            alert_queue.put(Alert(datetime.now(), "System", "Info", "Main", f"Network monitoring started on {interface}"))
        except Exception as e:
            print(f"[!] Failed to start network sniffer: {e}")
            alert_queue.put(Alert(datetime.now(), "System", "Warning", "Main", f"Network sniffer failed: {e}"))
    elif interface and not admin_mode:
        print("[!] Network interface detected but packet capture requires Administrator privileges")
        alert_queue.put(Alert(datetime.now(), "System", "Warning", "Main", "Network monitoring disabled (requires admin)"))
    else:
        print("[!] No active network interface found")
        alert_queue.put(Alert(datetime.now(), "System", "Warning", "Main", "No network interface detected"))

    # Log Watcher - Can run in limited mode without admin
    try:
        log_thread = LogWatcherThread(alert_queue, db_manager, app_state)
        log_thread.start()
        if admin_mode:
            print("[*] System log monitoring started (full access)")
            alert_queue.put(Alert(datetime.now(), "System", "Info", "Main", "Security log monitoring started"))
        else:
            print("[*] System log monitoring started (limited access)")
            alert_queue.put(Alert(datetime.now(), "System", "Warning", "Main", "Limited log access (run as admin for full monitoring)"))
    except Exception as e:
        print(f"[!] Failed to start log watcher: {e}")
        alert_queue.put(Alert(datetime.now(), "System", "Critical", "Main", f"Log watcher failed: {e}"))

    # Status summary
    if admin_mode:
        print("[*] Running in Administrator mode with full functionality")
    else:
        print("[*] Running in limited mode - some features disabled")
    
    # Diagnostic alert
    alert_queue.put(Alert(datetime.now(), "System", "Info", "Main", f"SentinelHIDS initialized - Admin mode: {admin_mode}"))

    # 4. Start GUI (Blocks this thread until closed)
    print("Starting GUI...")
    try:
        start_gui(alert_queue, app_state, db_manager)
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
            sniffer_thread.join(timeout=5)
        if log_thread:
            log_thread.stop()
            log_thread.join(timeout=5)
        print("SentinelHIDS stopped.")

if __name__ == "__main__":
    main()
