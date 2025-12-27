import customtkinter as ctk
import threading
import queue
from datetime import datetime
from core.models import Alert

from core.state import AppState
from core.database import DatabaseManager

class SentinelDashboard(ctk.CTk):
    def __init__(self, alert_queue: queue.Queue, app_state: AppState, db_manager: DatabaseManager):
        super().__init__()
        
        self.alert_queue = alert_queue
        self.app_state = app_state
        self.db_manager = db_manager
        self.last_hash = None # Track top line for deduplication
        
        # Window setup
        self.title("SentinelHIDS - Monitor")
        self.geometry("1100x600")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
        
        # Grid layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Sidebar
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(6, weight=1) # Spacer push down
        
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="SentinelHIDS", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        self.btn_overview = ctk.CTkButton(self.sidebar_frame, text="Overview", command=lambda: self.switch_view("Overview"))
        self.btn_overview.grid(row=1, column=0, padx=20, pady=10)
        
        self.btn_network = ctk.CTkButton(self.sidebar_frame, text="Network Monitor", command=lambda: self.switch_view("Network Monitoring"))
        self.btn_network.grid(row=2, column=0, padx=20, pady=10)
        
        self.btn_system = ctk.CTkButton(self.sidebar_frame, text="System Logs", command=lambda: self.switch_view("System Event Logs"))
        self.btn_system.grid(row=3, column=0, padx=20, pady=10)
        
        # Controls
        self.chk_audit = ctk.CTkCheckBox(self.sidebar_frame, text="Audit All Mode", command=self.toggle_audit)
        self.chk_audit.grid(row=4, column=0, padx=20, pady=(10, 5))
        
        self.chk_noise = ctk.CTkCheckBox(self.sidebar_frame, text="Hide Local Noise", command=self.toggle_noise)
        self.chk_noise.select() # Default on
        self.chk_noise.grid(row=5, column=0, padx=20, pady=5)
        
        self.chk_aggr = ctk.CTkCheckBox(self.sidebar_frame, text="Dedup. Mode", command=self.toggle_aggr)
        self.chk_aggr.select() # Default on
        self.chk_aggr.grid(row=6, column=0, padx=20, pady=5)

        self.btn_clear = ctk.CTkButton(self.sidebar_frame, text="Clear Logs", fg_color="red", hover_color="darkred", command=self.clear_logs)
        self.btn_clear.grid(row=7, column=0, padx=20, pady=(20, 10))

        # Main Content Area
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        self.view_label = ctk.CTkLabel(self.main_frame, text="Operational Overview", font=ctk.CTkFont(size=24, weight="bold"))
        self.view_label.pack(anchor="w", pady=(0, 10))

        # --- Overview View (Stats) ---
        self.overview_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        
        # Grid for stats
        self.overview_frame.grid_columnconfigure(0, weight=1)
        self.overview_frame.grid_columnconfigure(1, weight=1)
        self.overview_frame.grid_columnconfigure(2, weight=1)
        
        # Stats Widgets
        self.lbl_pkt_count = self._create_stat_card(self.overview_frame, "Total Packets", "0", 0, "blue")
        self.lbl_noise_count = self._create_stat_card(self.overview_frame, "Noise Filtered", "0", 1, "gray")
        self.lbl_alert_count = self._create_stat_card(self.overview_frame, "Security Alerts", "0", 2, "orange")

        # --- Network View ---
        self.network_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        
        # Network Header (Adjusted Time padding)
        header_text = "TIME          | PROCESS              | DESTINATION        | PORT  | GEO | MESSAGE                             | LATENCY | COUNT"
        self.net_header_lbl = ctk.CTkLabel(self.network_frame, text=header_text, font=("Consolas", 11, "bold"), anchor="w", text_color="silver")
        self.net_header_lbl.pack(fill="x")
        
        self.network_log = ctk.CTkTextbox(self.network_frame, width=800, height=500, font=("Consolas", 12))
        self.network_log.pack(fill="both", expand=True)
        self.network_log.configure(state="disabled")
        
        self._setup_tags(self.network_log)

        # --- System View ---
        self.system_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        
        # System Header
        sys_header_text = "TIME          | SOURCE          | SEVERITY | MESSAGE"
        self.sys_header_lbl = ctk.CTkLabel(self.system_frame, text=sys_header_text, font=("Consolas", 11, "bold"), anchor="w", text_color="silver")
        self.sys_header_lbl.pack(fill="x")
        
        self.system_log = ctk.CTkTextbox(self.system_frame, width=800, height=500, font=("Consolas", 12))
        self.system_log.pack(fill="both", expand=True)
        self.system_log.configure(state="disabled")
        
        self._setup_tags(self.system_log)
        
        # Default View
        self.active_view = "Overview"
        self.overview_frame.pack(fill="both", expand=True)
        # self.network_frame.pack(fill="both", expand=True) # Old default
        
        # Start loops
        self.load_historical_data()
        self.check_queue()
        self.update_stats()

    def load_historical_data(self):
        """Load recent alerts from database into the UI."""
        alerts = self.db_manager.get_recent_alerts(limit=100)
        for alert in alerts:
            self.add_alert(alert)

    def _create_stat_card(self, parent, title, value, col, color):
        frame = ctk.CTkFrame(parent, height=150, fg_color=("#333333", "#2b2b2b")) # Card background
        frame.grid(row=0, column=col, padx=10, pady=10, sticky="nsew")
        
        lbl_title = ctk.CTkLabel(frame, text=title, font=("Arial", 14), text_color="silver")
        lbl_title.pack(pady=(20, 5))
        
        lbl_val = ctk.CTkLabel(frame, text=value, font=("Arial", 32, "bold"), text_color=color)
        lbl_val.pack(pady=10)
        
        return lbl_val

    def update_stats(self):
        """Update live counters."""
        self.lbl_pkt_count.configure(text=f"{self.app_state.pkt_count:,}")
        self.lbl_noise_count.configure(text=f"{self.app_state.noise_count:,}")
        self.lbl_alert_count.configure(text=f"{self.app_state.alert_count:,}")
        self.after(1000, self.update_stats)

    def _setup_tags(self, textbox):
        textbox.tag_config("Trace", foreground="gray")
        textbox.tag_config("Info", foreground="white")
        textbox.tag_config("Warning", foreground="orange")
        textbox.tag_config("Critical", foreground="red")
        textbox.tag_config("System", foreground="cyan")

    def toggle_audit(self):
        self.app_state.show_all_traffic = bool(self.chk_audit.get())
        status = "Audit Mode Active" if self.app_state.show_all_traffic else "Security Only"
        self.add_alert(Alert(datetime.now(), "System", "Info", "Dashboard", f"Switched to {status}"))

    def toggle_noise(self):
        self.app_state.hide_local_noise = bool(self.chk_noise.get())

    def toggle_aggr(self):
        self.app_state.aggregation_enabled = bool(self.chk_aggr.get())

    def clear_logs(self):
        # Clear the active view
        target = self.network_log if self.active_view == "Network" else self.system_log
        target.configure(state="normal")
        target.delete("1.0", "end")
        target.configure(state="disabled")

    def switch_view(self, view_name):
        # Hide all first
        self.network_frame.pack_forget()
        self.system_frame.pack_forget()
        self.overview_frame.pack_forget()
        
        if view_name == "Overview":
            self.active_view = "Overview"
            self.view_label.configure(text="Operational Overview")
            self.overview_frame.pack(fill="both", expand=True)
        elif view_name == "System Event Logs":
            self.active_view = "System"
            self.view_label.configure(text="System Events")
            self.system_frame.pack(fill="both", expand=True)
        else:
            # Default to Network for Network Monitoring
            self.active_view = "Network"
            self.view_label.configure(text="Network Intelligence")
            self.network_frame.pack(fill="both", expand=True)
            
        self.add_alert(Alert(datetime.now(), "System", "Info", "Dashboard", f"Switched view to {view_name}"))

    def check_queue(self):
        """Poll the queue for new alerts."""
        try:
            while True:
                # Non-blocking get
                alert = self.alert_queue.get_nowait()
                self.add_alert(alert)
        except queue.Empty:
            pass
        finally:
            # Schedule next check in 100ms
            self.after(100, self.check_queue)

    def add_alert(self, alert: Alert):
        """Add alert to the appropriate log view."""
        display_time = datetime.now()
        latency_ms = (display_time - alert.timestamp).total_seconds() * 1000
        t_str = alert.timestamp.strftime('%H:%M:%S')

        # ROUTING LOGIC
        if alert.alert_type in ["Network", "Traffic"]:
            # --- Network Log (Columnar) ---
            target_log = self.network_log
            
            # Strict fixed-width formatting
            proc = (alert.process_name or "Unknown")[:20].ljust(20)
            dest = (alert.dst_ip or "-")[:18].ljust(18)
            port = str(alert.dst_port or "-")[:5].ljust(5)
            geo = (alert.country or "-")[:3].ljust(3)
            msg = alert.message[:35].ljust(35)
            cnt = f"[x{alert.count}]" if alert.count > 1 else "    "
            lat = f"{latency_ms:3.0f}ms"

            formatted_line = f"[{t_str}] {proc} {dest} {port} {geo} {msg} {lat} {cnt}\n"
            
            # Deduplication relies on the hash matching the last inserted line IN THIS LOG
            # simpler approach: we won't strictly dedup the UI line here to avoid complexity with switching views
            # or we rely on the backend not sending it unless count > 1
            
            target_log.configure(state="normal")
            target_log.insert("1.0", formatted_line, alert.severity)
            
            # Truncate
            if float(target_log.index("end-1c")) > 500:
                target_log.delete("501.0", "end")
            target_log.configure(state="disabled")

        else:
            # --- System Log (Simple) ---
            target_log = self.system_log
            
            src = (alert.source or "System")[:15].ljust(15)
            sev = (alert.severity or "Info").ljust(8)
            msg = alert.message
            
            formatted_line = f"[{t_str}] {src} {sev} {msg}\n"
            
            target_log.configure(state="normal")
            target_log.insert("1.0", formatted_line, alert.severity)
            target_log.configure(state="disabled")

def start_gui(alert_queue: queue.Queue, app_state: AppState, db_manager: DatabaseManager):
    app = SentinelDashboard(alert_queue, app_state, db_manager)
    app.mainloop()
