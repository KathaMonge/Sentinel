import customtkinter as ctk
import threading
import queue
from datetime import datetime
from core.models import Alert

from core.state import AppState

class SentinelDashboard(ctk.CTk):
    def __init__(self, alert_queue: queue.Queue, app_state: AppState):
        super().__init__()
        
        self.alert_queue = alert_queue
        self.app_state = app_state
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
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
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
        
        self.chk_aggr = ctk.CTkCheckBox(self.sidebar_frame, text="Temporal Aggr.", command=self.toggle_aggr)
        self.chk_aggr.select() # Default on
        self.chk_aggr.grid(row=6, column=0, padx=20, pady=5)

        self.btn_clear = ctk.CTkButton(self.sidebar_frame, text="Clear Logs", fg_color="red", hover_color="darkred", command=self.clear_logs)
        self.btn_clear.grid(row=7, column=0, padx=20, pady=(20, 10))

        # Main Content Area
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        # Header
        self.header = ctk.CTkLabel(self.main_frame, text="Operational Intelligence", font=ctk.CTkFont(size=24, weight="bold"))
        self.header.pack(anchor="w")
        
        # Alerts Text Box (Structured format)
        self.alerts_textbox = ctk.CTkTextbox(self.main_frame, width=800, height=520, font=("Consolas", 12))
        self.alerts_textbox.pack(pady=10, fill="both", expand=True)
        self.alerts_textbox.configure(state="disabled")
        
        # Color Tags for Severity
        self.alerts_textbox.tag_config("Trace", foreground="gray")
        self.alerts_textbox.tag_config("Info", foreground="white") # Notice
        self.alerts_textbox.tag_config("Warning", foreground="orange")
        self.alerts_textbox.tag_config("Critical", foreground="red") # Alert
        self.alerts_textbox.tag_config("System", foreground="cyan")
        
        # Start polling queue
        self.check_queue()

    def toggle_audit(self):
        self.app_state.show_all_traffic = bool(self.chk_audit.get())
        status = "Audit Mode Active" if self.app_state.show_all_traffic else "Security Only"
        self.add_alert(Alert(datetime.now(), "System", "Info", "Dashboard", f"Switched to {status}"))

    def toggle_noise(self):
        self.app_state.hide_local_noise = bool(self.chk_noise.get())

    def toggle_aggr(self):
        self.app_state.aggregation_enabled = bool(self.chk_aggr.get())

    def clear_logs(self):
        self.alerts_textbox.configure(state="normal")
        self.alerts_textbox.delete("1.0", "end")
        self.alerts_textbox.configure(state="disabled")

    def switch_view(self, view_name):
        self.header.configure(text=view_name)
        # For a full implementation, we would swap frames here.
        # For now, just updating the header confirms the buttons work.
        self.add_alert(Alert(datetime.now(), "UI", "Info", "Dashboard", f"Switched view to {view_name}"))

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
        """Add structured alert with columnar formatting and color-coding."""
        display_time = datetime.now()
        latency_ms = (display_time - alert.timestamp).total_seconds() * 1000
        
        # Handle Deduplication: If the same flow hit within 5s, we update the first line
        # Simple implementation: check if the hash of top line matches
        h = alert.flow_hash
        try:
            self.alerts_textbox.configure(state="normal")
            
            # Formatted Columnar string
            # [TIME] [PROT] [PROCESS] [DESTINATION] [PORT] [GEO] [MSG] [CNT]
            t_str = alert.timestamp.strftime('%H:%M:%S')
            proc = (alert.process_name or "Unknown")[:15].ljust(15)
            dest = (alert.dst_ip or "-").ljust(15)
            port = str(alert.dst_port or "-").ljust(5)
            geo = (alert.country or "-").ljust(3)
            msg = alert.message[:30].ljust(30)
            cnt = f"[x{alert.count}]" if alert.count > 1 else "    "
            lat = f"{latency_ms:3.0f}ms"

            formatted_line = f"[{t_str}] {proc} {dest} {port} {geo} {msg} {lat} {cnt}\n"

            # Deduplication: If this hash matches the last one, replace the top line
            if h == self.last_hash:
                self.alerts_textbox.delete("1.0", "2.0")
            
            self.alerts_textbox.insert("1.0", formatted_line, alert.severity)
            self.last_hash = h
            
            # Keep log buffer manageable (e.g. 500 lines)
            if float(self.alerts_textbox.index("end-1c")) > 500:
                self.alerts_textbox.delete("501.0", "end")
                
        finally:
            self.alerts_textbox.configure(state="disabled")

def start_gui(alert_queue: queue.Queue, app_state: AppState):
    app = SentinelDashboard(alert_queue, app_state)
    app.mainloop()
