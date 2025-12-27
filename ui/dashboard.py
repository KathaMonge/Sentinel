import customtkinter as ctk
import threading
import queue
from datetime import datetime
from core.models import Alert

class SentinelDashboard(ctk.CTk):
    def __init__(self, alert_queue: queue.Queue):
        super().__init__()
        
        self.alert_queue = alert_queue
        
        # Window setup
        self.title("SentinelHIDS - Monitor")
        self.geometry("1000x600")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
        
        # Grid layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Sidebar
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)
        
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="SentinelHIDS", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        self.btn_overview = ctk.CTkButton(self.sidebar_frame, text="Overview")
        self.btn_overview.grid(row=1, column=0, padx=20, pady=10)
        
        self.btn_network = ctk.CTkButton(self.sidebar_frame, text="Network Monitor")
        self.btn_network.grid(row=2, column=0, padx=20, pady=10)
        
        self.btn_system = ctk.CTkButton(self.sidebar_frame, text="System Logs")
        self.btn_system.grid(row=3, column=0, padx=20, pady=10)
        
        # Main Content Area
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        # Header
        self.header = ctk.CTkLabel(self.main_frame, text="Live Alerts", font=ctk.CTkFont(size=24, weight="bold"))
        self.header.pack(anchor="w")
        
        # Alerts Text Box (Simple List for now)
        self.alerts_textbox = ctk.CTkTextbox(self.main_frame, width=800, height=500)
        self.alerts_textbox.pack(pady=10, fill="both", expand=True)
        self.alerts_textbox.configure(state="disabled") # Read only
        
        # Start polling queue
        self.check_queue()

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
        """Add alert to the display."""
        self.alerts_textbox.configure(state="normal")
        self.alerts_textbox.insert("1.0", str(alert) + "\n") # Add to top
        self.alerts_textbox.configure(state="disabled")

def start_gui(alert_queue: queue.Queue):
    app = SentinelDashboard(alert_queue)
    app.mainloop()
