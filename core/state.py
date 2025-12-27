class AppState:
    def __init__(self):
        self.show_all_traffic = False
        self.hide_local_noise = True  # Hide mDNS, SSDP, etc.
        self.aggregation_enabled = True # Use temporal aggregation
