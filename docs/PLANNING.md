# Project Planning & Roadmap

## 🎯 Objective
The objective of **SentinelHIDS** is to build a local, host-based intrusion detection system for Windows that provides real-time visibility into network and system security events without compromising user privacy.

## 🚧 Current Status (Phase 1-4 Complete)
- [x] **Core Architecture**: Thread-safe queue system and main orchestrator implemented.
- [x] **Network Module (Alpha)**: Basic PyShark integration for Port 80 detection.
- [x] **System Module (Alpha)**: Windows Security Log watcher structure implemented.
- [x] **GUI**: Dark-mode dashboard with live alert feed.
- [x] **Dependency Management**: Standardized `requirements.txt` and installation guides.

## 📈 Success Definition
We define success for the MVP (Minimum Viable Product) based on the following:
1.  **Reliability**: No crashes in core threads (Sniffer/Watcher) over a 4-hour monitoring window.
2.  **Visibility**: Alerts are displayed in the GUI within < 1 second of detection.
3.  **Low Resource Overhead**: CPU usage remains below 5% for background monitoring tasks.
4.  **Actionability**: Users can customize Port/Country alerts via `rules.yaml` without changing code.

## 🚀 Future Next Steps (Phase 5+)

### 1. Process Mapping Integration
Correlate network packets with specific Windows Processes (PID) using `psutil`. This allows the user to see *which application* is sending unencrypted traffic.

### 2. GeoIP Localization
Integrate the MaxMind GeoLite2 offline database to resolve destination IPs to their respective countries and flag high-risk regions.

### 3. Rules Engine Logic
Complete the implementation of `core/rules_engine.py` to dynamically load `rules.yaml` and apply logic for:
- Whitelisting processes.
- Threshold-based alerting.
- Severity scoring.

### 4. Persistence Layer
Implement a SQLite database handler to store historical alerts, allowing users to review logs after the application has been closed.

### 5. GUI Enhancements
- Tabbed view for Network vs. System logs.
- Visual counters for different severity levels.
- Alert filtering and search functionality.
