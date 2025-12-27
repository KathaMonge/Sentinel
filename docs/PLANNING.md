# Project Planning and Roadmap

## Project Objective
The objective of **SentinelHIDS** is to build a local, host-based intrusion detection system (HIDS) for Windows. The system provides real-time visibility into network and system security events without compromising user privacy. It serves as a defensive monitoring tool for auditing, education, and personal host security.

## Current Project Status
The project has successfully transitioned from initial scaffolding to a functional alpha version.

- **Phase 1: Core Architecture (Complete)**: Implemented a thread-safe `queue.Queue` system for inter-thread communication. The `main.py` script acts as the orchestrator, managing the lifecycle of background monitoring threads and the GUI main loop.
- **Phase 2: Network Monitoring (Functional Alpha)**: Integrated PyShark for live packet capture. Currently detects outbound traffic on Port 80 (HTTP). Handles asynchronous event loop issues within dedicated threads.
- **Phase 3: System Monitoring (Functional Alpha)**: Established the structure for monitoring Windows Security Logs using `pywin32`. Implemented basic privilege checks and feedback loops to the UI.
- [x] Phase 4: Graphical User Interface (Functional)**: Developed a modern Dark-Mode dashboard using CustomTkinter. The UI successfully polls the alert queue and updates the display without freezing the main thread.
- [x] Phase 5: Operational Intelligence & UI Refinement (Complete)**:
  - **Process Correlation**: Integrated `psutil` to map network flows to local executables.
  - **GeoIP Integration**: Resolved destination IPs to country codes.
  - **Log Intelligence**: Implemented columnar normalization, temporal aggregation (deduplication), and semantic noise suppression.
  - **Analytics UI**: Created a multi-view dashboard with live stats (Overview, Network, System) and optimized columnar alignment.

## Success Definition and Key Performance Indicators (KPIs)
We measure the implementation success against the following standardized metrics:

1. **System Stability**: Continuous operation for over 4 hours without memory leaks or thread crashes (specifically PyShark/TShark subprocesses).
2. **Alert Latency**: Average time from event occurrence (packet capture or log entry) to GUI display must remain under 1 second. To prove this, the system logs both "Timestamp of Capture" and "Timestamp of Display".
3. **Resource Efficiency**: CPU usage must remain below 5% on a standard modern workstation. To achieve this while using TShark, the system includes a "Sampling Mode" toggle and "Noise Suppression" to reduce processing overhead.
4. **Data Density**: Achieve a minimum 60% reduction in UI log row count via temporal aggregation (deduplication).
5. **Usability**: Rules must be modifiable via `rules.yaml` with an instantaneous effect.

## Detailed Roadmap for Future Implementation

### Phase 5: Operational Intelligence (Complete)
- **Process & GeoIP Mapping**: Successfully correlating traffic to processes and locations.
- **Noise Suppression**: Implemented filtering for background protocols (SSDP, mDNS).
- **Advanced UI**: Overview dashboard with live packet and alert counters.

### Phase 6: Logic and Persistence
- **Advanced Rules Engine**: Implement `core/rules_engine.py`. This module will parse `rules.yaml` and provide a `check_alert(alert)` method. Logic will include severity scoring (0-10) and white-listing of trusted system processes to reduce noise.
- **SQLite Persistence**: Implement `core/database.py`. All generated alerts will be stored in a local `alerts.db` file. This allows for historical analysis, session-to-session persistence, and future reporting features.

### Phase 7: UI/UX & Rules Refinement
- **Rules Customization**: Enable dynamic rule reloading from the GUI.
- **Visual Analytics**: Add lightweight charts for historical alert trends using canvas elements.

## Technical Challenges and Mitigations
- **Challenge**: PyShark's dependency on TShark can lead to orphan processes.
  - **Mitigation**: Implement strict `capture.close()` in the `finally` block of the sniffer thread and use `daemon=True` for monitoring threads.
- **Challenge**: Windows Security Log access is restricted.
  - **Mitigation**: The application performs an `IsUserAnAdmin()` check on startup and provides clear feedback to the user if privileges are insufficient.
- **Challenge**: Correlating packets to processes in real-time is performance-heavy.
  - **Mitigation**: Use a caching mechanism for process lookups and limit mapping to only "Suspicious" packets rather than every single IP packet.

## Ethical and Security Constraints
- **Passive Only**: The system does not block or modify traffic; it only monitors and alerts.
- **Local Data**: All captured metadata stays on the host machine.
- **Consent**: Designed for use by the owner of the machine for defensive purposes only.
