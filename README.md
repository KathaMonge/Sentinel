# SentinelHIDS

**Local Host Intrusion & Privacy Monitoring System (Windows)**

SentinelHIDS is a lightweight, host-based intrusion detection system designed for Windows. It monitors network traffic and system events in real-time to detect suspicious activity and potential privacy leaks.

## 🚀 Features

- **Network Monitoring**: Captures outbound traffic to detect unencrypted HTTP (Port 80) and connections to high-risk regions.
- **System Event Monitoring**: Watches Windows Security Logs for failed logins and other suspicious patterns.
- **Real-Time Dashboard**: A modern, responsive GUI built with CustomTkinter for live alert viewing.
- **Local-First Privacy**: Operates entirely locally; no data is sent to external cloud services.
- **Rule-Based Engine**: YAML-driven rules for easy customization of alert thresholds.

## 🛠️ Tech Stack

- **Language**: Python 3.11+
- **GUI**: CustomTkinter
- **Network Capture**: PyShark (TShark engine)
- **Process Intelligence**: psutil
- **System Logs**: pywin32
- **Config**: YAML

## 📋 Prerequisites

SentinelHIDS requires specific Windows drivers and tools to function:

1.  **Npcap**: Install from [nmap.org/npcap](https://nmap.org/npcap/). During installation, check the box **"Install Npcap in WinPcap API-compatible Mode"**.
2.  **Wireshark / TShark**: Install from [wireshark.org](https://www.wireshark.org/). TShark is used as the underlying capture engine.
3.  **Administrator Privileges**: The application must be run from an Elevated/Admin terminal to access network drivers and Security Event Logs.

## 💻 Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/SentinelHIDS.git
    cd SentinelHIDS
    ```

2.  **Install Python dependencies**:
    ```bash
    python -m pip install -r requirements.txt
    ```

## 🏃 Usage

1.  Open **Command Prompt** or **PowerShell** as **Administrator**.
2.  Navigate to the project directory.
3.  Run the application:
    ```bash
    python main.py
    ```

## 📁 Project Structure

```text
SentinelHIDS/
├── main.py                 # Application entry point
├── core/
│   ├── sniffer.py          # Network capture thread
│   ├── log_watcher.py      # Event log monitoring thread
│   └── models.py           # Alert data structures
├── ui/
│   └── dashboard.py        # CustomTkinter GUI
├── data/
│   └── rules.yaml          # Detection rules (YAML)
├── docs/
│   └── PLANNING.md         # Detailed project roadmap
└── requirements.txt
```

## ⚠️ Troubleshooting

- **TShark not found**: Ensure Wireshark is installed and `tshark.exe` is in your system PATH.
- **Permission Denied**: Ensure you are running the terminal as Administrator.
- **Sniffer Crash**: Verify Npcap is installed and your network interface is active.

## ⚖️ License

Designed for defensive monitoring, auditing, and educational purposes.
