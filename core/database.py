import sqlite3
import threading
from datetime import datetime
from core.models import Alert
import os

class DatabaseManager:
    def __init__(self, db_path="data/alerts.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        """Create the alerts table if it doesn't exist."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    alert_type TEXT,
                    severity TEXT,
                    source TEXT,
                    message TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    process_name TEXT,
                    process_id INTEGER,
                    country TEXT,
                    hit_count INTEGER
                )
            ''')
            conn.commit()
            conn.close()

    def save_alert(self, alert: Alert):
        """Save an alert to the database in a thread-safe manner."""
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO alerts (
                        timestamp, alert_type, severity, source, message,
                        src_ip, dst_ip, dst_port, process_name, process_id,
                        country, hit_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert.timestamp.isoformat(),
                    alert.alert_type,
                    alert.severity,
                    alert.source,
                    alert.message,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.dst_port,
                    alert.process_name,
                    alert.process_id,
                    alert.country,
                    alert.count
                ))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"[!] Database error: {e}")
