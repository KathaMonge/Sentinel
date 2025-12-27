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

    def get_recent_alerts(self, limit=100):
        """Retrieve the most recent alerts from the database."""
        alerts = []
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT timestamp, alert_type, severity, source, message,
                           src_ip, dst_ip, dst_port, process_name, process_id,
                           country, hit_count
                    FROM alerts ORDER BY id DESC LIMIT ?
                ''', (limit,))
                rows = cursor.fetchall()
                for row in reversed(rows): # Return in chronological order
                    alert = Alert(
                        timestamp=datetime.fromisoformat(row[0]),
                        alert_type=row[1],
                        severity=row[2],
                        source=row[3],
                        message=row[4],
                        src_ip=row[5],
                        dst_ip=row[6],
                        dst_port=row[7],
                        process_name=row[8],
                        process_id=row[9],
                        country=row[10],
                        count=row[11]
                    )
                    alerts.append(alert)
                conn.close()
            except Exception as e:
                print(f"[!] Database retrieval error: {e}")
        return alerts
