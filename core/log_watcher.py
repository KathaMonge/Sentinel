import threading
import time
import win32evtlog # type: ignore
import win32evtlogutil # type: ignore
import win32security # type: ignore
import win32api # type: ignore
from datetime import datetime
from core.models import Alert
import queue
from core.database import DatabaseManager
from core.state import AppState
import logging

class LogWatcherThread(threading.Thread):
    def __init__(self, alert_queue: queue.Queue, db_manager: DatabaseManager, app_state: AppState):
        super().__init__()
        self.alert_queue = alert_queue
        self.db_manager = db_manager
        self.app_state = app_state
        self.running = True
        self.daemon = True
        self.logger = logging.getLogger(__name__)
        self.last_record_number = 0
        self.retry_count = 0
        self.max_retries = 3

    def run(self):
        print("[*] Starting System Log Watcher...")
        self.logger.info("LogWatcher thread starting")
        
        # Feedback alert
        init_alert = Alert(
            timestamp=datetime.now(),
            alert_type="System",
            severity="Info",
            source="LogWatcher",
            message="System log monitoring initialized."
        )
        self.alert_queue.put(init_alert)
        self.db_manager.save_alert(init_alert)
        
        server = 'localhost'
        log_type = 'Security'
        
        while self.running:
            event_handle = None
            try:
                # Open the security log
                event_handle = win32evtlog.OpenEventLog(server, log_type)
                
                # Get the current record number to start from the end
                total_records = win32evtlog.GetNumberOfEventLogRecords(event_handle)
                self.last_record_number = total_records
                
                self.logger.info(f"Starting from record {self.last_record_number} of {total_records}")
                
                # Reset retry count on successful connection
                self.retry_count = 0
                
                while self.running:
                    if not self.app_state.monitoring_active:
                        time.sleep(1)
                        continue
                    
                    # Check for new records
                    current_total = win32evtlog.GetNumberOfEventLogRecords(event_handle)
                    
                    if current_total > self.last_record_number:
                        # Read new events
                        self._read_new_events(event_handle, current_total)
                    
                    time.sleep(2)  # Poll every 2 seconds
                
            except win32evtlog.error as e:
                self.logger.error(f"Windows Event Log error: {e}")
                self._handle_error(f"Event Log access error: {e}")
                
            except PermissionError as e:
                self.logger.error(f"Permission denied accessing Event Log: {e}")
                self._handle_error(f"Permission denied (requires admin): {e}")
                break  # No point retrying permission errors
                
            except Exception as e:
                self.logger.error(f"Unexpected error in LogWatcher: {e}")
                self._handle_error(f"Unexpected error: {e}")
                
            finally:
                if event_handle:
                    try:
                        win32evtlog.CloseEventLog(event_handle)
                    except:
                        pass
            
            # Retry logic with exponential backoff
            if self.running and self.retry_count < self.max_retries:
                self.retry_count += 1
                backoff_time = min(30, 2 ** self.retry_count)  # Max 30 seconds
                self.logger.info(f"Retrying in {backoff_time} seconds (attempt {self.retry_count}/{self.max_retries})")
                time.sleep(backoff_time)
            elif self.retry_count >= self.max_retries:
                self.logger.error("Max retries reached, stopping LogWatcher")
                break

    def _read_new_events(self, event_handle, current_total):
        """Read and process new events from the Event Log."""
        try:
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(event_handle, flags, self.last_record_number)
            
            for event in events:
                if not self.running:
                    break
                    
                self._process_event(event)
                self.last_record_number += 1
                
        except Exception as e:
            self.logger.error(f"Error reading events: {e}")
    
    def _process_event(self, event):
        """Process a single Windows Event Log entry."""
        try:
            event_id = event.EventID
            event_type = event.EventType
            source = event.SourceName
            time_generated = event.TimeGenerated
            
            # Convert Windows time to datetime
            event_time = datetime.fromtimestamp(time_generated)
            
            # Parse event data
            event_data = ""
            if event.StringInserts:
                event_data = " | ".join(event.StringInserts)
            
            # Check for specific security events
            severity = "Info"
            alert_type = "System"
            message = f"Event {event_id} from {source}"
            
            # Failed logon (4625)
            if event_id == 4625:
                severity = "Warning"
                alert_type = "Security"
                message = f"Failed logon attempt: {event_data}"
                self.app_state.alert_count += 1
            
            # Successful logon (4624)
            elif event_id == 4624:
                severity = "Info"
                alert_type = "Security"
                message = f"Successful logon: {event_data}"
            
            # Account lockout (4740)
            elif event_id == 4740:
                severity = "Warning"
                alert_type = "Security"
                message = f"Account locked out: {event_data}"
                self.app_state.alert_count += 1
            
            # Special privileges assigned (4672)
            elif event_id == 4672:
                severity = "Warning"
                alert_type = "Security"
                message = f"Special privileges assigned: {event_data}"
            
            # Process creation (4688)
            elif event_id == 4688:
                severity = "Info"
                alert_type = "Security"
                message = f"Process created: {event_data}"
            
            # Create alert
            alert = Alert(
                timestamp=event_time,
                alert_type=alert_type,
                severity=severity,
                source="LogWatcher",
                message=message
            )
            
            self.alert_queue.put(alert)
            self.db_manager.save_alert(alert)
            
            # Log high-severity events
            if severity in ["Warning", "Critical"]:
                self.db_manager.log_security_event(alert)
                
        except Exception as e:
            self.logger.error(f"Error processing event: {e}")
    
    def _handle_error(self, error_msg):
        """Handle errors by creating alerts and managing retry state."""
        try:
            error_alert = Alert(
                timestamp=datetime.now(),
                alert_type="System",
                severity="Warning",
                source="LogWatcher",
                message=error_msg
            )
            self.alert_queue.put(error_alert)
            self.db_manager.save_alert(error_alert)
        except Exception as e:
            self.logger.error(f"Failed to create error alert: {e}")

    def stop(self):
        self.running = False