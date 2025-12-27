import os
import geoip2.database

class GeoIPManager:
    def __init__(self, db_path='data/geoip.mmdb'):
        self.db_path = db_path
        self.reader = None
        self.enabled = False
        
        if os.path.exists(self.db_path):
            try:
                self.reader = geoip2.database.Reader(self.db_path)
                self.enabled = True
                print(f"[*] GeoIP Database loaded from {self.db_path}")
            except Exception as e:
                print(f"[!] Failed to load GeoIP DB: {e}")
        else:
            print(f"[!] GeoIP Database not found at {self.db_path}. GeoIP features disabled.")

    def lookup(self, ip_address):
        """Returns country code (ISO) or 'Unknown'."""
        if not self.enabled or not self.reader:
            return "Unknown"
            
        # Skip local/private IPs
        if ip_address.startswith(("127.", "192.168.", "10.")):
             return "Local"

        try:
            response = self.reader.city(ip_address)
            return response.country.iso_code or "Unknown"
        except geoip2.errors.AddressNotFoundError:
            return "Unknown"
        except Exception as e:
            # print(f"[!] GeoIP lookup error: {e}")
            return "Error"

    def close(self):
        if self.reader:
            self.reader.close()
