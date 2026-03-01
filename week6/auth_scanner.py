import json
import logging
from collections import Counter
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')

class AuthLogScanner:
    def __init__(self):
        self.events = []
        self.failed_by_user = Counter()
        self.failed_by_ip = Counter()
        self.total_success = 0
        self.total_fail = 0
        self.parse_errors = 0
    
    def parse_log_file(self, filepath):
        """Parse authentication log file and extract events."""
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    self._parse_line(line)
        except FileNotFoundError:
            logging.error(f"Log file not found: {filepath}")
        except Exception as e:
            logging.error(f"Error reading file: {e}")
    
    def _parse_line(self, line):
        """Parse a single log line."""
        try:
            parts = line.split()
            if len(parts) < 2:
                self.parse_errors += 1
                return
            
            timestamp = f"{parts[0]} {parts[1]}"
            kv_pairs = parts[2:]
            
            event_data = {'timestamp': timestamp}
            
            for pair in kv_pairs:
                if '=' not in pair:
                    continue
                key, value = pair.split('=', 1)
                event_data[key] = value
            
            # Validate required fields
            if 'event' not in event_data or 'status' not in event_data:
                self.parse_errors += 1
                return
            
            self.events.append(event_data)
            
            # Track statistics
            if event_data['status'] == 'SUCCESS':
                self.total_success += 1
            elif event_data['status'] == 'FAIL':
                self.total_fail += 1
                user = event_data.get('user', 'UNKNOWN')
                ip = event_data.get('ip', 'UNKNOWN')
                self.failed_by_user[user] += 1
                self.failed_by_ip[ip] += 1
        
        except Exception as e:
            logging.warning(f"Error parsing line: {line[:50]}... - {e}")
            self.parse_errors += 1
    
    def get_statistics(self):
        """Calculate and return statistics."""
        total_events = len(self.events)
        failure_rate = (self.total_fail / total_events * 100) if total_events > 0 else 0
        
        return {
            'total_events': total_events,
            'total_success': self.total_success,
            'total_fail': self.total_fail,
            'failure_rate': round(failure_rate, 2),
            'parse_errors': self.parse_errors,
            'top_targeted_users': self.failed_by_user.most_common(5),
            'top_attacking_ips': self.failed_by_ip.most_common(5)
        }
    
    def generate_json_report(self, analyst_name="Analyst", classification="INTERNAL"):
        """Generate JSON report."""
        stats = self.get_statistics()
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'analyst': analyst_name,
                'classification': classification
            },
            'summary': {
                'total_events': stats['total_events'],
                'total_success': stats['total_success'],
                'total_fail': stats['total_fail'],
                'failure_rate': stats['failure_rate'],
                'parse_errors': stats['parse_errors']
            },
            'top_targeted_users': [
                {'username': user, 'failed_attempts': count}
                for user, count in stats['top_targeted_users']
            ],
            'top_attacking_ips': [
                {'ip_address': ip, 'failed_attempts': count}
                for ip, count in stats['top_attacking_ips']
            ]
        }
        return json.dumps(report, indent=2)
    
    def generate_text_report(self, analyst_name="Analyst"):
        """Generate human-readable text report."""
        stats = self.get_statistics()
        report = []
        report.append("=" * 70)
        report.append("AUTHENTICATION LOG SECURITY INCIDENT REPORT")
        report.append("=" * 70)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Analyst: {analyst_name}")
        report.append("")
        
        report.append("SUMMARY STATISTICS")
        report.append("-" * 70)
        report.append(f"Total Events Processed:     {stats['total_events']}")
        report.append(f"Successful Logins:          {stats['total_success']}")
        report.append(f"Failed Logins:              {stats['total_fail']}")
        report.append(f"Failure Rate:               {stats['failure_rate']}%")
        report.append(f"Parsing Errors:             {stats['parse_errors']}")
        report.append("")
        
        report.append("TOP 5 TARGETED USER ACCOUNTS")
        report.append("-" * 70)
        if stats['top_targeted_users']:
            for rank, (user, count) in enumerate(stats['top_targeted_users'], 1):
                report.append(f"{rank}. {user:20} - {count} failed attempts")
        else:
            report.append("No failed login attempts detected.")
        report.append("")
        
        report.append("TOP 5 ATTACKING IP ADDRESSES")
        report.append("-" * 70)
        if stats['top_attacking_ips']:
            for rank, (ip, count) in enumerate(stats['top_attacking_ips'], 1):
                report.append(f"{rank}. {ip:20} - {count} failed attempts")
        else:
            report.append("No failed login attempts detected.")
        report.append("")
        report.append("=" * 70)
        
        return "\n".join(report)
    
    def save_reports(self, output_dir=".", analyst_name="Analyst", classification="INTERNAL"):
        """Save both JSON and text reports to files."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save JSON report
        json_file = output_path / "incident_report.json"
        with open(json_file, 'w') as f:
            f.write(self.generate_json_report(analyst_name, classification))
        print(f"JSON report saved: {json_file}")
        
        # Save text report
        txt_file = output_path / "incident_report.txt"
        with open(txt_file, 'w') as f:
            f.write(self.generate_text_report(analyst_name))
        print(f"Text report saved: {txt_file}")


def main():
    """Main execution function."""
    scanner = AuthLogScanner()
    
    # Parse log file (adjust path as needed)
    log_file = "auth.log"
    scanner.parse_log_file(log_file)
    
    # Generate and save reports
    scanner.save_reports(analyst_name="Anthony Moretto", classification="INTERNAL")
    
    # Print text report to console
    print("\n" + scanner.generate_text_report("Anthony Moretto"))


if __name__ == "__main__":
    main()