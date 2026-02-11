#!/usr/bin/env python3
# log_analyzer.py
# Analyzes firewall logs and generates JSON reports

import json
from collections import Counter

def parse_log_file(filename):
    """
    Parses firewall log file line by line.

    Returns: List of log entry dictionaries
    """
    log_entries = []

    with open(filename, 'r') as f:
        lines = f.readlines()

    for line in lines:
        # Skip empty lines
        if not line.strip():
            continue

        # Split line into components
        # Format: date time action source_ip dest_ip port
        parts = line.strip().split()

        if len(parts) >= 6:
            entry = {
                'date': parts[0],
                'time': parts[1],
                'action': parts[2],
                'source_ip': parts[3],
                'dest_ip': parts[4],
                'port': int(parts[5])
            }
            log_entries.append(entry)

    return log_entries


def analyze_logs(log_entries):
    """
    Analyzes parsed log entries for security insights.

    Returns: Dictionary with analysis results
    """
    # Count ALLOW vs DENY
    allow_count = 0
    deny_count = 0

    # Track denied source IPs
    denied_ips = set()

    # Track all denied ports for finding most targeted
    denied_ports = []

    # Track timestamps
    timestamps = []

    for entry in log_entries:
        # Count actions
        if entry['action'] == 'ALLOW':
            allow_count += 1
        elif entry['action'] == 'DENY':
            deny_count += 1
            denied_ips.add(entry['source_ip'])
            denied_ports.append(entry['port'])

        # Collect timestamps
        timestamps.append(f"{entry['date']} {entry['time']}")

    # Find most targeted port using Counter
    port_counter = Counter(denied_ports)
    most_targeted_port = None
    most_targeted_count = 0

    if port_counter:
        most_targeted_port, most_targeted_count = port_counter.most_common(1)[0]

    # Determine time range
    first_timestamp = timestamps[0] if timestamps else "N/A"
    last_timestamp = timestamps[-1] if timestamps else "N/A"

    return {
        'total_entries': len(log_entries),
        'allow_count': allow_count,
        'deny_count': deny_count,
        'denied_source_ips': sorted(list(denied_ips)),
        'most_targeted_port': most_targeted_port,
        'most_targeted_count': most_targeted_count,
        'time_range': {
            'first': first_timestamp,
            'last': last_timestamp
        }
    }


def save_json_report(analysis, filename):
    """
    Saves analysis results to JSON file.

    Parameters:
    - analysis: Analysis results dictionary
    - filename: Output JSON filename
    """
    with open(filename, 'w') as f:
        json.dump(analysis, f, indent=2)


def display_summary(analysis):
    """
    Displays analysis summary to terminal.
    """
    print("=" * 70)
    print("FIREWALL LOG ANALYSIS SUMMARY")
    print("=" * 70)
    print()

    print(f"📊 Total Log Entries: {analysis['total_entries']}")
    print()

    print(f"✅ ALLOW actions: {analysis['allow_count']}")
    print(f"🚫 DENY actions: {analysis['deny_count']}")

    # Calculate percentages
    total = analysis['total_entries']
    deny_pct = (analysis['deny_count'] / total * 100) if total > 0 else 0
    print(f"   ({deny_pct:.1f}% of traffic was denied)")
    print()

    print(f"🔒 Unique denied source IPs: {len(analysis['denied_source_ips'])}")
    print("   Blocked IPs:")
    for ip in analysis['denied_source_ips']:
        print(f"     - {ip}")
    print()

    if analysis['most_targeted_port']:
        port = analysis['most_targeted_port']
        count = analysis['most_targeted_count']

        # Identify common ports
        port_names = {
            22: "SSH",
            23: "Telnet",
            80: "HTTP",
            135: "RPC",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP"
        }
        port_name = port_names.get(port, "Unknown")

        print(f"🎯 Most targeted port: {port} ({port_name})")
        print(f"   Attacked {count} times")
        print()

    print(f"⏰ Time range:")
    print(f"   First entry: {analysis['time_range']['first']}")
    print(f"   Last entry:  {analysis['time_range']['last']}")
    print()

    print("=" * 70)


# Main program
if __name__ == "__main__":
    print()
    print("=" * 70)
    print("FIREWALL LOG ANALYZER")
    print("=" * 70)
    print()

    # Parse log file
    print("📖 Reading firewall.log...")
    log_entries = parse_log_file('firewall.log')
    print(f"✓ Parsed {len(log_entries)} log entries")
    print()

    # Analyze logs
    print("🔍 Analyzing firewall traffic patterns...")
    analysis = analyze_logs(log_entries)
    print("✓ Analysis complete")
    print()

    # Display summary
    display_summary(analysis)

    # Save JSON report
    print()
    print("💾 Saving analysis to log_analysis.json...")
    save_json_report(analysis, 'log_analysis.json')
    print("✓ JSON report saved successfully")
    print()