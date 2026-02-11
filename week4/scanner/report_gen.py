#!/usr/bin/env python3
# report_gen.py
# Report generation functions

import json

def generate_json_report(scan_data, filename):
    """
    Generates JSON report of scan results.

    Parameters:
    - scan_data: Dictionary containing scan results
    - filename: Output filename
    """
    with open(filename, 'w') as f:
        json.dump(scan_data, f, indent=2)

    print(f"✓ Report saved to {filename}")


def generate_text_summary(scan_data):
    """
    Generates human-readable text summary.

    Parameters:
    - scan_data: Dictionary containing scan results

    Returns: Formatted summary string
    """
    lines = []

    lines.append("\n" + "=" * 70)
    lines.append("SCAN SUMMARY")
    lines.append("=" * 70)

    lines.append(f"\nTarget IP: {scan_data['target_ip']}")
    lines.append(f"Scan Time: {scan_data['scan_time']}")
    lines.append(f"Port Range: {scan_data['port_range']['start']}-{scan_data['port_range']['end']}")

    lines.append(f"\nTotal Ports Scanned: {scan_data['total_scanned']}")
    lines.append(f"Open Ports Found: {len(scan_data['open_ports'])}")
    lines.append(f"Closed Ports: {scan_data['total_scanned'] - len(scan_data['open_ports'])}")

    if scan_data['open_ports']:
        lines.append("\n" + "-" * 70)
        lines.append("OPEN PORTS DETECTED")
        lines.append("-" * 70)

        for port_info in scan_data['open_ports']:
            port = port_info['port']
            service = port_info['service']
            privileged = "⚠️ PRIVILEGED" if port_info['privileged'] else ""

            lines.append(f"  Port {port:>5}: {service:20} {privileged}")

    lines.append("\n" + "=" * 70)

    return '\n'.join(lines)