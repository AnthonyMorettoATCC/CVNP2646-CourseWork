#!/usr/bin/env python3
# threat_parser.py
# Parses JSON threat intelligence data and generates security reports

import json
from datetime import datetime

def load_threat_data(filename):
    """
    Loads threat intelligence data from JSON file.

    Parameters:
    - filename: Path to JSON file

    Returns: Parsed JSON data as dictionary
    """
    with open(filename, 'r') as f:
        data = json.load(f)
    return data


def analyze_threats(threat_data):
    """
    Analyzes threat data and generates statistics.

    Returns: Dictionary with analysis results
    """
    threats = threat_data['threats']

    # Count threats by severity
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0
    }

    # Collect all malicious IPs
    all_ips = []

    # Find active exploits
    active_exploits = []

    # Process each threat
    for threat in threats:
        # Count by severity
        severity = threat['severity']
        severity_counts[severity] += 1

        # Extract IPs
        ips = threat['indicators']['ips']
        all_ips.extend(ips)

        # Check for active exploits
        if threat['active_exploit']:
            active_exploits.append({
                'id': threat['id'],
                'type': threat['type'],
                'description': threat['description']
            })

    # Calculate percentage of CRITICAL threats
    total_threats = len(threats)
    critical_percentage = (severity_counts['CRITICAL'] / total_threats) * 100

    return {
        'total_threats': total_threats,
        'severity_counts': severity_counts,
        'unique_ips': list(set(all_ips)),  # Remove duplicates
        'total_ips': len(all_ips),
        'active_exploits': active_exploits,
        'critical_percentage': critical_percentage
    }


def generate_report(threat_data, analysis, output_file):
    """
    Generates a formatted text report and saves to file.

    Parameters:
    - threat_data: Original threat data
    - analysis: Analysis results dictionary
    - output_file: Path to output file
    """
    report_lines = []

    # Header
    report_lines.append("=" * 70)
    report_lines.append("THREAT INTELLIGENCE ANALYSIS REPORT")
    report_lines.append("=" * 70)
    report_lines.append(f"Feed: {threat_data['feed_name']}")
    report_lines.append(f"Date: {threat_data['date']}")
    report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("")

    # Summary statistics
    report_lines.append("-" * 70)
    report_lines.append("SUMMARY STATISTICS")
    report_lines.append("-" * 70)
    report_lines.append(f"Total Threats: {analysis['total_threats']}")
    report_lines.append(f"Total Malicious IPs: {analysis['total_ips']}")
    report_lines.append(f"Unique IPs: {len(analysis['unique_ips'])}")
    report_lines.append(f"Active Exploits: {len(analysis['active_exploits'])}")
    report_lines.append("")

    # Severity breakdown
    report_lines.append("-" * 70)
    report_lines.append("SEVERITY BREAKDOWN")
    report_lines.append("-" * 70)
    for severity, count in analysis['severity_counts'].items():
        if count > 0:
            report_lines.append(f"{severity:10}: {count} threats")
    report_lines.append(f"\nCRITICAL threats: {analysis['critical_percentage']:.1f}%")
    report_lines.append("")

    # Malicious IPs
    report_lines.append("-" * 70)
    report_lines.append("MALICIOUS IP ADDRESSES")
    report_lines.append("-" * 70)
    for ip in sorted(analysis['unique_ips']):
        report_lines.append(f"  - {ip}")
    report_lines.append("")

    # Active exploits
    report_lines.append("-" * 70)
    report_lines.append("ACTIVE EXPLOITS (IMMEDIATE ATTENTION REQUIRED)")
    report_lines.append("-" * 70)
    for exploit in analysis['active_exploits']:
        report_lines.append(f"\n{exploit['id']} ({exploit['type'].upper()})")
        report_lines.append(f"  Description: {exploit['description']}")
    report_lines.append("")

    # Footer
    report_lines.append("=" * 70)
    report_lines.append("END OF REPORT")
    report_lines.append("=" * 70)

    # Write to file using context manager
    with open(output_file, 'w') as f:
        f.write('\n'.join(report_lines))

    return report_lines


# Main program
if __name__ == "__main__":
    print("=" * 70)
    print("THREAT INTELLIGENCE PARSER")
    print("=" * 70)
    print()

    # Load threat data from JSON file
    print("📖 Loading threat data from threats.json...")
    threat_data = load_threat_data('threats.json')
    print(f"✓ Loaded {len(threat_data['threats'])} threats from {threat_data['feed_name']}")
    print()

    # Analyze the data
    print("🔍 Analyzing threat intelligence...")
    analysis = analyze_threats(threat_data)
    print("✓ Analysis complete")
    print()

    # Generate and save report
    print("📝 Generating security report...")
    report_lines = generate_report(threat_data, analysis, 'threat_report.txt')
    print("✓ Report saved to threat_report.txt")
    print()

    # Display report to terminal
    print("=" * 70)
    print("REPORT PREVIEW")
    print("=" * 70)
    for line in report_lines:
        print(line)