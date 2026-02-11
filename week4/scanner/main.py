#!/usr/bin/env python3
# main.py
# Main security scanner program - imports and uses all modules

# Import functions from our custom modules
from utils import validate_ip, get_timestamp, format_banner
from port_checker import check_port_status, is_privileged, get_port_info
from report_gen import generate_json_report, generate_text_summary


def scan_ports(target_ip, start_port, end_port):
    """
    Scans a range of ports on target IP.

    Parameters:
    - target_ip: IP address to scan
    - start_port: First port in range
    - end_port: Last port in range

    Returns: Scan results dictionary
    """
    print(f"\n🔍 Scanning {target_ip} ports {start_port}-{end_port}...")
    print(f"⏰ Scan started at {get_timestamp()}")
    print()

    open_ports = []
    total_scanned = 0

    for port in range(start_port, end_port + 1):
        total_scanned += 1
        status = check_port_status(port)

        if status == "OPEN":
            port_data = {
                'port': port,
                'status': status,
                'service': get_port_info(port),
                'privileged': is_privileged(port)
            }
            open_ports.append(port_data)

            # Display open port immediately
            priv_marker = "⚠️" if is_privileged(port) else "✓"
            print(f"{priv_marker} Port {port:>5}: {status:6} - {get_port_info(port)}")

    scan_data = {
        'target_ip': target_ip,
        'scan_time': get_timestamp(),
        'port_range': {
            'start': start_port,
            'end': end_port
        },
        'total_scanned': total_scanned,
        'open_ports': open_ports
    }

    return scan_data


def main():
    """
    Main program entry point.
    """
    # Display banner
    print(format_banner("SECURITY PORT SCANNER"))

    # Get target IP
    target_ip = input("Enter target IP address to scan: ")

    # Validate IP
    if not validate_ip(target_ip):
        print(f"\n❌ Error: '{target_ip}' is not a valid IP address")
        print("   Example valid IP: 192.168.1.1")
        return

    print(f"✓ Valid IP address: {target_ip}")

    # Define port range
    start_port = 20
    end_port = 100

    # Perform scan
    scan_data = scan_ports(target_ip, start_port, end_port)

    # Display text summary
    summary = generate_text_summary(scan_data)
    print(summary)

    # Generate JSON report
    report_filename = f"scan_report_{scan_data['target_ip'].replace('.', '_')}.json"
    generate_json_report(scan_data, report_filename)

    print(f"\n✅ Scan complete! {len(scan_data['open_ports'])} open ports found.")


# Run main program
if __name__ == "__main__":
    main()