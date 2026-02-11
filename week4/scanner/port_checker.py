#!/usr/bin/env python3
# port_checker.py
# Port status checking functions

def check_port_status(port):
    """
    Simulates checking if a port is open.
    In a real scanner, this would use socket connections.

    Parameters:
    - port: Port number to check

    Returns: "OPEN" or "CLOSED"
    """
    # Common ports that we'll simulate as open
    common_open_ports = [22, 80, 443, 3306, 8080]

    if port in common_open_ports:
        return "OPEN"
    else:
        return "CLOSED"


def is_privileged(port):
    """
    Checks if port is in privileged range (0-1023).

    Parameters:
    - port: Port number

    Returns: True if privileged, False otherwise
    """
    return 0 <= port <= 1023


def get_port_info(port):
    """
    Returns information about common ports.

    Parameters:
    - port: Port number

    Returns: Service name or "Unknown"
    """
    port_services = {
        20: "FTP Data",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP Alternate"
    }

    return port_services.get(port, "Unknown")