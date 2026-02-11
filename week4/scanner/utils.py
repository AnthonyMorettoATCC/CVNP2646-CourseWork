#!/usr/bin/env python3
# utils.py
# Utility functions for security scanner

from datetime import datetime

def validate_ip(ip):
    """
    Validates IPv4 address format.

    Parameters:
    - ip: IP address string

    Returns: True if valid, False otherwise
    """
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False

        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False

        return True
    except (ValueError, AttributeError):
        return False


def get_timestamp():
    """
    Returns current timestamp as formatted string.

    Returns: Timestamp string in format "YYYY-MM-DD HH:MM:SS"
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def format_banner(text):
    """
    Creates a formatted banner for output.

    Parameters:
    - text: Text to display in banner

    Returns: Formatted banner string
    """
    width = 70
    border = "=" * width
    padding = " " * ((width - len(text)) // 2)

    return f"\n{border}\n{padding}{text}\n{border}\n"