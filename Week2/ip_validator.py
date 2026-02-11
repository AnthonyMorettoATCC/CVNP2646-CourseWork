#!/usr/bin/env python3
# ip_validator.py
# Validates IPv4 addresses

def validate_ip(ip_address):
    """
    Validates an IPv4 address.
    Returns True if valid, False otherwise.

    A valid IPv4 has:
    - Exactly 4 parts separated by dots
    - Each part is a number between 0-255
    """
    try:
        # Split the IP address by dots
        parts = ip_address.split('.')

        # Check if we have exactly 4 parts
        if len(parts) != 4:
            return False

        # Check each part
        for part in parts:
            # Convert to integer
            num = int(part)

            # Check if in valid range (0-255)
            if num < 0 or num > 255:
                return False

        # All checks passed
        return True

    except ValueError:
        # If conversion to int fails, it's invalid
        return False


# Main program - Test the function
print("=== IP Address Validator ===\n")

# Test cases
test_ips = [
    "192.168.1.1",      # Valid
    "10.0.0.255",       # Valid
    "256.1.1.1",        # Invalid - 256 is out of range
    "192.168.1",        # Invalid - only 3 parts
    "192.168.1.1.1",    # Invalid - 5 parts
    "abc.def.ghi.jkl"   # Invalid - not numbers
]

print("Testing IP addresses:\n")
for ip in test_ips:
    result = validate_ip(ip)
    status = "✓ VALID" if result else "✗ INVALID"
    print(f"{ip:20} → {status}")

# Interactive mode
print("\n" + "="*40)
user_ip = input("\nEnter an IP address to validate: ")
if validate_ip(user_ip):
    print(f"✅ {user_ip} is a VALID IPv4 address!")
else:
    print(f"❌ {user_ip} is NOT a valid IPv4 address.")