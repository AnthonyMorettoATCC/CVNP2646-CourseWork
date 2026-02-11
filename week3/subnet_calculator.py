#!/usr/bin/env python3
# subnet_calculator.py
# Calculates network information for IPv4 subnets

def calculate_subnet(network_ip, subnet_mask):
    """
    Calculates subnet information based on CIDR notation.

    Parameters:
    - network_ip: The network address (e.g., "192.168.1.0")
    - subnet_mask: CIDR notation (e.g., 24 for /24)

    Returns: Dictionary with subnet information
    """
    # Calculate total IP addresses using exponent operator
    # Formula: 2^(32 - subnet_mask)
    total_ips = 2 ** (32 - subnet_mask)

    # Usable hosts = total IPs - 2 (network and broadcast addresses)
    usable_hosts = total_ips - 2

    # Determine network class based on first octet
    first_octet = int(network_ip.split('.')[0])

    if 1 <= first_octet <= 127:
        network_class = "A"
    elif 128 <= first_octet <= 191:
        network_class = "B"
    elif 192 <= first_octet <= 223:
        network_class = "C"
    else:
        network_class = "Unknown"

    return {
        'network_ip': network_ip,
        'subnet_mask': subnet_mask,
        'total_ips': total_ips,
        'usable_hosts': usable_hosts,
        'network_class': network_class
    }


# Main program
print("=" * 60)
print("NETWORK SUBNET CALCULATOR")
print("=" * 60 + "\n")

# Test Case 1: /24 subnet (common for small networks)
print("Test Case 1: Common Small Network")
print("-" * 60)
result1 = calculate_subnet("192.168.1.0", 24)
print(f"Network Address: {result1['network_ip']}/{result1['subnet_mask']}")
print(f"Network Class: Class {result1['network_class']}")
print(f"Total IP Addresses: {result1['total_ips']:,}")
print(f"Usable Host IPs: {result1['usable_hosts']:,}")
print(f"Calculation: 2^(32-{result1['subnet_mask']}) = 2^{32-result1['subnet_mask']} = {result1['total_ips']}\n")

# Test Case 2: /28 subnet (smaller subnet for security segmentation)
print("Test Case 2: Security Segmented Subnet")
print("-" * 60)
result2 = calculate_subnet("10.0.10.0", 28)
print(f"Network Address: {result2['network_ip']}/{result2['subnet_mask']}")
print(f"Network Class: Class {result2['network_class']}")
print(f"Total IP Addresses: {result2['total_ips']}")
print(f"Usable Host IPs: {result2['usable_hosts']}")
print(f"Calculation: 2^(32-{result2['subnet_mask']}) = 2^{32-result2['subnet_mask']} = {result2['total_ips']}\n")

# Interactive mode
print("=" * 60)
print("INTERACTIVE MODE")
print("=" * 60)

# Get user input
network = input("\nEnter network IP address (e.g., 172.16.0.0): ")
mask = int(input("Enter subnet mask (CIDR notation, e.g., 24): "))

# Calculate and display results
result = calculate_subnet(network, mask)

print("\n" + "=" * 60)
print("SUBNET CALCULATION RESULTS")
print("=" * 60)
print(f"Network Address:    {result['network_ip']}/{result['subnet_mask']}")
print(f"Network Class:      Class {result['network_class']}")
print(f"Total IP Addresses: {result['total_ips']:,}")
print(f"Usable Host IPs:    {result['usable_hosts']:,}")
print(f"\nFormula: 2^(32-{result['subnet_mask']}) = {result['total_ips']}")
print("=" * 60)

# Security context
print("\n💡 Security Note:")
if result['total_ips'] > 256:
    print("   Large subnet - consider segmentation for security isolation")
elif result['total_ips'] <= 16:
    print("   Small subnet - good for critical infrastructure isolation")
else:
    print("   Medium subnet - suitable for departmental segmentation")