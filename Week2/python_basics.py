#!/usr/bin/env python3
# python_basics.py
# Demonstrates fundamental Python programming concepts

# ============================================
# SECTION 1: Variables and Data Types
# ============================================
print("="*50)
print("SECTION 1: Variables and Data Types")
print("="*50 + "\n")

# String variable
student_name = "Alex Thompson"
print(f"String variable: student_name = '{student_name}'")
print(f"Type: {type(student_name)}\n")

# Integer variable
port_number = 443
print(f"Integer variable: port_number = {port_number}")
print(f"Type: {type(port_number)}\n")

# Float variable
cpu_usage = 78.5
print(f"Float variable: cpu_usage = {cpu_usage}%")
print(f"Type: {type(cpu_usage)}\n")

# Boolean variable
is_secure = True
print(f"Boolean variable: is_secure = {is_secure}")
print(f"Type: {type(is_secure)}\n")

# List variable
common_ports = [21, 22, 23, 80, 443, 3389]
print(f"List variable: common_ports = {common_ports}")
print(f"Type: {type(common_ports)}")
print(f"Number of ports: {len(common_ports)}\n")

# ============================================
# SECTION 2: Conditional Statements
# ============================================
print("\n" + "="*50)
print("SECTION 2: Conditional Statements")
print("="*50 + "\n")

# Simple if statement
threat_level = 7

print(f"Threat level: {threat_level}/10")
if threat_level >= 8:
    print("Status: CRITICAL - Immediate action required!")
elif threat_level >= 5:
    print("Status: WARNING - Monitor closely")
elif threat_level >= 3:
    print("Status: CAUTION - Stay alert")
else:
    print("Status: NORMAL - No immediate threats")

# Nested conditionals
print("\nChecking port security...")
test_port = 22
if test_port in common_ports:
    print(f"Port {test_port} is commonly targeted")
    if test_port == 22:
        print("  → SSH port detected. Ensure strong authentication!")
    elif test_port == 23:
        print("  → TELNET port detected. Consider disabling (insecure)!")
    elif test_port == 3389:
        print("  → RDP port detected. Enable network-level authentication!")
else:
    print(f"Port {test_port} is not in common target list")

# ============================================
# SECTION 3: Loops
# ============================================
print("\n" + "="*50)
print("SECTION 3: Loops")
print("="*50 + "\n")

# For loop with list
print("Scanning common ports:")
for port in common_ports:
    print(f"  Checking port {port}...")

# For loop with range
print("\nCounting down to scan:")
for i in range(5, 0, -1):
    print(f"  {i}...")
print("  Scan started!")

# While loop
print("\nSimulating login attempts:")
attempts = 0
max_attempts = 3
while attempts < max_attempts:
    attempts += 1
    print(f"  Attempt {attempts}/{max_attempts}")
print("  Maximum attempts reached. Account locked.")

# ============================================
# SECTION 4: String Manipulation
# ============================================
print("\n" + "="*50)
print("SECTION 4: String Manipulation")
print("="*50 + "\n")

ip_address = "192.168.1.100"
print(f"Original IP: {ip_address}")
print(f"Upper case: {ip_address.upper()}")
print(f"Split by dots: {ip_address.split('.')}")
print(f"Starts with '192': {ip_address.startswith('192')}")
print(f"Contains '168': {'168' in ip_address}")

# ============================================
# SECTION 5: Functions
# ============================================
print("\n" + "="*50)
print("SECTION 5: Functions")
print("="*50 + "\n")

def calculate_risk_score(vulnerabilities, threat_level, patch_status):
    """
    Calculates a security risk score.

    Parameters:
    - vulnerabilities: number of known vulnerabilities
    - threat_level: threat level (1-10)
    - patch_status: "current" or "outdated"

    Returns: risk score (0-100)
    """
    base_score = vulnerabilities * 10
    threat_modifier = threat_level * 5
    patch_penalty = 20 if patch_status == "outdated" else 0

    risk_score = min(base_score + threat_modifier + patch_penalty, 100)
    return risk_score

# Test the function
vuln_count = 3
threat = 6
patches = "outdated"

score = calculate_risk_score(vuln_count, threat, patches)
print(f"System Risk Assessment:")
print(f"  Vulnerabilities: {vuln_count}")
print(f"  Threat Level: {threat}/10")
print(f"  Patch Status: {patches}")
print(f"  Risk Score: {score}/100")

if score >= 70:
    print("  ⚠️  HIGH RISK - Immediate remediation required!")
elif score >= 40:
    print("  ⚠️  MEDIUM RISK - Schedule updates soon")
else:
    print("  ✓ LOW RISK - Continue monitoring")

# ============================================
# SECTION 6: List Operations
# ============================================
print("\n" + "="*50)
print("SECTION 6: List Operations")
print("="*50 + "\n")

# Creating and modifying lists
allowed_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
print(f"Allowed IPs: {allowed_ips}")

# Adding to list
new_ip = "192.168.1.40"
allowed_ips.append(new_ip)
print(f"After adding {new_ip}: {allowed_ips}")

# Removing from list
removed_ip = "192.168.1.20"
allowed_ips.remove(removed_ip)
print(f"After removing {removed_ip}: {allowed_ips}")

# Checking if item in list
check_ip = "192.168.1.10"
if check_ip in allowed_ips:
    print(f"✓ {check_ip} is in the allowed list")
else:
    print(f"✗ {check_ip} is NOT in the allowed list")

# ============================================
# SUMMARY
# ============================================
print("\n" + "="*50)
print("SUMMARY: Python Basics Demonstrated")
print("="*50)
print("✓ Variables (string, int, float, boolean, list)")
print("✓ Conditional statements (if/elif/else)")
print("✓ Loops (for and while)")
print("✓ String manipulation")
print("✓ Functions with parameters and return values")
print("✓ List operations (append, remove, check membership)")
print("✓ Comments for code documentation")
print("="*50)