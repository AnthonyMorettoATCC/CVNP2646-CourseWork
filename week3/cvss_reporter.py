#!/usr/bin/env python3
# cvss_reporter.py
# Reports vulnerability severity based on CVSS scores

def categorize_cvss(cvss_score, vulnerability_name):
    """
    Categorizes CVSS score and generates a vulnerability report.

    CVSS Severity Ratings:
    - CRITICAL: 9.0 - 10.0
    - HIGH: 7.0 - 8.9
    - MEDIUM: 4.0 - 6.9
    - LOW: 0.1 - 3.9
    - NONE: 0.0

    Parameters:
    - cvss_score: Float between 0.0 and 10.0
    - vulnerability_name: Name/description of the vulnerability

    Returns: Dictionary with severity information
    """
    # Convert score to percentage
    score_percentage = (cvss_score / 10.0) * 100

    # Determine severity category using comparison operators
    if cvss_score >= 9.0:
        severity = "CRITICAL"
        priority = "P1 - Immediate Action Required"
        color_indicator = "🔴"
    elif cvss_score >= 7.0:
        severity = "HIGH"
        priority = "P2 - Urgent Remediation"
        color_indicator = "🟠"
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
        priority = "P3 - Schedule Fix"
        color_indicator = "🟡"
    elif cvss_score > 0.0:
        severity = "LOW"
        priority = "P4 - Monitor"
        color_indicator = "🟢"
    else:
        severity = "NONE"
        priority = "P5 - Informational"
        color_indicator = "⚪"

    return {
        'vulnerability': vulnerability_name,
        'score': cvss_score,
        'percentage': score_percentage,
        'severity': severity,
        'priority': priority,
        'indicator': color_indicator
    }


def print_vulnerability_report(vuln_data):
    """Prints a formatted vulnerability report."""
    print("\n" + "=" * 70)
    print(f"{vuln_data['indicator']} VULNERABILITY REPORT")
    print("=" * 70)
    print(f"Vulnerability:    {vuln_data['vulnerability']}")
    print(f"CVSS Score:       {vuln_data['score']:.1f} / 10.0")
    print(f"Score Percentage: {vuln_data['percentage']:.1f}%")
    print(f"Severity Level:   {vuln_data['severity']}")
    print(f"Priority:         {vuln_data['priority']}")
    print("=" * 70)


# Main program
print("=" * 70)
print("CVSS VULNERABILITY SEVERITY REPORTER")
print("=" * 70)

# Test Case 1: CRITICAL severity
print("\n--- Test Case 1: Critical Vulnerability ---")
vuln1 = categorize_cvss(9.8, "CVE-2024-1234: Remote Code Execution")
print_vulnerability_report(vuln1)

# Test Case 2: MEDIUM severity
print("\n--- Test Case 2: Medium Severity Vulnerability ---")
vuln2 = categorize_cvss(5.3, "CVE-2024-5678: Information Disclosure")
print_vulnerability_report(vuln2)

# Test Case 3: LOW severity
print("\n--- Test Case 3: Low Severity Vulnerability ---")
vuln3 = categorize_cvss(2.1, "CVE-2024-9012: Local Privilege Escalation")
print_vulnerability_report(vuln3)

# Interactive mode
print("\n\n" + "=" * 70)
print("INTERACTIVE MODE - Enter Your Own Vulnerability Data")
print("=" * 70)

vuln_name = input("\nEnter vulnerability name/CVE: ")
score = float(input("Enter CVSS score (0.0 - 10.0): "))

# Validate score range
if 0.0 <= score <= 10.0:
    vuln_data = categorize_cvss(score, vuln_name)
    print_vulnerability_report(vuln_data)

    # Additional context
    print(f"\n📊 Analysis:")
    if vuln_data['severity'] == "CRITICAL":
        print("   ⚠️  This vulnerability poses an immediate threat to systems.")
        print("   ⚠️  Patch or mitigate within 24 hours.")
    elif vuln_data['severity'] == "HIGH":
        print("   ⚠️  This vulnerability should be addressed urgently.")
        print("   ⚠️  Patch or mitigate within 7 days.")
    elif vuln_data['severity'] == "MEDIUM":
        print("   ℹ️  Schedule remediation in the next maintenance window.")
    else:
        print("   ℹ️  Monitor and address as resources allow.")
else:
    print("\n❌ Error: CVSS score must be between 0.0 and 10.0")