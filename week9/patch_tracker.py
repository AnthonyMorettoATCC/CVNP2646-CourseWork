import json

def load_inventory(filepath):
    with open(filepath, 'r') as f:
        hosts = json.load(f)
    return hosts

# Test
hosts = load_inventory('host_inventory.json')
print(f"Loaded {len(hosts)} hosts")
print(f"First host: {hosts[0]['hostname']}")
from datetime import datetime

def calculate_days_since_patch(host):
    # Parse the date string
    last_patch = datetime.strptime(
        host['last_patch_date'], 
        '%Y-%m-%d'
    )
    
    # Calculate difference
    delta = datetime.now() - last_patch
    
    # Return days as integer
    return delta.days
# Test
for host in hosts:
    days = calculate_days_since_patch(host)
    print(f"{host['hostname']} was last patched {days} days ago.")
def identify_outdated_hosts(hosts, threshold=30):
    outdated_hosts = []
    for host in hosts:
        days = calculate_days_since_patch(host)
        if days > threshold:
            outdated_hosts.append({
                'hostname': host['hostname'],
                'days_since_patch': days
            })
    return outdated_hosts
# Test
outdated = identify_outdated_hosts(hosts)
print(f"Hosts not patched in the last 30 days: {len(outdated)}")
for host in outdated:
    print(f"{host['hostname']} - {host['days_since_patch']} days since last patch")

def filter_by_os(hosts, os_type):
    """Case-insensitive partial match on OS field"""
    return [
        h for h in hosts 
        if os_type.lower() in h['os'].lower()
    ]

def filter_by_criticality(hosts, level):
    """Exact match on criticality"""
    return [h for h in hosts if h['criticality'] == level]

def filter_by_environment(hosts, env):
    """Exact match on environment"""
    return [h for h in hosts if h['environment'] == env]
# Test
linux_hosts = filter_by_os(hosts, 'linux')
print(f"Linux hosts: {len(linux_hosts)}")

windows_hosts = filter_by_os(hosts, 'windows')
print(f"Windows hosts: {len(windows_hosts)}")

critical_hosts = filter_by_criticality(hosts, 'critical')
print(f"Critical hosts: {len(critical_hosts)}")

prod_hosts = filter_by_environment(hosts, 'production')
print(f"Production hosts: {len(prod_hosts)}")

def calculate_risk_score(host):
    score = 0
    
    # Factor 1: Criticality (max 40 pts)
    criticality_points = {
        'critical': 40,
        'high': 25,
        'medium': 10,
        'low': 5
    }
    score += criticality_points.get(host['criticality'], 0)
    
    # Factor 2: Patch age (max 30 pts)
    days = host.get('days_since_patch', 0)
    if days > 90:
        score += 30
    elif days > 60:
        score += 20
    elif days > 30:
        score += 10
    # Factor 3: Environment (max 15 pts)
    env_points = {
        'production': 15,
        'staging': 8,
        'development': 3
    }
    score += env_points.get(host['environment'], 0)
    # Factor 4 & 5: Compliance tags (10 pts each)
    tags = host.get('tags', [])
    if 'pci-scope' in tags:
        score += 10
    if 'hipaa' in tags:
        score += 10
    # Factor 6: Internet-facing (15 pts)
    if 'internet-facing' in tags:
        score += 15
    
    return min(score, 100)  # Cap at 100
def get_risk_level(score):
    if score >= 70:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    else:
        return "low"
# Test
for host in hosts:
    host['days_since_patch'] = calculate_days_since_patch(host)
    host['risk_score'] = calculate_risk_score(host)
    host['risk_level'] = get_risk_level(host['risk_score'])
    print(f"{host['hostname']} - Risk Score: {host['risk_score']} ({host['risk_level']})")

from collections import Counter

risk_counts = Counter(h['risk_level'] for h in hosts)
print(f"Risk distribution: {risk_counts}")

def get_high_risk_hosts(hosts, threshold=50):
    # Filter hosts >= threshold
    high_risk = [h for h in hosts if h['risk_score'] >= threshold]
    
    # Sort by risk_score descending (highest first)
    high_risk.sort(key=lambda h: h['risk_score'], reverse=True)
    
    return high_risk

# Or using sorted() instead of .sort():
def get_high_risk_hosts(hosts, threshold=50):
    high_risk = [h for h in hosts if h['risk_score'] >= threshold]
    return sorted(high_risk, key=lambda h: h['risk_score'], reverse=True)
# Test
high_risk = get_high_risk_hosts(hosts)
print(f"High-risk hosts: {len(high_risk)}")
for host in high_risk[:5]:
    print(f"  {host['hostname']}: {host['risk_score']} ({host['risk_level']})")
import json
from datetime import datetime

def generate_json_report(hosts, high_risk_hosts):
    # Calculate risk distribution
    risk_dist = Counter(h['risk_level'] for h in hosts)
    
    report = {
        "report_date": datetime.now().isoformat(),
        "report_type": "High Risk Host Assessment",
        "total_hosts": len(hosts),
        "total_high_risk": len(high_risk_hosts),
        "risk_distribution": {
            "critical": risk_dist.get('critical', 0),
            "high": risk_dist.get('high', 0),
            "medium": risk_dist.get('medium', 0),
            "low": risk_dist.get('low', 0)
        },
        "high_risk_hosts": [
            {
                "hostname": h['hostname'],
                "risk_score": h['risk_score'],
                "risk_level": h['risk_level'],
                "days_since_patch": h['days_since_patch'],
                "criticality": h['criticality'],
                "environment": h['environment'],
                "tags": h.get('tags', [])
            }
            for h in high_risk_hosts
        ]
    }
    
    return json.dumps(report, indent=2)
# Test
report_json = generate_json_report(hosts, high_risk)
with open('high_risk_report.json', 'w') as f:
    f.write(report_json)

def generate_text_summary(hosts, high_risk_hosts):
    lines = []
    
    # Header
    lines.append("=" * 60)
    lines.append("     WEEKLY PATCH COMPLIANCE SUMMARY REPORT")
    lines.append("=" * 60)
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    
    # Executive summary
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 60)
    risk_dist = Counter(h['risk_level'] for h in hosts)
    critical_count = risk_dist.get('critical', 0)
    
    lines.append(f"Total Systems Analyzed:        {len(hosts)}")
    lines.append(f"High-Risk Systems Identified:  {len(high_risk_hosts)} ({len(high_risk_hosts)/len(hosts)*100:.1f}%)")
    lines.append(f"Critical Priority Systems:     {critical_count}")
    
    # Count systems >90 days unpatched
    very_old = sum(1 for h in hosts if h['days_since_patch'] > 90)
    lines.append(f"Immediate Action Required:     {very_old} systems >90 days unpatched")
    lines.append("")
    
    # Risk distribution
    lines.append("RISK DISTRIBUTION")
    lines.append("-" * 60)
    lines.append(f"Critical (>=70 points):         {risk_dist.get('critical', 0)} systems")
    lines.append(f"High (50-69 points):           {risk_dist.get('high', 0)} systems")
    lines.append(f"Medium (25-49 points):         {risk_dist.get('medium', 0)} systems")
    lines.append(f"Low (<25 points):              {risk_dist.get('low', 0)} systems")
    lines.append("")
    
    # Top 5 highest risk
    lines.append("TOP 5 HIGHEST RISK SYSTEMS")
    lines.append("-" * 60)
    for i, host in enumerate(high_risk_hosts[:5], 1):
        lines.append(f"{i}. {host['hostname']} (Score: {host['risk_score']}, {host['risk_level'].title()})")
        lines.append(f"   Last Patched: {host['days_since_patch']} days ago | {host['environment'].title()} | Tags: {', '.join(host.get('tags', []))}")
        lines.append("")
    
    # Recommended actions
    lines.append("RECOMMENDED ACTIONS")
    lines.append("-" * 60)
    lines.append("IMMEDIATE (Next 48 hours):")
    lines.append(f"• Patch {critical_count} critical-risk systems")
    lines.append("")
    lines.append("THIS WEEK (Next 7 days):")
    lines.append(f"• Schedule maintenance windows for {len(high_risk_hosts)} high-risk production systems")
    lines.append("")
    
    # Compliance notes
    lines.append("COMPLIANCE NOTES")
    lines.append("-" * 60)
    pci_count = sum(1 for h in hosts if 'pci-scope' in h.get('tags', []) and h['days_since_patch'] > 30)
    if pci_count > 0:
        lines.append(f"PCI-DSS: {pci_count} systems in PCI scope require immediate attention")
    lines.append("=" * 60)
    
    return "\n".join(lines)
# Test
text_report = generate_text_summary(hosts, high_risk)
with open('patch_summary.txt', 'w') as f:
    f.write(text_report)
print(text_report)  # Also print to console
