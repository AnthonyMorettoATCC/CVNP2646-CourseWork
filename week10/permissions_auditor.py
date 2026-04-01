import json

def load_json(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

# Test both loads
users_data = load_json('users.json')
roles_data = load_json('roles.json')

print(f"Loaded {len(users_data)} users")
print(f"Loaded {len(roles_data)} role assignments")
print(f"First user: {users_data[0]}")

def build_user_lookup(users_data):
    """Create dictionary keyed by user_id for fast lookups."""
    return {user['user_id']: user for user in users_data}

# Build once, use many times
users_dict = build_user_lookup(users_data)

# Test: Look up specific user
user = users_dict['U001']
print(f"{user['username']} is in {user['department']}")

from collections import defaultdict

def group_roles_by_user(roles_data):
    """Group all roles for each user using defaultdict."""
    user_roles = defaultdict(list)
    
    for role_entry in roles_data:
        user_id = role_entry['user_id']
        user_roles[user_id].append(role_entry['role'])
    
    return dict(user_roles)  # Convert back to regular dict

# Test
user_roles = group_roles_by_user(roles_data)
print(f"U002 has roles: {user_roles['U002']}")  # ['hr_manager', 'admin']
print(f"U999 has roles: {user_roles.get('U999', [])}")  # [] (user doesn't exist)

def check_user_permissions(users_dict, user_roles):
    """Check if users have permissions that don't match their department."""
    for user_id, roles in user_roles.items():
        user = users_dict.get(user_id)
        if not user:
            print(f"Warning: User ID {user_id} in roles but not in users data.")
            continue
        
        department = user['department']
        
        # Define expected permissions based on department
        expected_permissions = {
            'engineering': {'developer', 'admin'},
            'hr': {'hr_manager', 'admin'},
            'sales': {'sales_rep', 'admin'}
        }
        
        allowed_roles = expected_permissions.get(department, set())
        
        for role in roles:
            if role not in allowed_roles:
                print(f"User {user['username']} (ID: {user_id}) has role '{role}' which is not allowed for department '{department}'.")
# Run the permission check
check_user_permissions(users_dict, user_roles)

def check_disabled_with_roles(users_dict, roles_data):
    violations = []
    
    # Build set of user_ids with roles (O(n) once)
    users_with_roles = {r['user_id'] for r in roles_data}
    
    # Check each disabled user (O(m) where m = # users)
    for user_id, user in users_dict.items():
        if user['status'] == 'disabled' and user_id in users_with_roles:
            # Find all roles for this user
            user_roles = [r['role'] for r in roles_data if r['user_id'] == user_id]
            
            violations.append({
                'user_id': user_id,
                'username': user['username'],
                'violation_type': 'disabled_with_roles',
                'severity': 'CRITICAL',
                'details': f"Disabled account has {len(user_roles)} active role(s): {', '.join(user_roles)}"
            })
    
    return violations
# Run the check and print violations
violations = check_disabled_with_roles(users_dict, roles_data)
for violation in violations:
    print(f"[{violation['severity']}] {violation['username']} ({violation['user_id']}): {violation['details']}")

def check_unauthorized_admins(users_dict, roles_data, authorized_depts={'IT', 'Security'}):
    violations = []
    
    for role_entry in roles_data:
        # Check if role contains "admin" (case-insensitive)
        if 'admin' in role_entry['role'].lower():
            user_id = role_entry['user_id']
            
            # Look up user's department
            if user_id in users_dict:
                user = users_dict[user_id]
                
                # Flag if department not authorized
                if user['department'] not in authorized_depts:
                    violations.append({
                        'user_id': user_id,
                        'username': user['username'],
                        'violation_type': 'unauthorized_admin',
                        'severity': 'HIGH',
                        'details': f"{user['department']} dept user has admin role: {role_entry['role']}",
                        'department': user['department'],
                        'role': role_entry['role']
                    })
    
    return violations
# Run the check and print violations
admin_violations = check_unauthorized_admins(users_dict, roles_data)
for violation in admin_violations:
    print(f"[{violation['severity']}] {violation['username']} ({violation['user_id']}): {violation['details']}")

from datetime import datetime, timedelta

def check_stale_accounts(users_dict, stale_days=90):
    violations = []
    cutoff_date = datetime.now() - timedelta(days=stale_days)
    
    for user_id, user in users_dict.items():
        # Only check active accounts
        if user['status'] != 'active':
            continue
        
        last_login_str = user.get('last_login')
        
        if not last_login_str:
            # No login date recorded
            violations.append({
                'user_id': user_id,
                'username': user['username'],
                'violation_type': 'stale_account',
                'severity': 'MEDIUM',
                'details': 'Active account with no recorded login date',
                'last_login': None
            })
        else:
            # Parse date and check threshold
            last_login = datetime.strptime(last_login_str, '%Y-%m-%d')
            
            if last_login < cutoff_date:
                days_since = (datetime.now() - last_login).days
                violations.append({
                    'user_id': user_id,
                    'username': user['username'],
                    'violation_type': 'stale_account',
                    'severity': 'MEDIUM',
                    'details': f"No login for {days_since} days (last: {last_login_str})",
                    'last_login': last_login_str,
                    'days_inactive': days_since
                })
    
    return violations
# Run the check and print violations
stale_violations = check_stale_accounts(users_dict)
for violation in stale_violations:
    print(f"[{violation['severity']}] {violation['username']} ({violation['user_id']}): {violation['details']}")

def generate_json_report(all_violations, users_dict, roles_data):
    # Calculate summary statistics
    severity_counts = {}
    type_counts = {}
    
    for v in all_violations:
        # Count by severity
        sev = v['severity']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Count by type
        vtype = v['violation_type']
        type_counts[vtype] = type_counts.get(vtype, 0) + 1
    
    # Build report structure
    report = {
        'audit_metadata': {
            'timestamp': datetime.now().isoformat(),
            'total_users_audited': len(users_dict),
            'total_role_assignments': len(roles_data),
            'total_violations': len(all_violations),
            'auditor': 'IAM Audit System v1.0'
        },
        'violation_summary': {
            'by_severity': severity_counts,
            'by_type': type_counts
        },
        'all_violations': all_violations
    }
    
    return json.dumps(report, indent=2)

def generate_text_report(all_violations, users_dict, roles_data):
    lines = []
    lines.append("=" * 80)
    lines.append("USER ACCOUNT & PERMISSIONS AUDIT REPORT")
    lines.append("=" * 80)
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    
    # Executive summary
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 80)
    lines.append(f"Total Users Audited: {len(users_dict)}")
    lines.append(f"Total Violations Found: {len(all_violations)}")
    lines.append("")
    
    # Violations by severity (with visual bars)
    severity_counts = {}
    for v in all_violations:
        sev = v['severity']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    lines.append("VIOLATIONS BY SEVERITY")
    lines.append("-" * 80)
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = severity_counts.get(severity, 0)
        bar = "█" * count
        lines.append(f"{severity:12s} [{count:3d}] {bar}")
    
    # ... detailed violations sections ...
    
    return "\n".join(lines)
# Generate and print reports
all_violations = violations + admin_violations + stale_violations

# Generate reports
json_report = generate_json_report(all_violations, users_dict, roles_data)
text_report = generate_text_report(all_violations, users_dict, roles_data)

# Save JSON report
with open('audit_report.json', 'w', encoding='utf-8') as f:
    f.write(json_report)
print("\n✓ JSON report saved to audit_report.json")

# Save text report
with open('audit_report.txt', 'w', encoding='utf-8') as f:
    f.write(text_report)
print("✓ Text report saved to audit_report.txt")
print("\nAudit complete!")