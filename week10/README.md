# User Account & Permissions Auditor

## 1. Overview

### What Does This Auditor Do?

The **User Account & Permissions Auditor** is an Identity Access Management (IAM) security tool that automatically scans user accounts and role assignments to identify permission violations and security misconfigurations. It performs comprehensive audits by:

- Loading user account data and role assignment records
- Cross-referencing account status with active permissions
- Detecting unauthorized role assignments
- Identifying stale or inactive accounts with potential orphaned access
- Generating both structured (JSON) and human-readable (TXT) audit reports

### Why Is IAM Auditing Critical for Security?

Identity and Access Management (IAM) auditing is fundamental to cybersecurity because:

1. **Principle of Least Privilege**: Users should only have the minimum permissions needed for their job. Auditing ensures permissions don't exceed this principle.

2. **Account Lifecycle Risk**: Disabled or inactive accounts that still retain permissions create "zombie accounts" that can be exploited if compromised.

3. **Insider Threats**: Regular audits detect unauthorized privilege escalation or role creep that could indicate malicious activity or misconfiguration.

4. **Compliance Requirements**: Regulatory standards (SOC 2, PCI-DSS, HIPAA, ISO 27001) mandate regular access reviews and audit trails.

5. **Rapid Incident Response**: When a breach occurs, audit logs identify exactly what access was available during the incident window.

6. **Risk Quantification**: Permission audits provide metrics (# of violations, severity distribution) to justify security investments.

---

## 2. Data Relationship

### Dataset Structure

This auditor works with two interconnected datasets:

#### **users.json** (Master User Records)
Primary key: `user_id`

```json
{
  "user_id": "U001",
  "username": "jdoe",
  "status": "active",           // "active" or "disabled"
  "department": "IT",
  "last_login": "2026-03-07"
}
```

**Key Fields:**
- `user_id`: Unique identifier (primary key)
- `status`: Account state ("active" or "disabled")
- `department`: Organizational unit
- `last_login`: ISO 8601 date of last authentication

#### **roles.json** (Role Assignments)
Foreign key: `user_id`

```json
{
  "user_id": "U001",
  "role": "admin",
  "assigned_date": "2025-01-15"
}
```

**Key Fields:**
- `user_id`: Reference to users.json (foreign key)
- `role`: Permission level or responsibility name
- `assigned_date`: When the role was granted

### Data Joining Strategy: Dictionary Lookups

The auditor uses **O(1) hash-based dictionary lookups** instead of nested loops:

```python
# EFFICIENT: Build lookup once, O(1) access per query
users_dict = {user['user_id']: user for user in users_data}
user = users_dict['U001']  # O(1) constant time

# INEFFICIENT: Would require O(n) linear scan per query
# for user in users_data:
#     if user['user_id'] == 'U001':
#         return user
```

**Performance Comparison:**

| Approach | Time Complexity | Use Case |
|----------|---|---|
| Dictionary lookup | O(1) per access | Fast repeated queries (auditing) |
| List iteration | O(n) per access | Small datasets, one-time queries |
| Building: Dict comprehension | O(n) once | Amortized O(1) total cost |

For 10,000 users with 15,000 role assignments, the dictionary approach saves ~140 million operations versus nested loops.

---

## 3. Detection Rules

The auditor implements three violation detection rules with escalating severity:

### Rule 1: Disabled Accounts with Active Roles (CRITICAL)

**Severity:** 🔴 **CRITICAL**

**What it detects:** Accounts marked as "disabled" that still have role assignments.

**Why it matters:**
- Disabled accounts should have zero permissions (account is supposed to be deactivated)
- Active roles on disabled accounts can be exploited if account re-enabled or if credentials leaked
- Indicates incomplete user offboarding process

**Detection Logic:**
```python
if user['status'] == 'disabled' and user_id in roles_assigned:
    flag_violation("disabled_with_roles")
```

**Remediation:**
- Remove all roles from disabled accounts immediately
- Verify account deactivation in all systems
- Review account creation/deletion audit logs

---

### Rule 2: Unauthorized Admin Roles (HIGH)

**Severity:** 🟠 **HIGH**

**What it detects:** Admin-level roles assigned to users outside approved departments.

**Why it matters:**
- Admin roles provide system-wide access and privilege escalation capabilities
- Only IT and Security departments should typically have admin access (configurable)
- Unauthorized admins indicate privilege creep or policy violations

**Detection Logic:**
```python
if 'admin' in role_entry['role'].lower():
    if user['department'] not in authorized_depts:
        flag_violation("unauthorized_admin")
```

**Configuration:**
```python
authorized_depts = {'IT', 'Security'}  # Customize as needed
```

**Remediation:**
- Remove admin role unless user's department is authorized
- If needed, replace with least-privilege alternative role
- Document business justification for any exceptions

---

### Rule 3: Stale Accounts (MEDIUM)

**Severity:** 🟡 **MEDIUM**

**What it detects:** Active accounts with no login activity for 90+ days.

**Why it matters:**
- Stale accounts are likely no longer needed (user left, role changed, etc.)
- Retained access for unused accounts increases attack surface
- Indicates incomplete provisioning/deprovisioning process

**Detection Logic:**
```python
cutoff_date = datetime.now() - timedelta(days=90)
if account['status'] == 'active' and last_login < cutoff_date:
    flag_violation("stale_account")
```

**Configurable Threshold:**
```python
check_stale_accounts(users_dict, stale_days=90)  # Change as needed
```

**Remediation:**
- Contact user to verify account is still needed
- Schedule account deactivation if not in use
- Disable access for unused departments/projects

---

## 4. AI Usage Documentation

### Intelligent Features

This auditor incorporates efficiency improvements that reduce computational complexity:

#### **Optimized Data Structures**
- **Dictionary Comprehension for User Lookup**: Converts O(n) linear searches to O(1) hash lookups
- **Set-Based Role Tracking**: Efficiently tests membership (`user_id in users_with_roles`)
- **DefaultDict for Grouping**: Automatically handles missing keys when grouping roles by user_id

#### **Scalable Rule Engine**
- Each detection rule operates independently, allowing parallel scanning
- Violations collected in unified list for batch reporting
- Report generation decoupled from detection (separation of concerns)

#### **Performance Characteristics**
- **Users DataFrame Build**: O(n) — one-time cost
- **Per-Rule Scanning**: O(n) to O(n*m) depending on rule complexity
- **Report Generation**: O(v) where v = number of violations
- **Total Runtime**: Linear in dataset size, efficient for enterprise scale (thousands of users)

---

## 5. Test Results

### Audit Execution Summary

**Test Date:** 2026-04-01 11:11:00  
**Total Users Scanned:** 10  
**Total Role Assignments:** 11  
**Total Violations Found:** 3

---

### Violation Breakdown by Severity

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 CRITICAL | 2 | Requires immediate action |
| 🟠 HIGH | 1 | Schedule remediation |
| 🟡 MEDIUM | 0 | Monitor and plan |
| 🟢 LOW | 0 | Log for reference |

---

### Detailed Findings

#### Critical Violations (2 found)

**1. User: asmith (U002)**
- **Rule:** Disabled with Roles
- **Issue:** Disabled account has 2 active role(s): `hr_manager`, `admin`
- **Risk:** High — disabled account retains administrative privileges
- **Action:** Immediately remove all roles from U002

**2. User: cjones (U005)**
- **Rule:** Disabled with Roles
- **Issue:** Disabled account has 1 active role(s): `sales_rep`
- **Risk:** High — disabled account still has sales access
- **Action:** Remove sales_rep role from U005

---

#### High Violations (1 found)

**1. User: asmith (U002) — Role: admin**
- **Rule:** Unauthorized Admin
- **Issue:** HR department user has admin role
- **Risk:** High — non-IT staff with system-wide privileges
- **Principle Violated:** Least Privilege (HR should not have admin access)
- **Action:** Replace with HR-specific role (e.g., `hr_manager` only)

---

### Departments Audited

| Department | Users | Violations |
|-----------|-------|-----------|
| IT | 1 | 0 |
| HR | 2 | 2 (asmith) |
| Finance | 1 | 0 |
| Marketing | 1 | 0 |
| Sales | 2 | 1 (cjones) |
| Engineering | 2 | 0 |
| Operations | 1 | 0 |

---

### Generated Reports

The auditor produces two complementary output files:

#### **audit_report.json** (Machine-Readable)
Contains structured data with:
- Full violation records with all fields
- Summary statistics (counts by severity/type)
- Timestamp metadata
- Parseable format for integration with security tools

**Use Case:** Ingest into SIEM, automated remediation workflows, dashboards

#### **audit_report.txt** (Human-Readable)
Contains formatted output with:
- Executive summary
- Severity distribution with visual indicators
- Detailed violation descriptions
- Timestamps for audit trail

**Use Case:** Email reports, management briefings, manual review

---

## Running the Auditor

### Prerequisites
- Python 3.8+
- `users.json` and `roles.json` in the same directory

### Execution
```bash
python permissions_auditor.py
```

### Output Files Generated
- `audit_report.json` — Structured audit data
- `audit_report.txt` — Human-readable summary

---

## Configuration & Customization

### Adjust Stale Account Threshold
```python
check_stale_accounts(users_dict, stale_days=60)  # Change from default 90
```

### Modify Authorized Admin Departments
```python
check_unauthorized_admins(users_dict, roles_data, 
                         authorized_depts={'IT', 'Security', 'DevOps'})
```

### Add Custom Detection Rules
Extend `check_*` functions following the existing pattern:
```python
def check_custom_rule(users_dict, roles_data):
    violations = []
    # Your detection logic here
    return violations
```

Then aggregate in main:
```python
all_violations = violations + admin_violations + stale_violations + custom_violations
```

---

## Security Best Practices

1. **Run regularly** — Schedule weekly or monthly audits
2. **Review violations promptly** — Act on CRITICAL findings within 24 hours
3. **Maintain audit logs** — Keep historical reports for compliance
4. **Test before deployment** — Validate custom rules against sample data
5. **Integrate with ticketing** — Auto-create remediation tickets from violations
6. **Track metrics** — Monitor trends in violation counts over time

---

## Files in This Directory

| File | Purpose |
|------|---------|
| `permissions_auditor.py` | Main auditor script |
| `users.json` | User account master data |
| `roles.json` | Role assignment records |
| `audit_report.json` | Generated JSON audit report |
| `audit_report.txt` | Generated text audit report |
| `README.md` | This documentation |

---

## Version History

- **v1.0** (2026-04-01): Initial release with 3 core detection rules
