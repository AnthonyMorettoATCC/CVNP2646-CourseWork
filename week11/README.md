# Configuration Drift Checker

## Overview

The Configuration Drift Checker is a Python tool that recursively compares two JSON configuration files to detect unauthorized or unintended changes in system configurations. It identifies three types of drift: missing keys (lost controls), extra keys (unauthorized additions), and changed values (modified settings).

Configuration monitoring is critical because:
- **Security**: Ensures security controls remain in place
- **Compliance**: Maintains adherence to standards and policies
- **Stability**: Prevents configuration-related outages
- **Auditing**: Provides evidence of changes over time

## Drift Types

The checker detects three categories of configuration drift:

### Missing
Keys present in the baseline but absent in the current configuration. These represent lost security controls or settings that may compromise system integrity.

**Example**: `logging.destination` missing from current config (baseline had `"siem"`)

### Extra
Keys present in the current configuration but not in the baseline. These may indicate unauthorized additions or misconfigurations.

**Example**: An extra firewall rule added without approval

### Changed
Values that differ between baseline and current configurations. These show modifications to existing settings.

**Examples**:
- `logging.enabled`: `True` → `False` (logging disabled)
- `rules[1].source`: `"10.0.0.0/8"` → `"0.0.0.0/0"` (source restriction removed)

## How Recursion Works

### Recursive Comparison

The `compare_configs` function calls itself for nested structures:

1. **Dictionary comparison:** Find missing/extra keys at current level, then recurse on common keys
2. **List comparison:** Compare elements by index, recurse on each item pair
3. **Value comparison:** Base case - direct equality check for primitives

**Example nested path building:**
- Root level: `firewall_name`
- Level 1: `logging.enabled`
- Level 2: `rules[0].port`

Path construction uses dot notation for dict keys and bracket notation for list indices.

## DriftResult Class

Encapsulates a single drift finding with structured data and utility methods.

### Attributes
- **path**: String path to the drifted element (e.g., `"logging.enabled"`)
- **drift_type**: One of `'missing'`, `'extra'`, `'changed'`
- **baseline_value**: Value in baseline config (None for extra)
- **current_value**: Value in current config (None for missing)
- **severity**: Calculated severity level (`'high'`, `'medium'`, `'low'`)

### Methods
- **`_calculate_severity()`**: Assigns severity based on keywords and drift type
  - High: Missing keys, security-related changes (enabled, port, source)
  - Medium: Configuration changes (level, action, protocol)
  - Low: Other changes
- **`__str__()`**: Returns formatted string like `"[~] logging.enabled (high)"`
- **`to_dict()`**: Converts to dictionary for JSON export
- **`is_critical()`**: Returns True for high severity findings

## Test Results

Testing with sample firewall configuration data:

### Summary
- **Total drift findings**: 4
- **By severity**: High=2, Medium=1, Low=1
- **Critical findings**: 2

### Critical Findings
- `logging.enabled` changed (`True` → `False`) - High severity
- `logging.destination` missing (`"siem"` → None) - High severity

### All Findings
```
[-] logging.destination (high)
[~] logging.enabled (high)
[~] logging.level (medium)
[~] rules (low)
```

## Challenges Encountered

Developing the recursive comparison had several challenges:

- **Result aggregation**: Initially confused about using `extend()` vs `append()` when merging recursive results. Lists of DriftResult objects require `extend()` to flatten.
- **Path building**: Ensuring correct path construction, especially avoiding leading dots for root-level keys (used conditional `f"{path}.{key}" if path else key`).
- **Type mismatches**: Handling cases where baseline has a dict but current has a primitive, or vice versa. The type check prevents invalid comparisons.
- **List length differences**: Current implementation treats entire lists as changed when lengths differ, rather than detecting specific additions/removals. This could be improved for more granular reporting.