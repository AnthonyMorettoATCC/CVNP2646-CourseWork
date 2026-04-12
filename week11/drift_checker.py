import json
from typing import Dict, Any, Tuple, Union, List

class DriftResult:
    """
    Encapsulates a single drift finding.
    """
    def __init__(self, path: str, drift_type: str, baseline_value: Any = None, current_value: Any = None):
        self.path = path
        self.drift_type = drift_type  # 'missing', 'extra', 'changed'
        self.baseline_value = baseline_value
        self.current_value = current_value
        self.severity = self._calculate_severity()

    def _calculate_severity(self) -> str:
        """
        Assigns severity based on keywords and drift type.
        """
        high_keywords = ['enabled', 'security', 'access', 'port', 'source']
        medium_keywords = ['level', 'action', 'protocol']
        
        if self.drift_type == 'missing':
            return 'high'  # Missing controls are critical
        elif self.drift_type == 'extra':
            return 'medium'  # Unauthorized additions
        elif self.drift_type == 'changed':
            if any(kw in self.path.lower() for kw in high_keywords):
                return 'high'
            elif any(kw in self.path.lower() for kw in medium_keywords):
                return 'medium'
            else:
                return 'low'
        return 'low'

    def __str__(self) -> str:
        """
        Returns formatted string like "[~] logging.enabled (high)".
        """
        symbols = {'missing': '-', 'extra': '+', 'changed': '~'}
        symbol = symbols.get(self.drift_type, '?')
        return f"[{symbol}] {self.path} ({self.severity})"

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts to dictionary for JSON export.
        """
        return {
            'path': self.path,
            'drift_type': self.drift_type,
            'baseline_value': self.baseline_value,
            'current_value': self.current_value,
            'severity': self.severity
        }

    def is_critical(self) -> bool:
        """
        Returns True for high severity findings.
        """
        return self.severity == 'high'

def compare_configs(baseline: Dict[str, Any], current: Dict[str, Any], path: str = '') -> List[DriftResult]:
    """
    Recursively compares two configuration dictionaries to detect drift.

    Args:
        baseline: The baseline configuration (expected state).
        current: The current configuration (actual state).
        path: The current path in the nested structure (used internally for reporting).

    Returns:
        A list of DriftResult objects representing the differences.
    """
    results = []

    if baseline == current:
        return results

    if type(baseline) != type(current):
        results.append(DriftResult(path or 'root', 'changed', baseline, current))
        return results

    if isinstance(baseline, dict):
        # Missing keys
        for key, value in baseline.items():
            if key not in current:
                results.append(DriftResult(f"{path}.{key}" if path else key, 'missing', value, None))

        # Extra keys
        for key, value in current.items():
            if key not in baseline:
                results.append(DriftResult(f"{path}.{key}" if path else key, 'extra', None, value))

        # Common keys: recurse
        for key in set(baseline.keys()) & set(current.keys()):
            sub_path = f"{path}.{key}" if path else key
            sub_results = compare_configs(baseline[key], current[key], sub_path)
            results.extend(sub_results)

    elif isinstance(baseline, list):
        if len(baseline) != len(current):
            results.append(DriftResult(path or 'root', 'changed', baseline, current))
        else:
            for i, (b_item, c_item) in enumerate(zip(baseline, current)):
                sub_path = f"{path}[{i}]" if path else f"[{i}]"
                sub_results = compare_configs(b_item, c_item, sub_path)
                results.extend(sub_results)
    else:
        # Primitive types
        if baseline != current:
            results.append(DriftResult(path or 'root', 'changed', baseline, current))

    return results

# Example usage
if __name__ == "__main__":
    # Sample baseline and current configurations for testing
    baseline = {
        "firewall_name": "prod-web-fw",
        "default_action": "deny",
        "rules": [
            {
                "name": "allow-https",
                "port": 443,
                "protocol": "tcp",
                "source": "0.0.0.0/0",
                "action": "allow",
                "enabled": True
            },
            {
                "name": "allow-ssh-internal",
                "port": 22,
                "protocol": "tcp",
                "source": "10.0.0.0/8",
                "action": "allow",
                "enabled": True
            }
        ],
        "logging": {
            "enabled": True,
            "level": "info",
            "destination": "siem"
        }
    }

    current = {
        "firewall_name": "prod-web-fw",
        "default_action": "deny",
        "rules": [
            {
                "name": "allow-https",
                "port": 8080,
                "protocol": "tcp",
                "source": "0.0.0.0/0",
                "action": "allow",
                "enabled": True
            },
            {
                "name": "allow-ssh-internal",
                "port": 22,
                "protocol": "tcp",
                "source": "0.0.0.0/0",
                "action": "allow",
                "enabled": True
            },
            {
                "name": "temp-debug",
                "port": 9999,
                "protocol": "tcp",
                "source": "0.0.0.0/0",
                "action": "allow",
                "enabled": True
            }
        ],
        "logging": {
            "enabled": False,
            "level": "debug"
        }
    }

    # Load baseline and current configurations
    # with open('baseline.json', 'r') as f:
    #     baseline = json.load(f)

    # with open('current.json', 'r') as f:
    #     current = json.load(f)

    # Compare configurations
    differences = compare_configs(baseline, current)

    # Print results
    print("Configuration Drift Report:")
    print(f"Total drift findings: {len(differences)}")
    
    severity_count = {'high': 0, 'medium': 0, 'low': 0}
    for diff in differences:
        severity_count[diff.severity] += 1
    
    print(f"By severity: High={severity_count['high']}, Medium={severity_count['medium']}, Low={severity_count['low']}")
    
    critical = [diff for diff in differences if diff.is_critical()]
    print(f"Critical findings: {len(critical)}")
    for diff in critical:
        print(f"  - {diff.path}: {diff.baseline_value} → {diff.current_value}")
    
    print("\nAll findings:")
    for diff in differences:
        print(f"  {diff}")
