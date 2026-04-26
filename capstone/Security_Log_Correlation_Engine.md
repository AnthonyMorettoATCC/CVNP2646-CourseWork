# Security Log Correlation Engine

*Capstone Project Proposal - Week 13*

## Project Overview

Analyze logs from multiple sources (firewall, IDS, authentication) to correlate events and detect multi-stage attacks.

## Problem Statement

Security analysts manually correlate events across different systems, missing patterns that span multiple log sources.

## Target Users / Use Case

Security operations teams, primarily log analysts

## Inputs

### JSON Input Files

- config.json: Correlation rules and thresholds
- logs.json: Aggregated log entries from various sources
- threat_indicators.json: Known IOCs and attack patterns

## Outputs

### JSON Output Files

- correlated_events.json: Timeline of related security events
- attack_chains.json: Detected multi-stage attack patterns
- alert_report.json: High-priority security alerts

## Command-Line Interface

### Usage

```bash
python main.py --logs data/logs.json --config config.json --intel threat_indicators.json --output ./results
```

### Arguments

--logs / -l: Path to the logs.json file containing the raw security events (required)
--config / -c: Path to config.json defining the correlation logic (e.g., time windows, threshold counts) (required)
--intel / -i: Path to threat_indicators.json for matching against known IOCs (required)
--output / -o: Directory where the three output JSON reports will be saved; defaults to ./output (optional)
--verbose / -v: Flag to enable debug-level logging to the console during processing (optional)

## Features

### Must-Have Features (MVP)

Log parsing, event correlation, timeline generation, alert creation

### Nice-to-Have Features

MITRE ATT&CK mapping, graph visualization, threat intelligence integration

## Technical Approach

### Classes

```python
- LogEntry: A data class or model that standardizes raw JSON logs into a common format (timestamp, source_ip, destination_ip, action, etc.) for easier comparison.
- CorrelationEngine: The core logic class. It ingests the LogEntry objects and applies rules from the config.json to identify relationships between disparate events. 
- ThreatMatcher: A specialized class that scans log data specifically for matches against the threat_indicators.json patterns (e.g., IP blacklists or known malicious user agents).
- AttackChainBuilder: Responsible for taking correlated events and "stitching" them into a sequential timeline to visualize the progression of a multi-stage attack.
- ReportGenerator: Handles the formatting and exporting of the final JSON files (correlated_events.json, attack_chains.json, and alert_report.json).
```

## Timeline

Week 13: Proposal and data design
Week 14: Implementation of proposal into working code
Week 15: Professionalize code
Week 16: Demonstrate project

