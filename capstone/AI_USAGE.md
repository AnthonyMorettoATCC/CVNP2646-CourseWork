# AI Usage Log

## Project: Security Log Correlation Engine

## Overview

This document tracks my use of AI assistance from GitHub Copilot while developing the Security Log Correlation Engine capstone project. AI was used to help with algorithm design, validation logic, report generation, and debugging.

---

## Summary Statistics

- Total AI-assisted sessions: 5+
- Code suggestions accepted as-is: 2
- Code suggestions modified before use: 3+
- Code suggestions rejected: 1
- Primary uses: algorithm design, JSON validation, log correlation logic, CLI handling, error handling

---

## Key Prompts & Interactions

### Session 1: Correlation Grouping Logic
**Prompt:**
"How can I group security log events by source IP and time window so that closely timed events from the same host are correlated into the same alert group?"

**AI Response Summary:**
Suggested sorting events by timestamp, then using a sliding window or group flush logic when a new event falls outside the window.

**My Action:**
Modified

**Reasoning:**
The core idea was useful, but I adapted it to work with a single `LogEntry` dataclass and a configurable `time_window_minutes` threshold. I also ensured the flush logic only created groups when the event count met the configured minimum.

---

### Session 2: JSON Input Validation
**Prompt:**
"Write Python validation helpers that ensure config and threat indicator JSON files contain required keys and valid values."

**AI Response Summary:**
Provided examples of key checks and type validation for nested JSON objects.

**My Action:**
Modified

**Reasoning:**
I adjusted the validation to include explicit positive integer checks for `time_window_minutes` and `min_events_per_group`, plus list validation for threat indicators such as `ip_blacklist` and `malicious_signatures`.

---

### Session 3: Threat Matching Rules
**Prompt:**
"How can I scan parsed log entries for threat indicator matches based on blacklisted IPs, malicious signatures, and suspicious user agents?"

**AI Response Summary:**
Suggested checks against blacklists and signature lists, with aggregated threat descriptions.

**My Action:**
Accepted with minor modifications

**Reasoning:**
The approach was sound. I added explicit `raw_data` user agent checks and consolidated threat match output into a structured list of matched conditions.

---

### Session 4: Reporting and Output Generation
**Prompt:**
"Generate a JSON report writer for correlated events, attack chains, and alert summaries."

**AI Response Summary:**
Suggested an output helper that writes report files in a result directory.

**My Action:**
Modified

**Reasoning:**
I enhanced the writer to create output directories automatically and used distinct JSON filenames for correlated events, attack chains, and alerts.

---

## Examples of Modified/Rejected AI Code

### Example 1: Group Flush Threshold
**Original AI suggestion:**
```python
if len(group) > 1:
    output.append(...)
```

**My modified version:**
```python
min_events = self.thresholds.get('min_events_per_group', 2)
if len(group) < min_events:
    return
```

**Why I changed it:**
I needed a configurable minimum group size rather than a hardcoded value.

---

### Example 2: File Loading Error Handling
**Original AI suggestion:**
```python
with open(filepath) as f:
    return json.load(f)
```

**My modified version:**
```python
try:
    with file_path.open('r', encoding='utf-8') as f:
        return json.load(f)
except FileNotFoundError:
    LOGGER.error('File not found: %s', file_path)
    raise
except json.JSONDecodeError as exc:
    LOGGER.error('Invalid JSON in %s: %s', file_path, exc)
    raise
```

**Why I changed it:**
I needed robust error logging for missing files and invalid JSON in a security tool.

---

## Verification Methods

I verified AI-assisted code through:

1. Unit tests for parser, validation, threat matching, and correlation behavior
2. Manual runs with sample `input_sample.json`, `config.json`, and `threat_indicators.json`
3. Edge case checks for empty log sets, invalid log entries, and boundary timestamps
4. Reviewing output files under `capstone/results`

---

## Reflection

GitHub Copilot helped accelerate development by providing algorithm ideas and boilerplate patterns. I found the most value in using AI to bootstrap functionality, then customizing the logic to fit the capstone requirements and adding strong validation and logging.

Key lessons:

- AI is useful for initial design and code structure, but not a substitute for reviewing implementation details.
- Most suggestions required modification to support the actual data model and config semantics.
- Reliable output depends on careful testing and explicit error handling.

**Key takeaway:** AI was a helpful collaborator, but the final Security Log Correlation Engine design reflects my own decisions and validation work.