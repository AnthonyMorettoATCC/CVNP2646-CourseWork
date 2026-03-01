# Authentication Log Scanner

## Title and Description

The **Authentication Log Scanner** (`auth_scanner.py`) is a Python-based security analysis tool designed to parse authentication logs and generate comprehensive incident reports. It analyzes login attempts, identifies security patterns, and produces structured JSON and human-readable text reports for security analysis and incident response.

## Usage Instructions

### Basic Usage

1. **Place your log file** in the same directory as `auth_scanner.py` and name it `auth.log`

2. **Run the scanner**:
   ```bash
   python3 auth_scanner.py
   ```

3. **Output files** will be generated in the same directory:
   - `incident_report.json` - Structured JSON report
   - `incident_report.txt` - Human-readable text report

### Log File Format

The scanner expects authentication logs in the following format:
```
YYYY-MM-DD HH:MM:SS event=EVENT_TYPE status=STATUS user=USERNAME ip=IP_ADDRESS
```

**Example**:
```
2026-03-01 08:15:23 event=LOGIN status=SUCCESS user=john ip=192.168.1.100
2026-03-01 08:16:45 event=LOGIN status=FAIL user=admin ip=203.0.113.45
```

### Custom Configuration

You can customize the scanner by modifying the `main()` function:

```python
scanner = AuthLogScanner()
scanner.parse_log_file("custom_log_file.log")
scanner.save_reports(analyst_name="Your Name", classification="INTERNAL")
```

## Features

The scanner detects and reports:

✓ **Authentication Events Analysis**
- Counts successful login attempts
- Counts failed login attempts
- Calculates overall failure rate percentage

✓ **User Account Targeting**
- Identifies top 5 most-targeted user accounts
- Reports number of failed login attempts per account
- Highlights accounts under attack

✓ **IP-Based Attack Detection**
- Identifies top 5 attacking IP addresses
- Tracks attack frequency from each source
- Useful for blocking/monitoring malicious IPs

✓ **Error Resilience**
- Handles malformed log entries gracefully
- Continues processing despite parsing errors
- Reports total parse errors in summary

✓ **Structured Reporting**
- JSON format with metadata (timestamp, analyst, classification)
- Human-readable text format with formatted tables
- Proper indentation (indent=2) for readability

## Implementation Details

### Log Parsing Strategy

The scanner uses a line-by-line parsing approach:

```python
def _parse_line(self, line):
    parts = line.split()
    timestamp = f"{parts[0]} {parts[1]}"
    kv_pairs = parts[2:]
    
    event_data = {'timestamp': timestamp}
    for pair in kv_pairs:
        if '=' not in pair:
            continue
        key, value = pair.split('=', 1)
        event_data[key] = value
```

**Why this approach?**
- Simple and efficient for whitespace-delimited formats
- Flexible for varying key-value pair counts
- Handles malformed entries without crashing

### Counter vs Plain Dictionary

The scanner uses `Counter` from the collections module for tracking statistics:

```python
from collections import Counter

self.failed_by_user = Counter()
self.failed_by_ip = Counter()
```

**Why Counter instead of plain dict?**

| Feature | Counter | Plain Dict |
|---------|---------|-----------|
| **Counting** | `count[key] += 1` | Manual increment logic |
| **Most Common** | `.most_common(5)` | Manual sorting needed |
| **Missing Keys** | Returns 0 automatically | Requires KeyError handling |
| **Code Clarity** | Purpose is explicit | Less obvious intent |
| **Performance** | Optimized for counting | Generic |

Counter makes the code cleaner, safer, and more maintainable.

### JSON Report Structure

```json
{
  "metadata": {
    "generated_at": "ISO 8601 timestamp",
    "analyst": "Analyst name",
    "classification": "Report classification"
  },
  "summary": {
    "total_events": "Number",
    "total_success": "Number",
    "total_fail": "Number",
    "failure_rate": "Percentage",
    "parse_errors": "Number"
  },
  "top_targeted_users": [
    {"username": "String", "failed_attempts": "Number"}
  ],
  "top_attacking_ips": [
    {"ip_address": "String", "failed_attempts": "Number"}
  ]
}
```

## Error Handling

The scanner handles multiple edge cases:

### 1. **File Not Found**
```python
except FileNotFoundError:
    logging.error(f"Log file not found: {filepath}")
```
- Logs error but doesn't crash
- Continues gracefully with empty report

### 2. **Malformed Log Lines**
```python
if len(parts) < 2:
    self.parse_errors += 1
    return
```
- Skips incomplete lines
- Increments error counter
- Reports total in statistics

### 3. **Missing Required Fields**
```python
if 'event' not in event_data or 'status' not in event_data:
    self.parse_errors += 1
    return
```
- Validates required fields (event, status)
- Rejects entries without both fields
- Prevents malformed data in reports

### 4. **General Exception Handling**
```python
except Exception as e:
    logging.warning(f"Error parsing line: {line[:50]}... - {e}")
    self.parse_errors += 1
```
- Catches unexpected errors
- Prevents partial failures from stopping execution
- Logs context (first 50 chars of line)

### 5. **Division by Zero**
```python
failure_rate = (self.total_fail / total_events * 100) if total_events > 0 else 0
```
- Prevents division by zero if no events parsed
- Returns 0% for empty logs

## Testing

### Test Data

Created `auth.log` with 15 sample entries including:
- **Mix of success and failure** (5 success, 10 failures)
- **Multiple users under attack** (admin, root, test)
- **Multiple attacking IPs** (203.0.113.45, 198.51.100.12)
- **Realistic timestamps** (2026-03-01)

### Test Results

```
Total Events Processed:     15
Successful Logins:          5
Failed Logins:              10
Failure Rate:               66.67%
Parsing Errors:             0

TOP 5 TARGETED USER ACCOUNTS
1. admin - 5 failed attempts
2. root  - 3 failed attempts
3. test  - 2 failed attempts

TOP 5 ATTACKING IP ADDRESSES
1. 203.0.113.45  - 6 failed attempts
2. 198.51.100.12 - 4 failed attempts
```

### Validation

✓ JSON report is valid (tested with json.loads)
✓ Statistics calculations are accurate
✓ Counter properly aggregates attempts
✓ Missing key-value pairs are skipped
✓ Empty logs don't cause crashes
✓ Reports generate without errors

## Challenges

### Challenge 1: **Flexible Log Parsing**

**Problem**: Logs might have varying numbers of key-value pairs per line

**Solution**: 
- Extract timestamp separately (first two fields)
- Parse remaining fields dynamically with `split('=', 1)` 
- Skip malformed pairs without failing entire line
- Validate required fields after parsing

### Challenge 2: **Accurate Statistics Counting**

**Problem**: Needed to track multiple types of counts (users, IPs) efficiently

**Solution**:
- Used `Counter` class for automatic aggregation
- Avoided manual dictionary manipulation
- Leveraged `.most_common(5)` for ranking
- Made code more Pythonic and maintainable

### Challenge 3: **Error Resilience**

**Problem**: Real logs often contain malformed entries; scanner shouldn't crash

**Solution**:
- Used try-except blocks for file operations
- Added length validation before accessing list elements
- Maintained parse_errors counter
- Continued processing despite errors
- Logged warnings for debugging

### Challenge 4: **Report Generation**

**Problem**: Needed both JSON (machine-readable) and text (human-readable) formats

**Solution**:
- Separated report logic into dedicated methods
- Used `json.dumps()` with `indent=2` for formatting
- Built text reports with formatted strings
- Stored both metadata and statistics in JSON
- Made reports flexible for different analyst names/classifications

### Challenge 5: **Data Validation**

**Problem**: Only certain log entries should be counted (missing status or event fields)

**Solution**:
- Check for required fields after parsing
- Skip invalid entries and increment error counter
- Ensure only clean data enters statistics
- Maintain data integrity in final reports

## Requirements

- Python 3.7+
- Standard library only (json, logging, collections, datetime, pathlib)
- No external dependencies

## Future Improvements

- Support for multiple log formats (with configuration)
- Time-based attack pattern analysis (attacks over time)
- Geographic IP lookup for attack source identification
- Threshold-based alerting (alert if failure rate exceeds %)
- Database export for long-term trend analysis
- Command-line argument parsing for custom log paths
