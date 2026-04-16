# Network Traffic Monitor
Professional network traffic analyzer with port scan and SYN flood detection.

## Features
- **Modular Design:** Clean separation of I/O, parsing, and logic
- **Comprehensive Logging:** File and console handlers with configurable levels
- **Full Test Coverage:** 23 pytest tests covering happy paths, edge cases, and error handling
- **Professional CLI:** argparse with validation, configurable thresholds, and proper exit codes

## Installation
```bash
# Clone repository
git clone <repo-url>
cd network-monitor

# Install dependencies
pip install pytest
```

## Usage
```bash
# Basic usage
python week12/network_monitor.py week12/traffic_sample.log

# With options
python week12/network_monitor.py week12/traffic_sample.log --output week12/results.json --port-scan-threshold 50 --syn-flood-threshold 75

# Verbose mode
python week12/network_monitor.py week12/traffic_sample.log -v

# Show help
python week12/network_monitor.py --help
```

## Project Structure
```text
week12/
├── network_monitor.py        # Main program
├── test_network_monitor.py   # Test suite
├── traffic_sample.log        # Sample data
├── network_monitor.log       # Generated logs
└── README.md                 # This file
```

## Refactoring Journey
### Problems with Original Code
1. **Global variables** made testing harder
2. **Magic numbers** (25, 100) had no explanation
3. **Mixed concerns** - I/O, parsing, and logic were tangled
4. **No error handling** - malformed input could crash the program
5. **Print debugging** instead of professional logging
6. **Zero tests** - every change was risky

### Refactoring Applied
1. **Extracted `NetworkConfig` class** - all thresholds and outputs centralized
2. **Created pure functions** - each function does one thing and has no side effects
3. **Separated I/O from logic** - `load_traffic_log()` vs `analyze_traffic()`
4. **Added professional logging** - file + console handlers, INFO/DEBUG/WARNING/ERROR levels
5. **Wrote comprehensive tests** - 23 tests across parsing, detection, I/O, and CLI validation
6. **Built argparse CLI** - proper validation and exit codes

### Biggest Challenge
Separating I/O from logic was the hardest part. The original code mixed file reading, parsing, and alert generation together, so refactoring required careful function boundaries.

## AI-Assisted Development
### Tools Used
- GitHub Copilot for code suggestions
- ChatGPT for refactoring patterns
- Claude for test generation

### What Worked Well
- AI generated useful initial test structure
- Helpful for suggesting function signatures
- Great for boilerplate code

### What I Had to Fix
- AI suggested a global logger (it was parameterized instead)
- AI tests had wrong data types in several places
- AI missed boundary test cases at the exact threshold

### Lesson Learned
AI is a great starting point but always needs review. Testing caught several bugs in the first AI-generated draft.

## Testing
Run tests:
```bash
pytest -v
```

## License
MIT
