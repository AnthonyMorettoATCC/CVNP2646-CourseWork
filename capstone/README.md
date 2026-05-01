# Security Log Correlation Engine

A capstone project that ingests JSON security logs, correlates suspicious events, builds attack chains, and exports actionable reports.

## Requirements

- Python 3.11 or newer
- No external runtime dependencies are required for the core engine
- `pytest` is used for local validation and testing

## Setup

From the repository root:

```bash
python -m pip install -r requirements.txt
```

If you are using the provided virtual environment, activate it first and then install requirements.

## Usage

Run the capstone engine with a log file, configuration file, and threat indicators file:

```bash
python main.py \
  --logs input_sample.json \
  --config config.json \
  --intel threat_indicators.json \
  --output ./results \
  --verbose
```

Or run the package as a module:

```bash
python -m capstone.main \
  --logs input_sample.json \
  --config config.json \
  --intel threat_indicators.json \
  --output ./results \
  --verbose
```

### Arguments

- `--logs` / `-l`: Path to the input log JSON file
- `--config` / `-c`: Path to the correlation configuration JSON file
- `--intel` / `-i`: Path to the threat indicators JSON file
- `--output` / `-o`: Output directory for generated reports
- `--verbose` / `-v`: Enable debug logging

## Output

The engine writes these files into the output directory:

- `correlated_events.json`
- `attack_chains.json`
- `alert_report.json`

## Testing

Run tests for the capstone engine from the repository root:

```bash
python -m pytest -q capstone
```

## Notes

- The engine now validates configuration and threat indicator schemas before processing.
- Invalid log entries are skipped with warnings instead of failing the entire run.
