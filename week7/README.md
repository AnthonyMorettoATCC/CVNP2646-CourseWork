# Backup Planner

## 1. Overview & Purpose

The Backup Planner is a Python script designed to simulate backup operations based on a user-defined configuration file. It loads a JSON configuration that specifies backup sources, destinations, and other parameters, then validates the configuration and runs a dry-run simulation of the backup process.

The tool is config-driven to provide flexibility: users can define multiple backup plans without modifying the code, making it adaptable to different backup scenarios. This approach separates configuration from logic, allowing for easy customization and maintenance.

## 2. Usage Instructions

To use the backup planner, run the script with a JSON configuration file as an argument:

```
python backup_planner.py backup_config.json
```

The script will:
1. Load and validate the configuration
2. If valid, simulate the backup operation
3. Display simulation results including file counts and sizes

## 3. Schema Design Decisions

### Sources Structure
Sources are structured as a list to support multiple directories or locations that need to be backed up in a single plan. Each source is a dictionary containing:
- `path`: The directory path to backup (required)
- `recursive`: Whether to include subdirectories (optional, defaults to false)
- `include`: List of file patterns to include (optional, defaults to common patterns)

This list structure allows for comprehensive backup plans that can span multiple locations.

### Required vs Optional Fields
**Required fields:**
- `plan_name`: String identifier for the backup plan
- `sources`: List of source directories to backup
- `destination`: Dictionary containing destination path

**Optional fields:**
- `sources[].recursive`: Boolean for subdirectory inclusion
- `sources[].include`: List of glob patterns for file filtering
- `destination.timestampedFolder`: Boolean for timestamped folders
- `retention`: Dictionary with retention policies

### Pattern Matching
The `include` field uses glob patterns (e.g., `*.log`, `*.txt`) to specify which files to backup from each source. This allows selective backups based on file extensions or naming conventions, reducing backup size and focusing on important data types.

## 4. Validation Levels

The configuration validation is implemented in four progressive levels:

1. **Required Fields Check**: Ensures all mandatory fields (`plan_name`, `sources`, `destination`) are present in the configuration.

2. **Type Validation**: Verifies that fields have the correct data types (e.g., `sources` must be a list, `destination` must be a dictionary).

3. **Value Validation**: Checks for logical constraints like non-empty sources list and valid string values.

4. **Nested Validation**: Performs deep validation of nested objects, ensuring each source has a valid `path` field and the destination has a required `path`.

This multi-level approach collects all errors before reporting, providing comprehensive feedback for configuration issues.

## 5. Simulation Logic

The simulation generates fake file data to demonstrate backup operations without accessing real filesystems:

- **File Generation**: For each source, creates 5-15 fake files based on the `include` patterns
- **Naming Logic**: 
  - `*.log` files get realistic names like `application_2024-01-15.log`
  - Other patterns use descriptive names (e.g., `readme.txt`, `document.docx`)
- **Size Assignment**: Each file gets a random size between 1-100 MB to simulate realistic file distributions
- **Totals Calculation**: Aggregates file counts and sizes across all sources

This approach provides a safe way to test backup configurations and estimate storage requirements.

## 6. Function Structure

The code is organized into focused functions with clear separation of concerns:

- `load_config(file_path)`: Handles JSON file reading and parsing with comprehensive error handling
- `validate_config(config)`: Implements the four-level validation system, returning validation status and error details
- `simulate_backup(config)`: Generates fake backup data and calculates totals, simulating the backup process

This modular design makes the code maintainable and testable.

## 7. AI Usage

GitHub Copilot assisted with:
- Generating the multi-level validation logic
- Creating comprehensive test configurations
- Implementing the simulation file naming logic
- Structuring the JSON schema and error handling

Through this project, I learned about:
- Progressive validation patterns for complex configurations
- Effective use of Python's `random` and `datetime` modules for simulation
- Best practices for config-driven application design
- Comprehensive error collection and reporting

## 8. Testing

The script includes 10 test configurations covering various scenarios:

- **2 Valid Configurations**: Complete, properly structured configs for positive testing
- **2 Missing Required Fields**: Tests for absent `plan_name` and `sources` fields
- **2 Wrong Data Types**: Invalid types for `sources` (string instead of list) and `destination` (string instead of dict)
- **2 Empty/Invalid Values**: Empty sources list and empty plan_name string
- **2 Nested Errors**: Sources missing `path` field and destination missing `path` field

These test cases cover edge cases like empty collections, type mismatches, and missing nested fields, ensuring robust validation.