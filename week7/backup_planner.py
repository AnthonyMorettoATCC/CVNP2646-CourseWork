import json
import random
import datetime

def load_config(file_path):
    """
    Read a JSON file and parse it into a Python dictionary.

    Args:
        file_path (str): The path to the JSON file.

    Returns:
        dict or None: The parsed JSON data as a Python dictionary, or None if an error occurs.
    """
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return data
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON format in '{file_path}': {e}")
        return None
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")
        return None

def validate_config(config):
    """
    Validate backup configuration with four levels:
    1. Required fields: plan_name, sources, destination
    2. Type validation: sources is list, destination is dict
    3. Value validation: sources not empty, each has path
    4. Nested validation: check each source object
    
    Returns: (is_valid: bool, errors: list)
    Collect ALL errors before returning, not just first
    """
    errors = []
    
    # Level 1: Required fields
    required_fields = ['plan_name', 'sources', 'destination']
    for field in required_fields:
        if field not in config:
            errors.append(f"Missing required field: '{field}'")
    
    # If required fields are missing, we can't proceed with other validations
    if any(field not in config for field in required_fields):
        return False, errors
    
    # Level 2: Type validation
    if not isinstance(config['sources'], list):
        errors.append("Field 'sources' must be a list")
    if not isinstance(config['destination'], dict):
        errors.append("Field 'destination' must be a dictionary")
    
    # Level 3: Value validation
    if isinstance(config['sources'], list) and len(config['sources']) == 0:
        errors.append("Field 'sources' cannot be empty")
    
    # Level 4: Nested validation for sources
    if isinstance(config['sources'], list):
        for i, source in enumerate(config['sources']):
            if not isinstance(source, dict):
                errors.append(f"Source {i} must be a dictionary")
                continue
            if 'path' not in source:
                errors.append(f"Source {i} is missing required field: 'path'")
            elif not isinstance(source['path'], str):
                errors.append(f"Source {i} 'path' must be a string")
    
    # Nested validation for destination
    if isinstance(config['destination'], dict):
        if 'path' not in config['destination']:
            errors.append("Destination is missing required field: 'path'")
        elif not isinstance(config['destination']['path'], str):
            errors.append("Destination 'path' must be a string")
    
    is_valid = len(errors) == 0
    return is_valid, errors

def simulate_backup(config):
    """
    Simulate backup operations (DRY-RUN) by generating fake file data.
    For each source in config:
    - Generate 5-15 fake filenames based on include_patterns
    - If pattern is *.log, generate realistic log names
    - Assign random file sizes between 1-100 MB
    - Calculate totals
    Do NOT read actual directories, generate fake data only.
    
    Returns: dict with simulation results
    """
    simulation_results = {
        "sources": [],
        "totals": {
            "total_files": 0,
            "total_size_mb": 0,
            "total_size_gb": 0
        }
    }
    
    for source in config.get('sources', []):
        source_result = {
            "path": source.get('path', 'Unknown'),
            "files": [],
            "source_total_files": 0,
            "source_total_size_mb": 0
        }
        
        # Get include patterns, default to some common ones if none specified
        include_patterns = source.get('include', ['*.txt', '*.docx', '*.pdf', '*.log'])
        
        # Generate 5-15 files per source
        num_files = random.randint(5, 15)
        
        for _ in range(num_files):
            # Pick a random pattern
            pattern = random.choice(include_patterns)
            
            # Generate filename based on pattern
            if pattern == '*.log':
                # Generate realistic log names
                log_types = ['application', 'system', 'security', 'error', 'access', 'backup']
                log_type = random.choice(log_types)
                date = datetime.date.today() - datetime.timedelta(days=random.randint(0, 30))
                filename = f"{log_type}_{date}.log"
            elif pattern == '*.txt':
                txt_names = ['readme', 'config', 'notes', 'data', 'report', 'summary']
                filename = f"{random.choice(txt_names)}.txt"
            elif pattern == '*.docx':
                doc_names = ['document', 'report', 'proposal', 'memo', 'letter', 'contract']
                filename = f"{random.choice(doc_names)}.docx"
            elif pattern == '*.pdf':
                pdf_names = ['manual', 'guide', 'invoice', 'certificate', 'form', 'statement']
                filename = f"{random.choice(pdf_names)}.pdf"
            else:
                # Generic filename for other patterns
                ext = pattern.replace('*', '')
                filename = f"file_{random.randint(1, 1000)}{ext}"
            
            # Generate random file size 1-100 MB
            size_mb = random.randint(1, 100)
            
            file_info = {
                "filename": filename,
                "size_mb": size_mb
            }
            
            source_result["files"].append(file_info)
            source_result["source_total_files"] += 1
            source_result["source_total_size_mb"] += size_mb
        
        simulation_results["sources"].append(source_result)
        simulation_results["totals"]["total_files"] += source_result["source_total_files"]
        simulation_results["totals"]["total_size_mb"] += source_result["source_total_size_mb"]
    
    # Calculate total size in GB
    simulation_results["totals"]["total_size_gb"] = round(simulation_results["totals"]["total_size_mb"] / 1024, 2)
    
    return simulation_results

# Test cases
if __name__ == "__main__":
    # Generate 10 test configurations for validation testing:
    # - 2 completely valid configs
    # - 2 with missing required fields
    # - 2 with wrong data types (sources as string, etc)
    # - 2 with empty or invalid values
    # - 2 with nested errors (source missing path)
    # Each should have a comment explaining what's wrong:

    test_configs = [
        # Valid config 1: Complete and correct
        {
            "plan_name": "Weekly Backup Plan",
            "sources": [
                {
                    "path": "C:\\Users\\Documents",
                    "recursive": True
                }
            ],
            "destination": {
                "path": "D:\\Backups"
            }
        },
        # Valid config 2: Multiple sources
        {
            "plan_name": "Daily Backup Plan",
            "sources": [
                {
                    "path": "C:\\Users\\Documents",
                    "recursive": True,
                    "include": ["*.docx", "*.pdf"]
                },
                {
                    "path": "C:\\Users\\Pictures",
                    "recursive": False
                }
            ],
            "destination": {
                "path": "E:\\BackupStorage",
                "timestampedFolder": True
            },
            "retention": {
                "days": 30
            }
        },
        # Missing required fields 1: Missing plan_name
        {
            "sources": [{"path": "C:\\Users\\Documents"}],
            "destination": {"path": "D:\\Backups"}
            # Missing: plan_name
        },
        # Missing required fields 2: Missing sources
        {
            "plan_name": "Backup Plan",
            "destination": {"path": "D:\\Backups"}
            # Missing: sources
        },
        # Wrong data types 1: sources as string instead of list
        {
            "plan_name": "Backup Plan",
            "sources": "C:\\Users\\Documents",  # Should be a list
            "destination": {"path": "D:\\Backups"}
        },
        # Wrong data types 2: destination as string instead of dict
        {
            "plan_name": "Backup Plan",
            "sources": [{"path": "C:\\Users\\Documents"}],
            "destination": "D:\\Backups"  # Should be a dict
        },
        # Empty or invalid values 1: Empty sources list
        {
            "plan_name": "Backup Plan",
            "sources": [],  # Empty list
            "destination": {"path": "D:\\Backups"}
        },
        # Empty or invalid values 2: Empty plan_name string
        {
            "plan_name": "",  # Empty string (but field exists)
            "sources": [{"path": "C:\\Users\\Documents"}],
            "destination": {"path": "D:\\Backups"}
        },
        # Nested errors 1: Source missing path
        {
            "plan_name": "Backup Plan",
            "sources": [
                {
                    "recursive": True
                    # Missing: path
                }
            ],
            "destination": {"path": "D:\\Backups"}
        },
        # Nested errors 2: Destination missing path
        {
            "plan_name": "Backup Plan",
            "sources": [{"path": "C:\\Users\\Documents"}],
            "destination": {
                "timestampedFolder": True
                # Missing: path
            }
        }
    ]

    # Run validation on all test configs
    for i, config in enumerate(test_configs):
        is_valid, errors = validate_config(config)
        print(f"Test config {i+1}: Valid={is_valid}, Errors={errors}")

    print("\n--- Backup Simulation Test ---")
    # Test simulation with valid config
    valid_config = test_configs[0]  # First valid config
    simulation = simulate_backup(valid_config)
    print(f"Plan: {valid_config['plan_name']}")
    print(f"Total files: {simulation['totals']['total_files']}")
    print(f"Total size: {simulation['totals']['total_size_mb']} MB ({simulation['totals']['total_size_gb']} GB)")
    print("Sources:")
    for source in simulation['sources']:
        print(f"  {source['path']}: {source['source_total_files']} files, {source['source_total_size_mb']} MB")
        # Show first 3 files as example
        for file_info in source['files'][:3]:
            print(f"    - {file_info['filename']} ({file_info['size_mb']} MB)")

    # Original test cases (keeping for reference)
    print("\n--- Original Test Cases ---")