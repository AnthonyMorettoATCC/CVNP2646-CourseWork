from pathlib import Path
from collections import defaultdict
import shutil
from datetime import datetime
import logging

# Setup logging for better error tracking
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class FileOrganizer:
    """Organizes files by extension into category folders."""
    
    def __init__(self, source_dir):
        """Initialize with source directory path."""
        self.source_dir = Path(source_dir).resolve()  # Resolve to absolute path
        
        # Validate directory exists
        if not self.source_dir.exists():
            raise ValueError(f"Directory does not exist: {self.source_dir}")
        if not self.source_dir.is_dir():
            raise ValueError(f"Path is not a directory: {self.source_dir}")
        
        self.file_categories = defaultdict(list)
        self.report_data = {
            'total_files': 0,
            'organized_files': 0,
            'errors': []
        }
    
    def scan_directory(self):
        """
        Scans directory and collects files by extension.
        
        Returns: Dictionary mapping extensions to file paths
        """
        print(f"📁 Scanning {self.source_dir}...")
        
        try:
            for file_path in self.source_dir.rglob('*'):
                # Only process actual files, skip directories
                if not file_path.is_file(follow_symlinks=False):
                    continue
                
                # Security: Verify file is within source directory
                try:
                    file_path.relative_to(self.source_dir)
                except ValueError:
                    logger.warning(f"Skipping file outside source directory: {file_path}")
                    continue
                
                ext = file_path.suffix.lower() or 'no_extension'
                self.file_categories[ext].append(file_path)
                self.report_data['total_files'] += 1
        
        except PermissionError as e:
            error_msg = f"Permission denied accessing directory: {e}"
            self.report_data['errors'].append(error_msg)
            logger.error(error_msg)
        
        print(f"✓ Found {self.report_data['total_files']} files")
        return self.file_categories
    
    def categorize_files(self):
        """
        Groups extensions into logical categories.
        
        Returns: Dictionary mapping categories to file extensions
        """
        category_map = {
            'Images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg'],
            'Documents': ['.pdf', '.doc', '.docx', '.txt', '.xlsx', '.pptx'],
            'Code': ['.py', '.js', '.html', '.css', '.json', '.xml'],
            'Archives': ['.zip', '.tar', '.gz', '.rar', '.7z'],
            'Media': ['.mp4', '.mp3', '.avi', '.mov', '.wav']
        }
        
        return category_map
    
    def _get_unique_path(self, target_path):
        """
        Generate unique filename if target already exists.
        
        Parameters:
        - target_path: Path object for the target file
        
        Returns: Unique Path object
        """
        if not target_path.exists():
            return target_path
        
        counter = 1
        stem = target_path.stem
        suffix = target_path.suffix
        parent = target_path.parent
        
        # Keep incrementing until we find an available name
        while True:
            new_name = f"{stem}_{counter}{suffix}"
            new_path = parent / new_name
            if not new_path.exists():
                return new_path
            counter += 1
    
    def move_files(self, category_map):
        """
        Moves files into category folders based on extension.
        
        Parameters:
        - category_map: Dictionary of categories and their extensions
        """
        print(f"\n📦 Organizing files into categories...\n")
        
        # Create 'Other' category for uncategorized files
        if 'Other' not in category_map:
            category_map = {**category_map, 'Other': []}
        
        # Create category folders
        for category in category_map.keys():
            category_dir = self.source_dir / category
            try:
                category_dir.mkdir(exist_ok=True)
            except OSError as e:
                error_msg = f"Failed to create folder '{category}': {e}"
                self.report_data['errors'].append(error_msg)
                logger.error(error_msg)
                continue
        
        # Move files
        for extension, file_paths in self.file_categories.items():
            # Find which category this extension belongs to
            target_category = 'Other'
            
            for category, extensions in category_map.items():
                if extension in extensions:
                    target_category = category
                    break
            
            target_dir = self.source_dir / target_category
            
            for file_path in file_paths:
                try:
                    # Skip if trying to move a category folder
                    if file_path.parent == self.source_dir and file_path.name == target_category:
                        continue
                    
                    new_path = target_dir / file_path.name
                    new_path = self._get_unique_path(new_path)
                    
                    shutil.move(str(file_path), str(new_path))
                    self.report_data['organized_files'] += 1
                    print(f"✓ Moved: {file_path.name} → {target_category}/")
                
                except FileNotFoundError:
                    error_msg = f"File not found (may have been moved): {file_path.name}"
                    self.report_data['errors'].append(error_msg)
                    logger.warning(error_msg)
                
                except OSError as e:
                    error_msg = f"Error moving {file_path.name}: {e}"
                    self.report_data['errors'].append(error_msg)
                    logger.error(error_msg)
    
    def generate_report(self, output_file='organization_report.txt'):
        """
        Generates a text report of the organization process.
        
        Parameters:
        - output_file: Path to save the report
        """
        print(f"\n📋 Generating report...")
        
        report_lines = []
        report_lines.append("=" * 70)
        report_lines.append("FILE ORGANIZATION REPORT")
        report_lines.append("=" * 70)
        report_lines.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Source Directory: {self.source_dir}")
        report_lines.append("")
        
        report_lines.append("-" * 70)
        report_lines.append("SUMMARY")
        report_lines.append("-" * 70)
        report_lines.append(f"Total Files Found: {self.report_data['total_files']}")
        report_lines.append(f"Files Successfully Organized: {self.report_data['organized_files']}")
        report_lines.append(f"Errors: {len(self.report_data['errors'])}")
        report_lines.append("")
        
        report_lines.append("-" * 70)
        report_lines.append("FILES BY EXTENSION")
        report_lines.append("-" * 70)
        for ext, files in sorted(self.file_categories.items()):
            report_lines.append(f"{ext:15} : {len(files):3} files")
        report_lines.append("")
        
        if self.report_data['errors']:
            report_lines.append("-" * 70)
            report_lines.append("ERRORS")
            report_lines.append("-" * 70)
            for error in self.report_data['errors']:
                report_lines.append(f"  • {error}")
            report_lines.append("")
        
        report_lines.append("=" * 70)
        
        # Write to file
        try:
            output_path = self.source_dir / output_file
            with open(output_path, 'w') as f:
                f.write('\n'.join(report_lines))
            print(f"✓ Report saved to {output_file}")
        except OSError as e:
            logger.error(f"Failed to write report: {e}")
        
        return report_lines


# Main usage
if __name__ == "__main__":
    try:
        organizer = FileOrganizer('.')
        organizer.scan_directory()
        categories = organizer.categorize_files()
        organizer.move_files(categories)
        organizer.generate_report()
    except ValueError as e:
        logger.error(f"Invalid configuration: {e}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")