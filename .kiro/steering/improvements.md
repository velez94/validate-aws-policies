# Suggested Improvements: CLI & Developer Best Practices

## CLI Best Practices

### 1. Exit Codes & Error Handling
**Current Issue**: Generic exception handling loses error context
```python
except Exception as err:
    print(str(err))
    return 1
```

**Recommendation**: Use specific exit codes and structured error handling
```python
# Define exit codes
EXIT_SUCCESS = 0
EXIT_VALIDATION_ERROR = 1
EXIT_CONFIG_ERROR = 2
EXIT_AWS_ERROR = 3
EXIT_FILE_ERROR = 4

# Specific exception handling
except FileNotFoundError as e:
    logging.error(f"Policy file not found: {e}")
    return EXIT_FILE_ERROR
except ClientError as e:
    logging.error(f"AWS API error: {e}")
    return EXIT_AWS_ERROR
except ValidationError as e:
    logging.error(f"Policy validation failed: {e}")
    return EXIT_VALIDATION_ERROR
```

### 2. Logging vs Print Statements
**Current Issue**: Mixed use of `print()` and `logging`, inconsistent output control

**Recommendation**: 
- Use logging for all output with proper levels
- Add `--verbose/-v` and `--quiet/-q` flags
- Reserve print() only for primary output (JSON results)
```python
parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
parser.add_argument('--quiet', action='store_true', help='Suppress non-essential output')

# Set logging level based on flags
if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
elif args.quiet:
    logging.basicConfig(level=logging.ERROR)
else:
    logging.basicConfig(level=logging.INFO)
```

### 3. Output Format Options
**Current Issue**: Output format is hardcoded (JSON to stdout, HTML/PDF files)

**Recommendation**: Add `--output-format` flag
```python
parser.add_argument(
    '-f', '--format',
    choices=['json', 'text', 'html', 'pdf'],
    default='json',
    help='Output format for results'
)
parser.add_argument(
    '-o', '--output',
    help='Output file path (default: stdout for json/text)'
)
```

### 4. Configuration File Support
**Current Issue**: All options must be passed as CLI arguments

**Recommendation**: Support config file (YAML/TOML)
```python
parser.add_argument(
    '--config',
    help='Path to configuration file (YAML or TOML)'
)

# Example config.yaml:
# profile: my-aws-profile
# policies_path: ./policies
# upload_report: true
# bucket_name: my-reports-bucket
# create_pdf: true
```

### 5. Dry Run Mode
**Recommendation**: Add `--dry-run` flag for validation without side effects
```python
parser.add_argument(
    '--dry-run',
    action='store_true',
    help='Validate policies without creating reports or uploading'
)
```

### 6. Better Argument Validation
**Current Issue**: Missing validation for required argument combinations
```python
# Current: bucket_name can be None even with upload_report=True
if args.upload_report and bucket_name is not None:
    # upload logic
```

**Recommendation**: Use argparse argument groups and validation
```python
# Make bucket_name required when upload_report is set
if args.upload_report and not args.bucket_name:
    parser.error('--bucket_name is required when --upload_report is set')

# Or use mutually exclusive groups
group = parser.add_mutually_exclusive_group()
group.add_argument('--ci', action='store_true')
group.add_argument('--interactive', action='store_true')
```

### 7. Progress Indicators
**Recommendation**: Add progress bars for batch operations
```python
from tqdm import tqdm

for policy in tqdm(list_policies, desc="Validating policies"):
    # validation logic
```

### 8. Standardize Flag Names
**Current Issue**: Inconsistent flag naming (`-cp` for create_pdf_reports)

**Recommendation**: Use consistent, descriptive names
```python
# Before: -cp, --create_pdf_reports
# After: --pdf, --generate-pdf (use hyphens, not underscores)

parser.add_argument('--pdf', action='store_true', help='Generate PDF report')
parser.add_argument('--zip', action='store_true', help='Create ZIP archive')
parser.add_argument('--upload', action='store_true', help='Upload to S3')
```

## Developer Best Practices

### 1. Testing Infrastructure
**Current Issue**: No tests present

**Recommendation**: Add comprehensive test suite
```
tests/
├── __init__.py
├── conftest.py                    # pytest fixtures
├── unit/
│   ├── test_validate_policies.py
│   ├── test_iam_analyzer.py
│   └── test_ops.py
├── integration/
│   └── test_cli.py
└── fixtures/
    ├── sample_policies/
    └── expected_outputs/
```

**Add to pyproject.toml**:
```toml
[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
    "pytest-mock>=3.10.0",
    "moto>=4.0.0",  # Mock AWS services
]

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
python_functions = ["test_*"]
addopts = "--cov=validate_aws_policies --cov-report=html --cov-report=term"
```

### 2. Code Quality Tools
**Current Issue**: Pre-commit config exists but minimal tooling

**Recommendation**: Enhance pre-commit hooks
```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.9
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
      - id: check-added-large-files
      - id: check-merge-conflict

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.8.0
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
```

**Add ruff configuration to pyproject.toml**:
```toml
[tool.ruff]
line-length = 100
target-version = "py38"

[tool.ruff.lint]
select = [
    "E",   # pycodestyle errors
    "W",   # pycodestyle warnings
    "F",   # pyflakes
    "I",   # isort
    "B",   # flake8-bugbear
    "C4",  # flake8-comprehensions
    "UP",  # pyupgrade
]
ignore = []

[tool.ruff.lint.per-file-ignores]
"__init__.py" = ["F401"]  # Allow unused imports in __init__
```

### 3. Type Hints
**Current Issue**: Minimal type hints

**Recommendation**: Add comprehensive type annotations
```python
from typing import List, Dict, Optional, Any
from pathlib import Path

def validate_policies(
    list_policies: List[str],
    policies_path: Path
) -> List[Dict[str, Any]]:
    """Validate policies using IAM Access Analyzer."""
    ...

def create_report(
    report: str,
    create_zip_files: bool = False,
    create_pdf: bool = False
) -> List[Path]:
    """Create validation reports."""
    ...
```

### 4. Remove Suspicious Import
**Current Issue**: Unused import in ops.py
```python
from psutil.tests.test_process_all import proc_info  # Never used!
```

**Recommendation**: Remove this line entirely

### 5. Use pathlib Instead of os.path
**Current Issue**: Mixed use of string paths and os.path

**Recommendation**: Standardize on pathlib.Path
```python
from pathlib import Path

# Before:
policies_path = args.directory_policies_path
list_policies = os.listdir(policies_path)
file_path = f"{policies_path}/{policy}"

# After:
policies_path = Path(args.directory_policies_path)
list_policies = [p.name for p in policies_path.glob("*.json")]
file_path = policies_path / policy
```

### 6. Context Managers for File Operations
**Current Issue**: Manual file open/close in ops.py
```python
text_file = open(file_path, "r")
data = text_file.read()
text_file.close()
```

**Recommendation**: Use context managers
```python
def read_policies(file_path: Path) -> str:
    """Read policy from file."""
    try:
        with file_path.open('r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        logging.error(f"Policy file not found: {file_path}")
        raise
```

### 7. Environment Variables for Configuration
**Recommendation**: Support environment variables for common settings
```python
import os

# Support env vars with CLI override
profile = args.profile or os.getenv('AWS_PROFILE')
bucket_name = args.bucket_name or os.getenv('REPORTS_BUCKET')
policies_path = args.directory_policies_path or os.getenv('POLICIES_PATH', './policies')
```

### 8. Structured Logging
**Recommendation**: Use structured logging with context
```python
import logging
import json

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            'timestamp': self.formatTime(record),
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module,
        }
        return json.dumps(log_data)

# Add --log-format flag
parser.add_argument(
    '--log-format',
    choices=['text', 'json'],
    default='text',
    help='Log output format'
)
```

### 9. Dependency Management
**Recommendation**: Add dependency groups and version constraints
```toml
[project]
dependencies = [
    "boto3>=1.34.138,<2.0.0",
    "colorama>=0.4.6,<1.0.0",
    "pdfkit>=1.0.0,<2.0.0",
    "json2html>=1.3.0,<2.0.0",
    "zipp>=3.19.2,<4.0.0",
    "argcomplete>=3.4.0,<4.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
    "pytest-mock>=3.10.0",
    "moto>=4.0.0",
    "ruff>=0.1.0",
    "mypy>=1.8.0",
    "pre-commit>=3.0.0",
]
docs = [
    "mkdocs>=1.5.0",
    "mkdocs-material>=9.0.0",
]
```

### 10. CI/CD Improvements
**Recommendation**: Add comprehensive GitHub Actions workflow
```yaml
# .github/workflows/test.yml
name: Test

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.8", "3.9", "3.10", "3.11", "3.12"]
    
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      
      - name: Install dependencies
        run: |
          pip install -e ".[dev]"
      
      - name: Run ruff
        run: ruff check .
      
      - name: Run mypy
        run: mypy src/
      
      - name: Run tests
        run: pytest --cov --cov-report=xml
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

### 11. Documentation Improvements
**Recommendation**: Add comprehensive docstrings and examples
```python
def validate_policies(list_policies: List[str], policies_path: Path) -> List[Dict[str, Any]]:
    """
    Validate AWS policies using IAM Access Analyzer API.
    
    Args:
        list_policies: List of policy filenames to validate (e.g., ['policy1.json'])
        policies_path: Directory path containing policy files
    
    Returns:
        List of validation reports, each containing:
            - filePolicy: Policy filename
            - summary: List of findings with issueCode, findingType, and details
    
    Raises:
        FileNotFoundError: If policies_path doesn't exist
        ClientError: If AWS API call fails
        ValidationError: If policy has ERROR-level findings
    
    Example:
        >>> policies = ['scp-policy.json', 'identity-policy.json']
        >>> path = Path('./policies')
        >>> results = validate_policies(policies, path)
        >>> print(results[0]['summary'])
    """
```

### 12. Error Recovery & Retry Logic
**Recommendation**: Add retry logic for AWS API calls
```python
from botocore.config import Config
from botocore.exceptions import ClientError
import time

# Configure boto3 with retries
config = Config(
    retries={
        'max_attempts': 3,
        'mode': 'adaptive'
    }
)
client = boto3.client('accessanalyzer', config=config)

# Or manual retry for specific operations
def upload_with_retry(file_name: Path, bucket: str, key: str, max_retries: int = 3):
    """Upload file to S3 with exponential backoff retry."""
    for attempt in range(max_retries):
        try:
            s3_client.upload_file(str(file_name), bucket, Key=key)
            return True
        except ClientError as e:
            if attempt == max_retries - 1:
                raise
            wait_time = 2 ** attempt
            logging.warning(f"Upload failed, retrying in {wait_time}s: {e}")
            time.sleep(wait_time)
    return False
```

## Priority Implementation Order

1. **High Priority** (Immediate improvements):
   - Remove suspicious psutil import
   - Add proper exit codes
   - Fix argument validation (bucket_name requirement)
   - Use context managers for file operations
   - Add basic unit tests

2. **Medium Priority** (Next iteration):
   - Enhance logging (verbose/quiet flags)
   - Add type hints throughout
   - Switch to pathlib
   - Add ruff/mypy to pre-commit
   - Add test CI workflow

3. **Low Priority** (Future enhancements):
   - Configuration file support
   - Progress indicators
   - Structured logging
   - Comprehensive integration tests
   - Enhanced documentation
