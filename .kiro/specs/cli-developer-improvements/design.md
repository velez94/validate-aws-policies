# Design Document: CLI & Developer Improvements

## Overview

This design refactors the AWS policy validation CLI tool to improve error handling, logging, configuration management, and code quality. The implementation uses Python 3.8+ with type hints, structured error handling, and modern CLI best practices.

## Architecture

### Module Structure

```
src/validate_aws_policies/
├── __init__.py
├── version.py
├── validate_policies.py      # Main CLI entry point (refactored)
├── cli/
│   ├── __init__.py
│   ├── args.py               # Argument parsing and validation
│   ├── config.py             # Configuration file handling
│   └── exit_codes.py         # Exit code constants
├── core/
│   ├── __init__.py
│   └── validator.py          # Core validation orchestration
├── iam_access_analyzer/
│   ├── __init__.py
│   └── iam_access_analyzer.py  # AWS API integration (refactored)
└── ops/
    ├── __init__.py
    ├── ops.py                # File operations (refactored)
    └── reports.py            # Report generation (extracted)
```

### Key Design Decisions

1. **Exit Codes**: Define constants for different error types
2. **Logging**: Replace print statements with structured logging
3. **Configuration**: Support YAML/TOML config files with CLI override
4. **Type Safety**: Add comprehensive type hints throughout
5. **Error Handling**: Specific exception types with proper context
6. **Separation of Concerns**: Extract report generation from ops module

## Component Designs

### 1. Exit Codes Module (`cli/exit_codes.py`)

**Purpose**: Centralize exit code definitions for consistent error handling.

**Requirements**: 1.1-1.6

```python

"""Exit code constants for CLI."""

EXIT_SUCCESS = 0
EXIT_VALIDATION_ERROR = 1
EXIT_CONFIG_ERROR = 2
EXIT_AWS_ERROR = 3
EXIT_FILE_ERROR = 4
```

### 2. Configuration Module (`cli/config.py`)

**Purpose**: Load and merge configuration from files, environment variables, and CLI arguments.

**Requirements**: 4.1-4.5, 7.1-7.4

```python
from typing import Dict, Any, Optional
from pathlib import Path
import yaml
import tomli
import os

class ConfigLoader:
    """Load configuration from multiple sources with precedence."""
    
    def load_config(self, config_path: Optional[Path] = None) -> Dict[str, Any]:
        """Load configuration with precedence: CLI > env vars > config file > defaults."""
        config = self._load_defaults()
        
        if config_path:
            file_config = self._load_file(config_path)
            config.update(file_config)
        
        env_config = self._load_env_vars()
        config.update(env_config)
        
        return config
    
    def _load_defaults(self) -> Dict[str, Any]:
        """Return default configuration values."""
        return {
            'policies_path': './policies',
            'format': 'json',
            'log_level': 'INFO',
            'create_zip': False,
            'create_pdf': False,
            'upload_report': False,
        }
    
    def _load_file(self, path: Path) -> Dict[str, Any]:
        """Load configuration from YAML or TOML file."""
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        
        if path.suffix in ['.yaml', '.yml']:
            with path.open('r') as f:
                return yaml.safe_load(f) or {}
        elif path.suffix == '.toml':
            with path.open('rb') as f:
                return tomli.load(f)
        else:
            raise ValueError(f"Unsupported config format: {path.suffix}")
    
    def _load_env_vars(self) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        env_config = {}
        
        if profile := os.getenv('AWS_PROFILE'):
            env_config['profile'] = profile
        if bucket := os.getenv('REPORTS_BUCKET'):
            env_config['bucket_name'] = bucket
        if policies_path := os.getenv('POLICIES_PATH'):
            env_config['policies_path'] = policies_path
        
        return env_config
```

### 3. Argument Parser Module (`cli/args.py`)

**Purpose**: Define and validate CLI arguments with proper error messages.

**Requirements**: 2.1-2.5, 3.1-3.6, 5.1-5.4, 6.1-6.4, 8.1-8.5

```python
import argparse
from pathlib import Path
from typing import Optional
import argcomplete

from .exit_codes import EXIT_CONFIG_ERROR

def create_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        description='Validate AWS policies using IAM Access Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Core arguments
    parser.add_argument(
        '-d', '--policies-path',
        type=Path,
        help='Directory containing policy JSON files'
    )
    
    # Output control
    parser.add_argument(
        '-f', '--format',
        choices=['json', 'text', 'html', 'pdf'],
        default='json',
        help='Output format (default: json)'
    )
    parser.add_argument(
        '-o', '--output',
        type=Path,
        help='Output file path (default: stdout for json/text)'
    )
    
    # Logging control
    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output (DEBUG level)'
    )
    log_group.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress non-essential output (ERROR level only)'
    )
    
    # AWS configuration
    parser.add_argument(
        '-p', '--profile',
        help='AWS CLI profile name'
    )
    
    # Report options
    parser.add_argument(
        '--pdf',
        action='store_true',
        help='Generate PDF report'
    )
    parser.add_argument(
        '--zip',
        action='store_true',
        help='Create ZIP archive of reports'
    )
    
    # Upload options
    parser.add_argument(
        '--upload',
        action='store_true',
        help='Upload reports to S3'
    )
    parser.add_argument(
        '--bucket',
        help='S3 bucket name for report uploads'
    )
    
    # Operational modes
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Validate policies without creating reports or uploading'
    )
    parser.add_argument(
        '--ci',
        action='store_true',
        help='CI/CD mode (minimal output)'
    )
    
    # Configuration
    parser.add_argument(
        '--config',
        type=Path,
        help='Configuration file path (YAML or TOML)'
    )
    
    # Version
    parser.add_argument(
        '--version',
        action='store_true',
        help='Show version and exit'
    )
    
    argcomplete.autocomplete(parser)
    return parser

def validate_args(args: argparse.Namespace) -> None:
    """Validate argument combinations and requirements."""
    errors = []
    
    # Requirement 6.1: upload requires bucket
    if args.upload and not args.bucket:
        errors.append('--bucket is required when --upload is set')
    
    # Requirement 6.2: policies_path is required (unless --version)
    if not args.version and not args.policies_path:
        errors.append('--policies-path is required')
    
    # Requirement 6.3: verbose and quiet are mutually exclusive (handled by argparse)
    
    if errors:
        raise ValueError('\n'.join(errors))
```

### 4. Core Validator Module (`core/validator.py`)

**Purpose**: Orchestrate the validation workflow with proper error handling.

**Requirements**: 1.1-1.6, 5.1-5.4

```python
from typing import List, Dict, Any
from pathlib import Path
import logging

from ..iam_access_analyzer.iam_access_analyzer import validate_policies
from ..ops.reports import ReportGenerator
from ..ops.ops import upload_file
from .exit_codes import EXIT_SUCCESS, EXIT_VALIDATION_ERROR, EXIT_AWS_ERROR, EXIT_FILE_ERROR

logger = logging.getLogger(__name__)

class PolicyValidator:
    """Orchestrate policy validation workflow."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.report_generator = ReportGenerator()
    
    def run(self) -> int:
        """Execute validation workflow and return exit code."""
        try:
            # Get policy files
            policies_path = Path(self.config['policies_path'])
            if not policies_path.exists():
                logger.error(f"Policies directory not found: {policies_path}")
                return EXIT_FILE_ERROR
            
            policy_files = self._get_policy_files(policies_path)
            if not policy_files:
                logger.warning(f"No policy files found in {policies_path}")
                return EXIT_SUCCESS
            
            # Validate policies
            logger.info(f"Validating {len(policy_files)} policies...")
            results = validate_policies(policy_files, policies_path)
            
            # Output results
            self._output_results(results)
            
            # Generate reports (unless dry-run)
            if not self.config.get('dry_run', False):
                report_files = self._generate_reports(results)
                
                # Upload reports if requested
                if self.config.get('upload_report', False):
                    self._upload_reports(report_files)
            
            return EXIT_SUCCESS
            
        except FileNotFoundError as e:
            logger.error(f"File error: {e}")
            return EXIT_FILE_ERROR
        except Exception as e:
            logger.error(f"Validation error: {e}")
            return EXIT_VALIDATION_ERROR
    
    def _get_policy_files(self, path: Path) -> List[str]:
        """Get list of JSON policy files."""
        return [f.name for f in path.glob('*.json')]
    
    def _output_results(self, results: List[Dict[str, Any]]) -> None:
        """Output validation results based on format."""
        format_type = self.config.get('format', 'json')
        output_path = self.config.get('output')
        
        if format_type == 'json':
            import json
            output = json.dumps(results, indent=2)
            if output_path:
                Path(output_path).write_text(output)
            else:
                print(output)
        elif format_type == 'text':
            output = self._format_text_output(results)
            if output_path:
                Path(output_path).write_text(output)
            else:
                print(output)
    
    def _format_text_output(self, results: List[Dict[str, Any]]) -> str:
        """Format results as human-readable text."""
        lines = ["Policy Validation Results", "=" * 50, ""]
        for result in results:
            lines.append(f"Policy: {result['filePolicy']}")
            for finding in result['summary']:
                lines.append(f"  - {finding['findingType']}: {finding['issueCode']}")
            lines.append("")
        return "\n".join(lines)
    
    def _generate_reports(self, results: List[Dict[str, Any]]) -> List[Path]:
        """Generate report files based on configuration."""
        report_files = []
        
        if self.config.get('format') in ['html', 'pdf']:
            html_file = self.report_generator.create_html_report(results)
            report_files.append(html_file)
            
            if self.config.get('pdf') or self.config.get('format') == 'pdf':
                pdf_file = self.report_generator.create_pdf_report(html_file)
                report_files.append(pdf_file)
        
        if self.config.get('zip'):
            zip_file = self.report_generator.create_zip(report_files)
            report_files = [zip_file]
        
        return report_files
    
    def _upload_reports(self, files: List[Path]) -> None:
        """Upload report files to S3."""
        from datetime import datetime
        
        bucket = self.config['bucket_name']
        date = datetime.today().strftime("%Y/%m/%d")
        
        for file_path in files:
            key = f"AccessAnalyzer/{date}/{file_path.name}"
            upload_file(file_path, bucket, key)
```

### 5. Refactored Main Entry Point (`validate_policies.py`)

**Purpose**: Clean main function that orchestrates configuration, logging, and validation.

**Requirements**: All requirements integrated

```python
import logging
import sys
from pathlib import Path

from .cli.args import create_parser, validate_args
from .cli.config import ConfigLoader
from .cli.exit_codes import EXIT_CONFIG_ERROR, EXIT_FILE_ERROR
from .core.validator import PolicyValidator
from .version import __version__

def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure logging based on verbosity flags."""
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.ERROR
    else:
        level = logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def main() -> int:
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Handle version
    if args.version:
        print(f"validate-aws-policies {__version__}")
        return 0
    
    # Setup logging
    setup_logging(args.verbose, args.quiet)
    logger = logging.getLogger(__name__)
    
    try:
        # Validate arguments
        validate_args(args)
        
        # Load configuration
        config_loader = ConfigLoader()
        config = config_loader.load_config(args.config)
        
        # Override with CLI arguments
        cli_config = {k: v for k, v in vars(args).items() if v is not None}
        config.update(cli_config)
        
        # Run validation
        validator = PolicyValidator(config)
        return validator.run()
        
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return EXIT_CONFIG_ERROR
    except FileNotFoundError as e:
        logger.error(f"File error: {e}")
        return EXIT_FILE_ERROR
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return EXIT_CONFIG_ERROR

if __name__ == "__main__":
    sys.exit(main())
```



### 6. Refactored File Operations (`ops/ops.py`)

**Purpose**: Clean up file operations with pathlib and context managers.

**Requirements**: 9.1-9.3, 10.1-10.3

```python
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger(__name__)

def read_policies(file_path: Path) -> str:
    """Read policy from file with proper error handling."""
    try:
        with file_path.open('r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        logger.error(f"Policy file not found: {file_path}")
        raise
    except Exception as e:
        logger.error(f"Error reading policy file {file_path}: {e}")
        raise

def validate_findings(policy: str, findings: list) -> dict:
    """Validate findings and return structured summary."""
    policy_name = Path(policy).stem
    summary = {"filePolicy": policy, "summary": []}
    
    if not findings:
        logger.info(f"✅ No findings for {policy}")
        summary["summary"].append({
            "policyName": policy_name,
            "issueCode": "None",
            "findingType": "None",
            "details": "No findings",
        })
    else:
        logger.info(f"Found {len(findings)} findings for {policy_name}")
        
        for finding in findings:
            if finding["findingType"] == "ERROR":
                logger.error(f"ERROR finding in {policy_name}: {finding}")
                raise ValueError(f"ERROR-level finding in policy {policy_name}")
            
            logger.warning(f"Finding in {policy_name}: {finding['findingType']}")
            summary["summary"].append({
                "policyName": policy_name,
                "issueCode": finding.get("issueCode"),
                "findingType": finding["findingType"],
                "details": finding,
            })
    
    return summary
```

### 7. Report Generation Module (`ops/reports.py`)

**Purpose**: Extract report generation logic into dedicated module.

**Requirements**: 3.1-3.6

```python
from pathlib import Path
from typing import List
from datetime import datetime
from zipfile import ZipFile
import logging
import json

import pdfkit
from json2html import json2html

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generate validation reports in various formats."""
    
    def create_html_report(self, results: list) -> Path:
        """Create HTML report from validation results."""
        timestamp = datetime.now()
        file_name = Path(f"AccessAnalyzerReport_{timestamp}.html")
        
        html_header = """
        <html>
        <style>
        .fl-table {
            border-radius: 5px;
            font-size: 12px;
            border: none;
            border-collapse: collapse;
            width: 100%;
            background-color: white;
        }
        .fl-table td, .fl-table th {
            text-align: left;
            padding: 8px;
            border: solid 1px #777;
        }
        .fl-table thead th {
            color: #ffffff;
            background: #4FC3D8;
        }
        .fl-table tr:nth-child(even) {
            background: #F8F8FA;
        }
        </style>
        <h1>Validate AWS Policies Report</h1>
        <p><em>Access Analyzer Report for Permissions Set</em></p>
        </html>
        """
        
        with file_name.open('w', encoding='utf-8') as f:
            f.write(html_header)
            content = json2html.convert(
                json=json.dumps(results),
                table_attributes='class="fl-table"'
            )
            f.write(content)
        
        logger.info(f"Created HTML report: {file_name}")
        return file_name
    
    def create_pdf_report(self, html_file: Path) -> Path:
        """Create PDF report from HTML file."""
        pdf_file = html_file.with_suffix('.pdf')
        
        options = {
            'page-size': 'A0',
            'margin-top': '0.7in',
            'margin-right': '0.7in',
            'margin-bottom': '0.7in',
            'margin-left': '0.7in',
            'encoding': 'UTF-8',
            'orientation': 'Landscape',
        }
        
        pdfkit.from_file(str(html_file), str(pdf_file), options=options)
        logger.info(f"Created PDF report: {pdf_file}")
        return pdf_file
    
    def create_zip(self, file_paths: List[Path]) -> Path:
        """Create ZIP archive of report files."""
        timestamp = datetime.now()
        zip_name = Path(f"reports_{timestamp}.zip")
        
        with ZipFile(zip_name, 'w') as zipf:
            for file_path in file_paths:
                zipf.write(file_path)
                logger.debug(f"Added {file_path} to ZIP")
        
        logger.info(f"Created ZIP archive: {zip_name}")
        return zip_name
```

### 8. Refactored IAM Analyzer (`iam_access_analyzer/iam_access_analyzer.py`)

**Purpose**: Add type hints and improve error handling.

**Requirements**: 1.1-1.6, 10.1-10.3

```python
from typing import List, Dict, Any
from pathlib import Path
import logging

import boto3
from botocore.exceptions import ClientError

from ..ops.ops import read_policies, validate_findings
from ..cli.exit_codes import EXIT_AWS_ERROR

logger = logging.getLogger(__name__)

def validate_policies(
    list_policies: List[str],
    policies_path: Path
) -> List[Dict[str, Any]]:
    """
    Validate policies using IAM Access Analyzer API.
    
    Args:
        list_policies: List of policy filenames to validate
        policies_path: Directory path containing policy files
    
    Returns:
        List of validation reports with findings
    
    Raises:
        ClientError: If AWS API call fails
        FileNotFoundError: If policy file doesn't exist
    """
    report = []
    
    try:
        client = boto3.client("accessanalyzer")
        paginator = client.get_paginator("validate_policy")
        
        for policy_file in list_policies:
            logger.info(f"Validating {policy_file}...")
            
            file_path = policies_path / policy_file
            policy_document = read_policies(file_path)
            
            response_iterator = paginator.paginate(
                policyDocument=policy_document,
                policyType="IDENTITY_POLICY",
                locale="EN",
                PaginationConfig={
                    "MaxItems": 100,
                    "PageSize": 20,
                },
            )
            
            findings = []
            for page in response_iterator:
                findings.extend(page.get("findings", []))
            
            result = validate_findings(policy_file, findings)
            report.append(result)
        
        return report
        
    except ClientError as e:
        logger.error(f"AWS API error: {e}")
        raise
    except FileNotFoundError as e:
        logger.error(f"Policy file not found: {e}")
        raise
```

### 9. Upload Function with Retry (`ops/ops.py` addition)

**Purpose**: Add retry logic for S3 uploads.

**Requirements**: 11.1-11.3

```python
import time
from pathlib import Path
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config

def upload_file(
    file_path: Path,
    bucket: str,
    key: str,
    max_retries: int = 3
) -> bool:
    """
    Upload file to S3 with exponential backoff retry.
    
    Args:
        file_path: Local file path to upload
        bucket: S3 bucket name
        key: S3 object key
        max_retries: Maximum number of retry attempts
    
    Returns:
        True if upload successful
    
    Raises:
        ClientError: If upload fails after all retries
    """
    config = Config(
        retries={
            'max_attempts': max_retries,
            'mode': 'adaptive'
        }
    )
    s3_client = boto3.client('s3', config=config)
    
    for attempt in range(max_retries):
        try:
            s3_client.upload_file(str(file_path), bucket, Key=key)
            logger.info(f"✨ Uploaded {file_path.name} to s3://{bucket}/{key}")
            return True
        except ClientError as e:
            if attempt == max_retries - 1:
                logger.error(f"Failed to upload after {max_retries} attempts: {e}")
                raise
            
            wait_time = 2 ** attempt
            logger.warning(f"Upload failed, retrying in {wait_time}s: {e}")
            time.sleep(wait_time)
    
    return False
```

## Testing Strategy

### Unit Tests Structure

```
tests/
├── __init__.py
├── conftest.py
├── unit/
│   ├── test_exit_codes.py
│   ├── test_config.py
│   ├── test_args.py
│   ├── test_validator.py
│   ├── test_ops.py
│   └── test_reports.py
├── integration/
│   ├── test_cli.py
│   └── test_end_to_end.py
└── fixtures/
    ├── sample_policies/
    │   ├── valid_policy.json
    │   └── invalid_policy.json
    ├── config_files/
    │   ├── valid_config.yaml
    │   └── valid_config.toml
    └── expected_outputs/
```

### Test Coverage Requirements

- Unit tests for all new modules (>80% coverage)
- Integration tests for CLI argument combinations
- Mock AWS API calls using moto library
- Test all error paths and exit codes
- Test configuration precedence (file < env < CLI)

## Dependencies

### New Dependencies

```toml
[project]
dependencies = [
    "boto3>=1.34.138,<2.0.0",
    "colorama>=0.4.6,<1.0.0",
    "pdfkit>=1.0.0,<2.0.0",
    "json2html>=1.3.0,<2.0.0",
    "argcomplete>=3.4.0,<4.0.0",
    "pyyaml>=6.0.0,<7.0.0",      # NEW: YAML config support
    "tomli>=2.0.0,<3.0.0",       # NEW: TOML config support (Python <3.11)
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
    "pytest-mock>=3.10.0",
    "moto>=4.0.0",
    "ruff>=0.1.0",
    "mypy>=1.8.0",
    "types-pyyaml",
]
```

## Migration Path

### Phase 1: Core Infrastructure
1. Create new module structure
2. Implement exit codes
3. Implement configuration loader
4. Refactor argument parser

### Phase 2: Core Logic
5. Refactor main entry point
6. Implement validator orchestrator
7. Refactor file operations
8. Extract report generation

### Phase 3: Testing & Quality
9. Add unit tests
10. Add integration tests
11. Update pre-commit hooks
12. Add type checking

## Correctness Properties

### Property 1: Exit Code Consistency
**For all executions**: The exit code SHALL match the error type
- Success → 0
- Validation error → 1
- Config error → 2
- AWS error → 3
- File error → 4

**Validates**: Requirements 1.1-1.6

### Property 2: Configuration Precedence
**For all configuration sources**: CLI arguments SHALL override environment variables SHALL override config file SHALL override defaults

**Validates**: Requirements 4.3, 7.4

### Property 3: Dry Run Safety
**When dry-run flag is set**: No files SHALL be created AND no S3 uploads SHALL occur

**Validates**: Requirements 5.2, 5.3

### Property 4: Argument Validation
**When invalid argument combinations are provided**: The system SHALL exit with code 2 AND display clear error message

**Validates**: Requirements 6.1-6.4

### Property 5: Logging Level Control
**When verbosity flags are set**: Log output SHALL match the specified level (DEBUG for --verbose, ERROR for --quiet, INFO for default)

**Validates**: Requirements 2.1-2.3

## Implementation Notes

1. Remove the suspicious `from psutil.tests.test_process_all import proc_info` import
2. Use pathlib.Path throughout instead of string paths
3. All file operations use context managers
4. Type hints on all functions
5. Structured logging with proper levels
6. Specific exception types with context

## Backward Compatibility

### Breaking Changes
- Flag names changed (e.g., `-cp` → `--pdf`)
- Default output to stdout for JSON (was file)
- Logging output format changed

### Migration Guide
- Update CI/CD scripts to use new flag names
- Update documentation with new CLI interface
- Provide deprecation warnings for old flags (optional)
