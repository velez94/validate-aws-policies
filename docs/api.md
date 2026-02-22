# API Reference

## Command-Line Interface

### Main Command

```
validate-aws-policies [OPTIONS]
```

### Options

#### General Options

| Option | Short | Type | Description |
|--------|-------|------|-------------|
| `--help` | `-h` | flag | Show help message |
| `--version` | `-v` | flag | Show version |
| `--config` | | path | Configuration file (YAML/TOML) |

#### AWS Options

| Option | Short | Type | Description |
|--------|-------|------|-------------|
| `--policies-path` | `-d` | path | Directory with policy JSON files |
| `--profile` | `-p` | string | AWS CLI profile name |

#### Output Options

| Option | Short | Type | Description |
|--------|-------|------|-------------|
| `--format` | `-f` | choice | Output format: json, text, html, md, markdown, all |
| `--output` | `-o` | path | Output file path |

#### Report Options

| Option | Short | Type | Description |
|--------|-------|------|-------------|
| `--zip` | `-z` | flag | Create ZIP archive |
| `--upload` | `-u` | flag | Upload to S3 |
| `--bucket` | `-b` | string | S3 bucket name |

#### Execution Options

| Option | Short | Type | Description |
|--------|-------|------|-------------|
| `--ci` | `-c` | flag | CI/CD mode |
| `--dry-run` | | flag | Validate without generating reports |

#### Logging Options

| Option | Short | Type | Description |
|--------|-------|------|-------------|
| `--verbose` | | flag | Enable verbose logging |
| `--quiet` | | flag | Suppress non-essential output |
| `--log-format` | | choice | Log format: text, json |

## Exit Codes

| Code | Constant | Description |
|------|----------|-------------|
| 0 | `EXIT_SUCCESS` | Successful execution |
| 1 | `EXIT_VALIDATION_ERROR` | Policy validation failed |
| 2 | `EXIT_CONFIG_ERROR` | Configuration error |
| 3 | `EXIT_AWS_ERROR` | AWS API error |
| 4 | `EXIT_FILE_ERROR` | File I/O error |

## Python API

### PolicyValidator

Main class for policy validation workflow.

```python
from validate_aws_policies.core.validator import PolicyValidator

config = {
    "policies_path": "./policies",
    "format": "json",
    "profile": "my-profile"
}

validator = PolicyValidator(config)
exit_code = validator.run()
```

#### Methods

##### `__init__(config: Dict[str, Any])`

Initialize validator with configuration.

**Parameters:**
- `config` (dict): Configuration dictionary

**Config Keys:**
- `policies_path` (str): Path to policies directory
- `format` (str): Output format
- `output` (str, optional): Output file path
- `profile` (str, optional): AWS profile name
- `dry_run` (bool): Skip report generation
- `upload` (bool): Upload to S3
- `bucket` (str): S3 bucket name
- `zip` (bool): Create ZIP archive

##### `run() -> int`

Execute validation workflow.

**Returns:**
- `int`: Exit code

### validate_policies

Core validation function.

```python
from validate_aws_policies.core.iam_analyzer import validate_policies
from pathlib import Path

policy_files = ["policy1.json", "policy2.json"]
policies_path = Path("./policies")

results = validate_policies(policy_files, policies_path)
```

**Parameters:**
- `list_policies` (List[str]): List of policy filenames
- `policies_path` (Path): Directory containing policies

**Returns:**
- `List[Dict[str, Any]]`: Validation results

**Result Structure:**
```python
[
    {
        "filePolicy": "policy.json",
        "summary": [
            {
                "findingType": "WARNING",
                "issueCode": "PASS_ROLE_WITH_STAR_IN_RESOURCE",
                "details": "Description of the issue..."
            }
        ]
    }
]
```

### ReportGenerator

Generate reports in various formats.

```python
from validate_aws_policies.ops.reports import ReportGenerator

generator = ReportGenerator()

# Generate HTML report
html_file = generator.create_html_report(results)

# Generate Markdown report
md_file = generator.create_markdown_report(results)

# Create ZIP archive
zip_file = generator.create_zip([html_file, md_file])
```

#### Methods

##### `create_html_report(results: List[Dict[str, Any]]) -> Path`

Generate HTML report.

**Parameters:**
- `results` (list): Validation results

**Returns:**
- `Path`: Path to generated HTML file

##### `create_markdown_report(results: List[Dict[str, Any]]) -> Path`

Generate Markdown report.

**Parameters:**
- `results` (list): Validation results

**Returns:**
- `Path`: Path to generated Markdown file

##### `create_zip(file_paths: List[Path]) -> Path`

Create ZIP archive of files.

**Parameters:**
- `file_paths` (list): List of file paths to archive

**Returns:**
- `Path`: Path to generated ZIP file

### upload_file

Upload file to S3.

```python
from validate_aws_policies.ops.s3_ops import upload_file
from pathlib import Path

file_path = Path("report.html")
bucket = "my-bucket"
key = "reports/report.html"

upload_file(file_path, bucket, key)
```

**Parameters:**
- `file_name` (Path): File to upload
- `bucket` (str): S3 bucket name
- `object_name` (str): S3 object key

**Raises:**
- `ClientError`: If upload fails

## Configuration Schema

### YAML Schema

```yaml
# Required
policies_path: string

# Optional
profile: string
format: "json" | "text" | "html" | "md" | "markdown" | "all"
output: string
zip: boolean
upload: boolean
bucket: string
ci: boolean
dry_run: boolean
verbose: boolean
quiet: boolean
log_format: "text" | "json"
```

### TOML Schema

```toml
# Required
policies_path = "string"

# Optional
profile = "string"
format = "json" | "text" | "html" | "md" | "markdown" | "all"
output = "string"
zip = false
upload = false
bucket = "string"
ci = false
dry_run = false
verbose = false
quiet = false
log_format = "text"
```

## Finding Types

### ERROR

Critical issues that must be fixed:

- `INVALID_SYNTAX` - Policy has syntax errors
- `INVALID_ACTION` - Action doesn't exist
- `INVALID_RESOURCE` - Resource ARN is invalid

### WARNING

Issues that should be reviewed:

- `PASS_ROLE_WITH_STAR_IN_RESOURCE` - Overly permissive PassRole
- `MISSING_VERSION` - Policy missing Version field
- `REDUNDANT_STATEMENT` - Statement is redundant

### SUGGESTION

Recommendations for improvement:

- `SIMPLIFY_POLICY` - Policy can be simplified
- `USE_MANAGED_POLICY` - Consider using managed policy

### SECURITY_WARNING

Security-related concerns:

- `EXTERNAL_PRINCIPAL` - External account access
- `PUBLIC_ACCESS` - Resource allows public access
