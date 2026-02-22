# CLI Configuration Module

This module provides configuration management for the validate-aws-policies CLI tool.

## Features

- **Multiple Configuration Sources**: Load configuration from defaults, files, and environment variables
- **Precedence Handling**: Proper precedence order (defaults < file < env vars < CLI args)
- **Multiple Formats**: Support for YAML and TOML configuration files
- **Environment Variables**: Standard environment variable support
- **Type Safety**: Full type hints throughout

## Configuration Precedence

Configuration is loaded in the following order (lowest to highest priority):

1. **Default values** (lowest priority)
2. **Configuration file** (YAML or TOML)
3. **Environment variables**
4. **CLI arguments** (highest priority - handled by argparse)

## Usage

### Basic Usage

```python
from validate_aws_policies.cli.config import ConfigLoader

# Load configuration from defaults and environment variables
loader = ConfigLoader()
config = loader.load_config()

# Access configuration values
profile = config['profile']
bucket = config.get('bucket_name', 'default-bucket')
```

### With Configuration File

```python
# Load from YAML file
loader = ConfigLoader(config_file='config.yaml')
config = loader.load_config()

# Load from TOML file
loader = ConfigLoader(config_file='config.toml')
config = loader.load_config()
```

### Environment Variables

The following environment variables are supported:

| Environment Variable | Config Key | Description |
|---------------------|------------|-------------|
| `AWS_PROFILE` | `profile` | AWS profile name for Access Analyzer API |
| `REPORTS_BUCKET` | `bucket_name` | S3 bucket for report uploads |
| `POLICIES_PATH` | `directory_policies_path` | Directory containing policy files |
| `LOG_LEVEL` | `log_level` | Logging level (DEBUG, INFO, WARNING, ERROR) |

Example:

```bash
export AWS_PROFILE=my-profile
export REPORTS_BUCKET=my-bucket
export POLICIES_PATH=/path/to/policies
export LOG_LEVEL=DEBUG

validate-aws-policies -d /path/to/policies
```

## Configuration File Format

### YAML Example

```yaml
# config.yaml
profile: my-aws-profile
bucket_name: my-reports-bucket
directory_policies_path: ./policies
upload_report: true
zip_reports: false
ci: false
log_level: INFO
```

### TOML Example

```toml
# config.toml
profile = "my-aws-profile"
bucket_name = "my-reports-bucket"
directory_policies_path = "./policies"
upload_report = true
zip_reports = false
ci = false
log_level = "INFO"
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `profile` | str | None | AWS profile name |
| `bucket_name` | str | None | S3 bucket for reports |
| `directory_policies_path` | str | "./policies" | Policy files directory |
| `upload_report` | bool | False | Upload reports to S3 |
| `zip_reports` | bool | False | Create ZIP archive |
| `ci` | bool | False | CI/CD mode |
| `log_level` | str | "INFO" | Logging level |

## Error Handling

The `ConfigLoader` raises `ConfigError` exceptions for:

- Configuration file not found
- Unsupported file format
- Invalid YAML/TOML syntax
- Missing required dependencies (pyyaml, tomli)

Example:

```python
from validate_aws_policies.cli.config import ConfigLoader, ConfigError

try:
    loader = ConfigLoader(config_file='config.yaml')
    config = loader.load_config()
except ConfigError as e:
    print(f"Configuration error: {e}")
```

## Dependencies

### Required
- Python 3.8+

### Optional
- `pyyaml` - For YAML configuration file support
- `tomli` - For TOML configuration file support (Python < 3.11)

Install optional dependencies:

```bash
pip install pyyaml tomli
```

## Testing

Run the test suite:

```bash
pytest tests/unit/test_config.py -v
```

## Integration with CLI

The ConfigLoader is designed to work seamlessly with argparse:

```python
import argparse
from validate_aws_policies.cli.config import ConfigLoader

# Load configuration
loader = ConfigLoader(config_file=args.config if hasattr(args, 'config') else None)
config = loader.load_config()

# Override with CLI arguments (highest priority)
if args.profile:
    config['profile'] = args.profile
if args.bucket_name:
    config['bucket_name'] = args.bucket_name
```

This ensures CLI arguments always take precedence over all other configuration sources.
