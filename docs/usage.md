# Usage Guide

## Basic Commands

### Validate Policies

```bash
validate-aws-policies --policies-path ./policies
```

### Specify AWS Profile

```bash
validate-aws-policies --policies-path ./policies -p my-profile
```

### Generate Reports

#### JSON Output (Default)

```bash
validate-aws-policies --policies-path ./policies
```

#### Text Output

```bash
validate-aws-policies --policies-path ./policies --format text
```

#### HTML Report

```bash
validate-aws-policies --policies-path ./policies --format html
```

#### Markdown Report

```bash
validate-aws-policies --policies-path ./policies --format md
```

#### All Formats

```bash
validate-aws-policies --policies-path ./policies --format all
```

### Save Output to File

```bash
validate-aws-policies --policies-path ./policies --format json -o results.json
```

### Create ZIP Archive

```bash
validate-aws-policies --policies-path ./policies --format all --zip
```

### Upload to S3

```bash
validate-aws-policies --policies-path ./policies --format html --upload -b my-bucket
```

## Advanced Usage

### Dry Run Mode

Test without generating reports or uploading:

```bash
validate-aws-policies --policies-path ./policies --dry-run
```

### Verbose Output

```bash
validate-aws-policies --policies-path ./policies --verbose
```

### Quiet Mode

```bash
validate-aws-policies --policies-path ./policies --quiet
```

### CI/CD Mode

```bash
validate-aws-policies --policies-path ./policies --ci
```

### Using Configuration File

```bash
validate-aws-policies --config config.yaml
```

## Command-Line Options

```
usage: validate-aws-policies [-h] [-v] [--config FILE] [-d PATH] [-p NAME]
                              [-f {json,text,html,md,markdown,all}] [-o FILE]
                              [-z] [-u] [-b NAME] [-c] [--dry-run]
                              [--verbose | --quiet] [--log-format {text,json}]

options:
  -h, --help            Show help message and exit
  -v, --version         Show version and exit
  --config FILE         Path to configuration file (YAML or TOML)
  -d, --policies-path PATH
                        Directory containing policy JSON files
  -p, --profile NAME    AWS CLI profile name
  -f, --format {json,text,html,md,markdown,all}
                        Output format (default: json)
  -o, --output FILE     Output file path
  -z, --zip             Create ZIP archive of reports
  -u, --upload          Upload reports to S3
  -b, --bucket NAME     S3 bucket name for uploads
  -c, --ci              CI/CD mode
  --dry-run             Validate without generating reports
  --verbose             Enable verbose logging
  --quiet               Suppress non-essential output
  --log-format {text,json}
                        Log output format
```

## Exit Codes

- `0` - Success
- `1` - Validation error (policy has ERROR-level findings)
- `2` - Configuration error
- `3` - AWS API error
- `4` - File I/O error

## Policy File Format

Policy files must be JSON format:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```

Place all policy files in a directory and point to it with `--policies-path`.
