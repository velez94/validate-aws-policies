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

#### JUnit XML and SARIF

```bash
validate-aws-policies --policies-path ./policies --format xml
validate-aws-policies --policies-path ./policies --format sarif
```

#### All Formats

```bash
validate-aws-policies --policies-path ./policies --format all   # html, md and xml
```

See [Policy Types & Custom Checks](access-analyzer-features.md) for SCP/RCP/resource
policies, custom policy checks, `--fail-on`, policy sets and CI examples.

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
usage: validate-aws-policies [-h] [-v] [--config FILE] [-d PATH]
                              [-t {identity,resource,scp,rcp}] [--resource-type TYPE]
                              [--locale LOCALE] [--max-findings N] [-r]
                              [--continue-on-error] [--fail-on LEVEL] [-p NAME]
                              [-f {json,text,html,md,markdown,xml,junit,sarif,all}]
                              [-o FILE] [-z] [-u] [-b NAME] [-c] [--dry-run]
                              [--verbose | --quiet] [--log-format {text,json}]
                              [--check-no-new-access] [--reference-path DIR]
                              [--strict-references] [--check-access-not-granted]
                              [--deny-actions A,B] [--deny-resources ARN,ARN]
                              [--check-no-public-access RESOURCE_TYPE]

options:
  -h, --help            Show help message and exit
  -v, --version         Show version and exit
  --config FILE         Path to configuration file (YAML or TOML)
  -d, --policies-path PATH
                        Directory containing policy JSON files
  -t, --policy-type {identity,resource,scp,rcp}
                        Type of the policies (default: identity)
  --resource-type TYPE  Resource type for resource policies (s3-bucket, trust-policy, ...)
  --locale LOCALE       Language of finding messages (default: EN)
  --max-findings N      Collect at most N findings per policy (default: all)
  -r, --recursive       Also validate *.json files in sub-directories
  --continue-on-error   Validate everything, report, then exit 1 on any ERROR
  --fail-on LEVEL       error, security-warning, warning, suggestion or none
  -p, --profile NAME    AWS CLI profile name
  -f, --format {json,text,html,md,markdown,xml,junit,sarif,all}
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

custom policy checks (identity and resource policies, billed per call):
  --check-no-new-access       Fail if a policy grants more than its baseline
  --reference-path DIR        Baseline policies (same file names)
  --strict-references         Missing baseline file counts as a failure
  --check-access-not-granted  Fail if --deny-actions/--deny-resources are granted
  --deny-actions A,B          Actions that must not be granted
  --deny-resources ARN,ARN    Resources that must not be accessible
  --check-no-public-access RESOURCE_TYPE
                              Fail if a resource policy can be public
```

## Exit Codes

- `0` - Success
- `1` - Validation error (ERROR-level finding, a failed custom check, or a finding at or above `--fail-on`)
- `2` - Configuration error (including a boto3 version that lacks a requested feature)
- `3` - AWS API error (permissions, throttling after retries, service errors)
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
