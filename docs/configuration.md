# Configuration

## Configuration File

You can use a configuration file instead of command-line arguments.

### YAML Format

Create `config.yaml`:

```yaml
# AWS Configuration
profile: my-aws-profile
policies_path: ./policies

# Output Configuration
format: html
output: report.html

# Report Options
zip: true
upload: false
bucket: my-reports-bucket

# Execution Options
dry_run: false
ci: false

# Logging
verbose: false
quiet: false
log_format: text
```

Use it:

```bash
validate-aws-policies --config config.yaml
```

### TOML Format

Create `config.toml`:

```toml
# AWS Configuration
profile = "my-aws-profile"
policies_path = "./policies"

# Output Configuration
format = "html"
output = "report.html"

# Report Options
zip = true
upload = false
bucket = "my-reports-bucket"

# Execution Options
dry_run = false
ci = false

# Logging
verbose = false
quiet = false
log_format = "text"
```

Use it:

```bash
validate-aws-policies --config config.toml
```

## Configuration Priority

Configuration is merged in this order (later overrides earlier):

1. Configuration file
2. Environment variables
3. Command-line arguments

## Environment Variables

You can use environment variables for common settings:

```bash
export AWS_PROFILE=my-profile
export POLICIES_PATH=./policies
export REPORTS_BUCKET=my-bucket

validate-aws-policies
```

Supported environment variables:

- `AWS_PROFILE` - AWS CLI profile name
- `POLICIES_PATH` - Path to policies directory
- `REPORTS_BUCKET` - S3 bucket for uploads

## AWS Configuration

### Using AWS Profiles

In `~/.aws/config`:

```ini
[profile my-profile]
region = us-east-1
output = json

[profile my-sso-profile]
sso_start_url = https://my-sso-portal.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = MyRole
region = us-east-1
```

### Using Environment Variables

```bash
export AWS_PROFILE=my-profile
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1
```

## S3 Upload Configuration

When using `--upload`, reports are uploaded to:

```
s3://<bucket>/AccessAnalyzer/<YYYY>/<MM>/<DD>/<filename>
```

Example:

```
s3://my-bucket/AccessAnalyzer/2024/02/22/AccessAnalyzerReport_2024-02-22_150000.html
```

## Logging Configuration

### Log Levels

- `--quiet` - Only errors
- Default - Info and above
- `--verbose` - Debug and above

### Log Formats

#### Text (Default)

```
2024-02-22 15:00:00 INFO Starting validation...
2024-02-22 15:00:01 INFO Validating 5 policies...
```

#### JSON

```bash
validate-aws-policies --policies-path ./policies --log-format json
```

```json
{"timestamp": "2024-02-22T15:00:00", "level": "INFO", "message": "Starting validation..."}
{"timestamp": "2024-02-22T15:00:01", "level": "INFO", "message": "Validating 5 policies..."}
```

## Example Configurations

### Development

```yaml
profile: dev-profile
policies_path: ./policies
format: text
verbose: true
dry_run: true
```

### CI/CD

```yaml
profile: ci-profile
policies_path: ./policies
format: json
ci: true
quiet: true
upload: true
bucket: ci-reports-bucket
```

### Production

```yaml
profile: prod-profile
policies_path: ./policies
format: all
zip: true
upload: true
bucket: prod-reports-bucket
log_format: json
```
