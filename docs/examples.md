# Examples

## Basic Validation

### Validate Single Directory

```bash
validate-aws-policies --policies-path ./policies
```

Output:

```json
[
  {
    "filePolicy": "my-policy.json",
    "summary": [
      {
        "findingType": "WARNING",
        "issueCode": "PASS_ROLE_WITH_STAR_IN_RESOURCE",
        "details": "Using a wildcard (*) in the resource can be overly permissive..."
      }
    ]
  }
]
```

## Report Generation

### HTML Report

```bash
validate-aws-policies --policies-path ./policies --format html
```

Creates: `AccessAnalyzerReport_2024-02-22_150000.html`

### Markdown Report

```bash
validate-aws-policies --policies-path ./policies --format md
```

Creates: `AccessAnalyzerReport_2024-02-22_150000.md`

### All Formats

```bash
validate-aws-policies --policies-path ./policies --format all
```

Creates both HTML and Markdown reports.

### With ZIP Archive

```bash
validate-aws-policies --policies-path ./policies --format all --zip
```

Creates: `AccessAnalyzerReports_2024-02-22_150000.zip`

## AWS Profile Usage

### Named Profile

```bash
validate-aws-policies --policies-path ./policies -p dev-profile
```

### SSO Profile

```bash
# Login first
aws sso login --profile my-sso-profile

# Then validate
validate-aws-policies --policies-path ./policies -p my-sso-profile
```

## S3 Upload

### Upload HTML Report

```bash
validate-aws-policies \
  --policies-path ./policies \
  --format html \
  --upload \
  --bucket my-reports-bucket
```

### Upload with ZIP

```bash
validate-aws-policies \
  --policies-path ./policies \
  --format all \
  --zip \
  --upload \
  --bucket my-reports-bucket
```

## Configuration File Usage

### Using YAML Config

Create `config.yaml`:

```yaml
profile: dev-profile
policies_path: ./policies
format: html
upload: true
bucket: my-bucket
```

Run:

```bash
validate-aws-policies --config config.yaml
```

### Override Config with CLI

```bash
validate-aws-policies --config config.yaml --format json
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Validate Policies

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.x'
      
      - name: Install tool
        run: pip install validate-aws-policies
      
      - name: Configure AWS
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE }}
          aws-region: us-east-1
      
      - name: Validate policies
        run: |
          validate-aws-policies \
            --policies-path ./policies \
            --format json \
            --ci
```

### GitLab CI

```yaml
validate-policies:
  image: python:3.11
  before_script:
    - pip install validate-aws-policies
  script:
    - validate-aws-policies --policies-path ./policies --ci
  artifacts:
    reports:
      junit: validation-results.json
```

## Advanced Examples

### Dry Run

Test without generating files:

```bash
validate-aws-policies --policies-path ./policies --dry-run
```

### Verbose Logging

```bash
validate-aws-policies --policies-path ./policies --verbose
```

### JSON Logging for Parsing

```bash
validate-aws-policies \
  --policies-path ./policies \
  --log-format json \
  --quiet > validation.log
```

### Save JSON Output

```bash
validate-aws-policies \
  --policies-path ./policies \
  --format json \
  -o results.json
```

## Policy Examples

### IAM Identity Policy

`policies/s3-read-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ]
    }
  ]
}
```

### SCP Policy

`policies/deny-regions.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "us-east-1",
            "us-west-2"
          ]
        }
      }
    }
  ]
}
```

### Resource-Based Policy

`policies/s3-bucket-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```

## Troubleshooting

### No Policies Found

```bash
validate-aws-policies --policies-path ./policies --verbose
```

Check that:
- Directory exists
- Contains `.json` files
- Files are valid JSON

### AWS Credentials Error

```bash
# Check credentials
aws sts get-caller-identity

# Or with profile
aws sts get-caller-identity --profile my-profile
```

### Permission Denied

Ensure your IAM user/role has:

```json
{
  "Effect": "Allow",
  "Action": "access-analyzer:ValidatePolicy",
  "Resource": "*"
}
```
