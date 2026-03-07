# AWS CodeBuild Integration Guide

## Overview

The JUnit XML report generation has been updated to be fully compatible with AWS CodeBuild test reporting. This guide shows how to integrate policy validation into your CodeBuild pipeline.

## Quick Start

### 1. Basic buildspec.yml

```yaml
version: 0.2

phases:
  install:
    runtime-versions:
      python: 3.11
    commands:
      - pip install validate-aws-policies

  build:
    commands:
      - echo "Validating AWS policies..."
      - python -m validate_aws_policies \
          --format xml \
          --directory-policies-path ./policies \
          --profile $AWS_PROFILE

reports:
  policy-validation-report:
    files:
      - 'AccessAnalyzerReport_*.xml'
    file-format: JUNITXML
```

### 2. With Multiple Policy Directories

```yaml
version: 0.2

phases:
  install:
    runtime-versions:
      python: 3.11
    commands:
      - pip install validate-aws-policies

  build:
    commands:
      - echo "Validating SCP policies..."
      - python -m validate_aws_policies \
          --format xml \
          --directory-policies-path ./policies/scp \
          --policy-type service_control_policy
      
      - echo "Validating IAM policies..."
      - python -m validate_aws_policies \
          --format xml \
          --directory-policies-path ./policies/iam \
          --policy-type identity_policy

reports:
  scp-validation:
    files:
      - 'AccessAnalyzerReport_*.xml'
    file-format: JUNITXML
```

### 3. With S3 Upload

```yaml
version: 0.2

phases:
  install:
    runtime-versions:
      python: 3.11
    commands:
      - pip install validate-aws-policies

  build:
    commands:
      - echo "Validating policies..."
      - python -m validate_aws_policies \
          --format xml \
          --directory-policies-path ./policies \
          --upload-report \
          --bucket-name my-policy-reports-bucket \
          --create-pdf-reports

reports:
  policy-validation:
    files:
      - 'AccessAnalyzerReport_*.xml'
    file-format: JUNITXML

artifacts:
  files:
    - 'AccessAnalyzerReport_*.pdf'
    - 'AccessAnalyzerReport_*.html'
```

## Report Interpretation

### Test Results in CodeBuild

CodeBuild will display:
- **Total Tests**: Number of policies validated + number of findings
- **Passed**: Policies with no ERROR or WARNING findings
- **Failed**: Policies with WARNING or SECURITY_WARNING findings
- **Errors**: Policies with ERROR findings
- **Skipped**: Always 0 (no tests are skipped)

### Finding Types Mapping

| Finding Type | JUnit Status | CodeBuild Display |
|--------------|--------------|-------------------|
| ERROR | Error | Red (Error) |
| WARNING | Failure | Yellow (Failed) |
| SECURITY_WARNING | Failure | Yellow (Failed) |
| SUGGESTION | Pass | Green (Passed) |
| No findings | Pass | Green (Passed) |

## Troubleshooting

### Issue: "Incomplete" Status in CodeBuild

**Solution**: This has been fixed. Ensure you're using the latest version with:
- `skipped="0"` attribute on testsuites and testsuite elements
- `<system-out>` and `<system-err>` elements in each testsuite
- Proper timestamp format (ISO 8601 without microseconds)

### Issue: Reports Not Found

**Check**:
1. XML files are generated in the workspace root
2. File pattern in `reports.files` matches the generated files
3. Build phase completes successfully before reports are collected

```yaml
reports:
  policy-validation:
    files:
      - 'AccessAnalyzerReport_*.xml'  # Wildcard pattern
    file-format: JUNITXML
    base-directory: '.'  # Optional: specify base directory
```

### Issue: Permission Denied

**Solution**: Ensure CodeBuild service role has permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "access-analyzer:ValidatePolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

## Advanced Configuration

### Fail Build on Policy Errors

```yaml
version: 0.2

phases:
  build:
    commands:
      - |
        python -m validate_aws_policies \
          --format xml \
          --directory-policies-path ./policies || exit 1
```

### Multiple Report Groups

```yaml
reports:
  scp-policies:
    files:
      - 'AccessAnalyzerReport_*_scp.xml'
    file-format: JUNITXML
  
  iam-policies:
    files:
      - 'AccessAnalyzerReport_*_iam.xml'
    file-format: JUNITXML
  
  resource-policies:
    files:
      - 'AccessAnalyzerReport_*_resource.xml'
    file-format: JUNITXML
```

### Custom Report Retention

```yaml
reports:
  policy-validation:
    files:
      - 'AccessAnalyzerReport_*.xml'
    file-format: JUNITXML
    discard-paths: yes
```

## Viewing Reports

### In CodeBuild Console

1. Navigate to your build project
2. Click on a build run
3. Go to the "Reports" tab
4. View test results with:
   - Summary statistics
   - Individual test cases
   - Failure details with finding information

### Using AWS CLI

```bash
# List report groups
aws codebuild list-report-groups

# List reports in a group
aws codebuild list-reports-for-report-group \
  --report-group-arn arn:aws:codebuild:region:account:report-group/name

# Get report details
aws codebuild batch-get-reports \
  --report-arns arn:aws:codebuild:region:account:report/id
```

## Best Practices

1. **Separate Report Groups**: Use different report groups for different policy types
2. **Fail Fast**: Configure build to fail on ERROR findings
3. **Archive Reports**: Upload HTML/PDF reports as artifacts for detailed review
4. **Notifications**: Set up SNS notifications for failed builds
5. **Retention**: Configure appropriate report retention periods

## Example Output

When a policy has findings, CodeBuild will show:

```
Test Results:
  Total: 3
  Passed: 1
  Failed: 1
  Errors: 1
  
Failed Tests:
  - policy.json > MISSING_ACTION_1
    Type: WARNING
    Details: Policy allows actions that don't exist...
    
Error Tests:
  - policy.json > INVALID_PRINCIPAL_2
    Type: ERROR
    Details: Principal format is invalid...
```

## Support

For issues or questions:
- Check the validation script: `python3 test_junit_xml_output.py <xml_file>`
- Review AWS CodeBuild logs for detailed error messages
- Ensure IAM Access Analyzer API is available in your region
