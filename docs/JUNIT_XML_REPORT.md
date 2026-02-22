# JUnit XML Report Format

## Overview

The AWS Policy Validation CLI now supports JUnit/XUnit XML report format for seamless integration with CI/CD pipelines. This format is compatible with popular CI/CD tools including:

- Jenkins
- GitLab CI
- GitHub Actions
- CircleCI
- Azure DevOps
- TeamCity
- Bamboo

## Usage

### Basic Usage

Generate a JUnit XML report:

```bash
validate-aws-policies --policies-path ./policies --format xml
```

Or use the `junit` alias:

```bash
validate-aws-policies --policies-path ./policies --format junit
```

### CI/CD Integration Examples

#### GitHub Actions

```yaml
name: Validate AWS Policies

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install validator
        run: pip install validate-aws-policies
      
      - name: Validate policies
        run: |
          validate-aws-policies \
            --policies-path ./policies \
            --format junit \
            --output results.xml
      
      - name: Publish Test Results
        uses: EnricoMi/publish-unit-test-result-action@v2
        if: always()
        with:
          files: results.xml
```

#### GitLab CI

```yaml
validate-policies:
  stage: test
  image: python:3.10
  script:
    - pip install validate-aws-policies
    - validate-aws-policies --policies-path ./policies --format junit --output results.xml
  artifacts:
    when: always
    reports:
      junit: results.xml
```

#### Jenkins

```groovy
pipeline {
    agent any
    
    stages {
        stage('Validate Policies') {
            steps {
                sh '''
                    pip install validate-aws-policies
                    validate-aws-policies \
                        --policies-path ./policies \
                        --format junit \
                        --output results.xml
                '''
            }
        }
    }
    
    post {
        always {
            junit 'results.xml'
        }
    }
}
```

#### CircleCI

```yaml
version: 2.1

jobs:
  validate:
    docker:
      - image: python:3.10
    steps:
      - checkout
      - run:
          name: Install validator
          command: pip install validate-aws-policies
      - run:
          name: Validate policies
          command: |
            validate-aws-policies \
              --policies-path ./policies \
              --format junit \
              --output results.xml
      - store_test_results:
          path: results.xml
```

## XML Report Structure

### Root Element

```xml
<testsuites name="AWS Policy Validation" 
            tests="10" 
            failures="2" 
            errors="1" 
            time="1.234"
            timestamp="2024-01-01T12:00:00"
            hostname="hostname">
```

**Attributes:**
- `name`: Always "AWS Policy Validation"
- `tests`: Total number of test cases across all policies
- `failures`: Total number of WARNING and SECURITY_WARNING findings
- `errors`: Total number of ERROR findings
- `time`: Total execution time in seconds
- `timestamp`: ISO 8601 timestamp of report generation
- `hostname`: Machine hostname where validation ran

### Test Suite (Policy)

Each policy file becomes a test suite:

```xml
<testsuite name="policy-name.json" 
           tests="3" 
           failures="1" 
           errors="1" 
           time="0.5"
           timestamp="2024-01-01T12:00:00">
```

**Attributes:**
- `name`: Policy filename
- `tests`: Number of findings (or 1 if no findings)
- `failures`: Number of WARNING/SECURITY_WARNING findings
- `errors`: Number of ERROR findings
- `time`: Estimated execution time for this policy

### Properties

Metadata about the validation:

```xml
<properties>
  <property name="validator" value="AWS IAM Access Analyzer"/>
  <property name="policy_file" value="policy-name.json"/>
  <property name="total_findings" value="3"/>
</properties>
```

### Test Cases (Findings)

#### ERROR Finding

```xml
<testcase classname="policy-name" name="SECURITY_ISSUE_1" time="0.1">
  <error type="ERROR" message="ERROR: SECURITY_ISSUE">
    Finding Type: ERROR
    Issue Code: SECURITY_ISSUE
    Details: Policy allows unrestricted access to sensitive resources
    Learn More: https://docs.aws.amazon.com/security
  </error>
</testcase>
```

#### WARNING Finding

```xml
<testcase classname="policy-name" name="BEST_PRACTICE_VIOLATION_1" time="0.1">
  <failure type="WARNING" message="WARNING: BEST_PRACTICE_VIOLATION">
    Finding Type: WARNING
    Issue Code: BEST_PRACTICE_VIOLATION
    Details: Policy should use more restrictive conditions
  </failure>
</testcase>
```

#### SECURITY_WARNING Finding

```xml
<testcase classname="policy-name" name="OVERLY_PERMISSIVE_1" time="0.1">
  <failure type="SECURITY_WARNING" message="SECURITY_WARNING: OVERLY_PERMISSIVE">
    Finding Type: SECURITY_WARNING
    Issue Code: OVERLY_PERMISSIVE
    Details: Policy grants more permissions than necessary
  </failure>
</testcase>
```

#### SUGGESTION Finding (Passing Test)

```xml
<testcase classname="policy-name" name="OPTIMIZATION_1" time="0.1"/>
```

#### Valid Policy (No Findings)

```xml
<testcase classname="policy-name" name="ValidatePolicy" time="0.1"/>
```

## Finding Type Mapping

| Finding Type | JUnit Element | CI/CD Status |
|--------------|---------------|--------------|
| ERROR | `<error>` | Failed (Red) |
| WARNING | `<failure>` | Failed (Yellow) |
| SECURITY_WARNING | `<failure>` | Failed (Yellow) |
| SUGGESTION | (none) | Passed (Green) |
| No findings | (none) | Passed (Green) |

## Exit Codes

The validator returns appropriate exit codes for CI/CD integration:

- `0` - Success (all policies valid or only suggestions)
- `1` - Validation error (ERROR findings detected)
- `3` - AWS API error
- `4` - File operation error

## Advanced Usage

### With ZIP Archive

Create a ZIP archive containing the XML report:

```bash
validate-aws-policies \
  --policies-path ./policies \
  --format xml \
  --zip
```

### Upload to S3

Upload the XML report to S3 for archival:

```bash
validate-aws-policies \
  --policies-path ./policies \
  --format xml \
  --upload \
  --bucket my-reports-bucket
```

### Specify Output File

```bash
validate-aws-policies \
  --policies-path ./policies \
  --format xml \
  --output policy-validation-results.xml
```

### CI Mode with XML Report

```bash
validate-aws-policies \
  --policies-path ./policies \
  --format xml \
  --ci \
  --output results.xml
```

## Troubleshooting

### XML Not Generated

If the XML report is not generated:

1. Check that you're using `--format xml` or `--format junit`
2. Ensure you're not using `--dry-run` mode (which skips report generation)
3. Verify write permissions in the output directory

### CI/CD Tool Not Recognizing Report

If your CI/CD tool doesn't recognize the XML report:

1. Verify the file extension is `.xml`
2. Check that the file path in your CI configuration matches the output location
3. Ensure the XML is well-formed (validate with `xmllint` if available)

### Empty Test Results

If the report shows no tests:

1. Verify that policy files exist in the specified directory
2. Check that policy files have `.json` extension
3. Review logs for validation errors

## Schema Compliance

The generated XML follows the JUnit XML schema as documented at:
- https://github.com/testmoapp/junitxml
- https://llg.cubic.org/docs/junit/

This ensures compatibility with standard CI/CD tools and test result parsers.

## Example Output

Here's a complete example of a generated XML report:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="AWS Policy Validation" 
            timestamp="2024-01-15T10:30:00.123456" 
            hostname="ci-runner-01" 
            tests="5" 
            failures="2" 
            errors="1" 
            time="0.300">
  <testsuite name="iam-policy.json" 
             tests="2" 
             failures="1" 
             errors="1" 
             time="0.100" 
             timestamp="2024-01-15T10:30:00.123456">
    <properties>
      <property name="validator" value="AWS IAM Access Analyzer"/>
      <property name="policy_file" value="iam-policy.json"/>
      <property name="total_findings" value="2"/>
    </properties>
    <testcase classname="iam-policy" name="SECURITY_ISSUE_1" time="0.050">
      <error type="ERROR" message="ERROR: SECURITY_ISSUE">
Finding Type: ERROR
Issue Code: SECURITY_ISSUE
Details: Policy allows unrestricted access to sensitive resources
Learn More: https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html
      </error>
    </testcase>
    <testcase classname="iam-policy" name="BEST_PRACTICE_VIOLATION_2" time="0.050">
      <failure type="WARNING" message="WARNING: BEST_PRACTICE_VIOLATION">
Finding Type: WARNING
Issue Code: BEST_PRACTICE_VIOLATION
Details: Policy should use more restrictive conditions
      </failure>
    </testcase>
  </testsuite>
  <testsuite name="s3-bucket-policy.json" 
             tests="2" 
             failures="1" 
             errors="0" 
             time="0.100" 
             timestamp="2024-01-15T10:30:00.123456">
    <properties>
      <property name="validator" value="AWS IAM Access Analyzer"/>
      <property name="policy_file" value="s3-bucket-policy.json"/>
      <property name="total_findings" value="2"/>
    </properties>
    <testcase classname="s3-bucket-policy" name="OVERLY_PERMISSIVE_1" time="0.050">
      <failure type="SECURITY_WARNING" message="SECURITY_WARNING: OVERLY_PERMISSIVE">
Finding Type: SECURITY_WARNING
Issue Code: OVERLY_PERMISSIVE
Details: Policy grants more permissions than necessary
      </failure>
    </testcase>
    <testcase classname="s3-bucket-policy" name="OPTIMIZATION_2" time="0.050"/>
  </testsuite>
  <testsuite name="valid-policy.json" 
             tests="1" 
             failures="0" 
             errors="0" 
             time="0.100" 
             timestamp="2024-01-15T10:30:00.123456">
    <properties>
      <property name="validator" value="AWS IAM Access Analyzer"/>
      <property name="policy_file" value="valid-policy.json"/>
      <property name="total_findings" value="0"/>
    </properties>
    <testcase classname="valid-policy" name="ValidatePolicy" time="0.100"/>
  </testsuite>
</testsuites>
```

## Benefits

1. **Automated Testing**: Integrate policy validation into your CI/CD pipeline
2. **Visual Feedback**: See test results in your CI/CD dashboard
3. **Trend Analysis**: Track policy validation over time
4. **Fail Fast**: Catch policy issues before deployment
5. **Standardized Format**: Works with any JUnit-compatible tool
6. **Detailed Reports**: Each finding is a separate test case with full details
