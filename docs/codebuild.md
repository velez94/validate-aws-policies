# AWS CodeBuild

Publish the policy validation results as a CodeBuild test report by writing JUnit XML.
See [JUnit XML Report](JUNIT_XML_REPORT.md) for the file structure.

## Basic buildspec

```yaml
version: 0.2

phases:
  install:
    runtime-versions:
      python: 3.12
    commands:
      - pip install validate-aws-policies
  build:
    commands:
      - validate-aws-policies --policies-path ./policies --format xml --output reports/policies.xml

reports:
  policy-validation:
    files:
      - 'reports/policies.xml'
    file-format: JUNITXML
```

Use the CodeBuild service role instead of `--profile`; the build already has credentials.
The role needs `access-analyzer:ValidatePolicy` (see
[IAM permissions](installation.md#iam-permissions)).

!!! note "Exit codes"
    The command exits with code 1 when an ERROR finding or a failed custom check is found, so
    the build fails. The report file is written before the command exits. Use
    `--fail-on none` if findings should never fail the build, or `--fail-on warning` to be
    stricter. See [Failure handling](access-analyzer-features.md#failure-handling).

## Several policy types

Run the tool once per policy type and write one report per run:

```yaml
phases:
  build:
    commands:
      - validate-aws-policies -d policies/scp --policy-type scp --format xml --output reports/scp.xml
      - validate-aws-policies -d policies/iam --format xml --output reports/iam.xml

reports:
  policy-validation:
    files:
      - 'reports/*.xml'
    file-format: JUNITXML
```

or validate them together with `policy_sets` in a [config file](access-analyzer-features.md#policy-sets).

## Upload reports to S3

```yaml
  build:
    commands:
      - >
        validate-aws-policies -d policies --format all --zip
        --upload --bucket my-policy-reports-bucket
```

`--format all` writes HTML, Markdown and JUnit XML. The files are uploaded to
`s3://my-policy-reports-bucket/AccessAnalyzer/<YYYY>/<MM>/<DD>/`. PDF reports were removed
in version 3.0.

## Custom checks in CodeBuild

Keep a baseline copy of the approved policies (for example a directory in the repository or
files fetched from S3) and compare against it:

```yaml
  build:
    commands:
      - >
        validate-aws-policies -d policies --check-no-new-access
        --reference-path baseline --format xml --output reports/policies.xml
```

Custom checks are billed per API call, see
[Policy Types & Custom Checks](access-analyzer-features.md#custom-policy-checks).

## How findings appear in CodeBuild

| Finding type | JUnit status | CodeBuild shows |
|---|---|---|
| `ERROR`, failed custom check | error | Error |
| `WARNING`, `SECURITY_WARNING` | failure | Failed |
| `SUGGESTION` | pass | Passed |
| no findings | pass | Passed |

## Troubleshooting

**Report shows "Incomplete"** Use version 3.1.1 or later. Earlier versions omitted
attributes CodeBuild requires (`skipped`, `system-out`, `system-err`). The
[validation script](https://github.com/velez94/validate-aws-policies/blob/main/scripts/validate_junit_xml.py)
checks a file against these rules:

```bash
python3 scripts/validate_junit_xml.py reports/policies.xml
```

**No report files found** Check the path in `reports.files`. Without `--output` the tool
writes `AccessAnalyzerReport_<timestamp>.xml` in the working directory.

**Exit code 3** The build role lacks an Access Analyzer permission, or the API was throttled
after retries. The log shows the AWS error code.
