# Examples

## Everyday commands

```bash
# Validate a directory, JSON to stdout
validate-aws-policies -d ./policies -p my-profile

# Readable output in the terminal
validate-aws-policies -d ./policies -f text

# Everything under policies/, including sub-directories
validate-aws-policies -d ./policies --recursive

# Only the findings, with jq
validate-aws-policies -d ./policies --quiet | jq '.[] | select(.summary[0].findingType != "None")'

# Validate without writing any file
validate-aws-policies -d ./policies -f html --dry-run
```

## Reports

```bash
validate-aws-policies -d ./policies -f html                 # AccessAnalyzerReport_20260306_150000.html
validate-aws-policies -d ./policies -f md  -o review.md     # your own file name
validate-aws-policies -d ./policies -f xml -o reports/policies.xml
validate-aws-policies -d ./policies -f all --zip            # html + md + xml in reports_20260306_150000.zip
validate-aws-policies -d ./policies -f sarif -o results.sarif
```

## Different policy types

```bash
validate-aws-policies -d ./scps   -t scp
validate-aws-policies -d ./rcps   -t rcp
validate-aws-policies -d ./trust  -t resource --resource-type trust-policy
validate-aws-policies -d ./bucket -t resource --resource-type s3-bucket
validate-aws-policies -d ./keys   -t resource            # KMS, SQS, ...: generic resource checks
```

SCP, trust policy and bucket policy in one run, with a config file:

```yaml
# validate.yaml
profile: my-profile
policy_sets:
  - {path: ./scps,  policy_type: scp}
  - {path: ./trust, policy_type: resource, resource_type: trust-policy}
  - {path: ./buckets, policy_type: resource, resource_type: s3-bucket}
fail_on: error
```

```bash
validate-aws-policies --config validate.yaml
```

## Pipelines that fail on findings

```bash
validate-aws-policies -d ./policies --fail-on error      # same as the default gate, but reports first
validate-aws-policies -d ./policies --fail-on warning    # warnings and security warnings fail too
validate-aws-policies -d ./policies --fail-on none       # findings never fail the run
echo $?
```

## Custom policy checks

```bash
# No policy may grant more than the approved baseline
validate-aws-policies -d ./policies --check-no-new-access --reference-path ./baseline

# Nobody may be allowed to delete the audit bucket
validate-aws-policies -d ./policies --check-access-not-granted \
  --deny-actions "s3:DeleteBucket,s3:DeleteObject" \
  --deny-resources "arn:aws:s3:::audit-logs,arn:aws:s3:::audit-logs/*"

# Bucket policies must not be public
validate-aws-policies -d ./buckets -t resource --resource-type s3-bucket \
  --check-no-public-access s3-bucket
```

A failing check prints, in text format:

```text
Policy: p.json
  - ERROR: CHECK_NO_NEW_ACCESS
      The modified permissions grant new access compared to your existing policy.
      https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-custom-policy-checks.html
```

## AWS profiles and SSO

```bash
aws sso login --profile my-sso-profile
validate-aws-policies -d ./policies -p my-sso-profile
```

## S3 upload

```bash
validate-aws-policies -d ./policies -f html --upload --bucket my-reports-bucket
validate-aws-policies -d ./policies -f all --zip --upload --bucket my-reports-bucket
```

## Configuration file and overrides

```yaml
# config.yaml
profile: dev-profile
policies_path: ./policies
format: html
upload: true
bucket_name: my-bucket
```

```bash
validate-aws-policies --config config.yaml                 # html, uploaded
validate-aws-policies --config config.yaml -f json         # command line wins: json to stdout
```

## CI/CD

=== "GitHub Actions"

    ```yaml
    name: Validate policies
    on: [pull_request]
    permissions:
      id-token: write
      contents: read
      security-events: write
    jobs:
      validate:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: aws-actions/configure-aws-credentials@v4
            with:
              role-to-assume: ${{ secrets.AWS_ROLE }}
              aws-region: us-east-1
          - run: pip install validate-aws-policies
          - run: validate-aws-policies -d policies --recursive --fail-on error -f sarif -o results.sarif
          - if: always()
            uses: github/codeql-action/upload-sarif@v3
            with:
              sarif_file: results.sarif
    ```

=== "GitLab CI"

    ```yaml
    validate-policies:
      image: python:3.12
      script:
        - pip install validate-aws-policies
        - validate-aws-policies -d policies --fail-on error -f xml -o results.xml
      artifacts:
        when: always
        reports:
          junit: results.xml
    ```

=== "Jenkins"

    ```groovy
    stage('Validate policies') {
      steps {
        sh 'pip install validate-aws-policies'
        sh 'validate-aws-policies -d policies -f xml -o results.xml'
      }
      post { always { junit 'results.xml' } }
    }
    ```

For AWS CodeBuild see [AWS CodeBuild](codebuild.md). More baseline-comparison examples are on
[Policy Types & Custom Checks](access-analyzer-features.md#ci-examples).

## Troubleshooting

**"No policy files found"** The tool reads only `*.json` files directly in the directory.
Add `--recursive` for sub-directories. Hidden directories are skipped.

**Exit code 3 with `AccessDeniedException`** The credentials lack
`access-analyzer:ValidatePolicy` (or a check permission). See
[IAM permissions](installation.md#iam-permissions).

**Exit code 3 with "Unable to locate credentials" or an expired token**

```bash
aws sts get-caller-identity --profile my-profile
aws sso login --profile my-profile
```

**Exit code 2 and "not supported by the installed boto3"** Run
`pip install --upgrade boto3 botocore`.

**A resource policy fails with `UNSUPPORTED_PRINCIPAL`** It was validated as an identity
policy. Add `--policy-type resource`.

**Findings look different from the AWS console** The console may validate with another
policy type. Make sure `--policy-type` and `--resource-type` match where you attach the policy.

**More detail** Add `--verbose`. Debug logs show the merged configuration, the files found and each
finding in full.
