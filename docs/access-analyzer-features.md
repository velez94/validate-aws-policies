# Policy Types, Custom Checks and CI

This page covers the options added in 3.2. Everything here is opt-in: running
`validate-aws-policies -d ./policies` behaves as it did before.

## Policy types and resource types

```bash
# Identity policies (default)
validate-aws-policies -d ./policies

# Service control policies and resource control policies
validate-aws-policies -d ./scps --policy-type scp
validate-aws-policies -d ./rcps --policy-type rcp

# Resource policies, with the resource they attach to for more specific checks
validate-aws-policies -d ./bucket-policies --policy-type resource --resource-type s3-bucket
validate-aws-policies -d ./trust-policies   --policy-type resource --resource-type trust-policy
```

| `--resource-type` | AWS value |
|---|---|
| `s3-bucket` | `AWS::S3::Bucket` |
| `s3-access-point` | `AWS::S3::AccessPoint` |
| `s3-mrap` | `AWS::S3::MultiRegionAccessPoint` |
| `s3-object-lambda` | `AWS::S3ObjectLambda::AccessPoint` |
| `trust-policy` | `AWS::IAM::AssumeRolePolicyDocument` |
| `dynamodb-table` | `AWS::DynamoDB::Table` |

`--resource-type` is only valid with `--policy-type resource`. For other resource
policies (KMS keys, SQS queues, and so on) omit it: Access Analyzer then runs the checks
that apply to all resource policies.

Other validation options:

- `--locale` (`DE EN ES FR IT JA KO PT_BR ZH_CN ZH_TW`) sets the language of the messages.
- `--max-findings N` stops collecting after N findings per policy. By default all findings
  are collected (earlier versions silently kept at most 100).
- `-r/--recursive` also validates `*.json` files in sub-directories (hidden directories are
  skipped). Report file names are relative paths such as `team-a/dev.json`.

## Failure handling

By default the run stops at the first `ERROR` finding and exits with code 1, as before.

| Option | Behavior |
|---|---|
| `--continue-on-error` | Validate everything, write the output and reports, then exit 1 if any ERROR was found. |
| `--fail-on LEVEL` | Exit 1 when a finding of this severity or higher exists. `LEVEL` is `error`, `security-warning`, `warning`, `suggestion` or `none`. Implies `--continue-on-error`. |

Severity order: `ERROR` > `SECURITY_WARNING` > `WARNING` > `SUGGESTION`.

## Custom policy checks

Custom policy checks use automated reasoning to test a policy against your own security
standard. They apply to **identity and resource policies only** (not SCPs or RCPs).

!!! warning "Cost"
    Policy validation is free. Custom policy checks are billed per API call
    (USD 0.0020 per call at the time of writing, see the
    [pricing page](https://aws.amazon.com/iam/access-analyzer/pricing/)). One call is made per
    policy per enabled check.

!!! info "IAM permissions"
    `access-analyzer:ValidatePolicy` for validation, plus
    `access-analyzer:CheckNoNewAccess`, `access-analyzer:CheckAccessNotGranted` and
    `access-analyzer:CheckNoPublicAccess` for the corresponding checks.
    Uploads additionally need `s3:PutObject`.

### Check for new access

Compare each policy with a baseline policy of the same file name:

```bash
validate-aws-policies -d ./policies --check-no-new-access --reference-path ./baseline
```

A policy with no file in `--reference-path` is skipped with a warning. Add
`--strict-references` to treat it as a failure.

### Check that access is not granted

```bash
validate-aws-policies -d ./policies --check-access-not-granted \
  --deny-actions "iam:*,s3:DeleteBucket" \
  --deny-resources "arn:aws:s3:::audit-logs,arn:aws:s3:::audit-logs/*"
```

With only actions, a policy fails if it allows any listed action on any resource. With only
resources, it fails if it allows any action on a listed resource. With both, it fails if it
allows a listed action on a listed resource.

### Check for public access

```bash
validate-aws-policies -d ./bucket-policies --policy-type resource \
  --resource-type s3-bucket --check-no-public-access s3-bucket
```

The value is an AWS resource type such as `AWS::S3::Bucket`, or its short form
(`s3-bucket`, `kms-key`, `sqs-queue`, `sns-topic`). The tool validates it against the
resource types known to your installed boto3.

### How results appear

A failed check is reported as an `ERROR` finding with the issue code
`CHECK_NO_NEW_ACCESS`, `CHECK_ACCESS_NOT_GRANTED` or `CHECK_NO_PUBLIC_ACCESS`, so it shows
up in every report format and the run exits with code 1 after the reports are written.
In JSON output each policy also gets a `checks` list:

```json
{
  "filePolicy": "p.json",
  "summary": [{"issueCode": "CHECK_NO_NEW_ACCESS", "findingType": "ERROR",
               "details": {"source": "custom_check", "reasons": [
                 {"description": "New access in the statement with index: 0.", "statementIndex": 0}]}}],
  "checks": [{"name": "CHECK_NO_NEW_ACCESS", "result": "FAIL", "message": "...", "reasons": []}]
}
```

Policies that already have `ERROR` findings are not checked. `result` is `PASS`, `FAIL` or
`SKIPPED`.

## Policy sets

Validate several kinds of policies in one run. Only available in the config file:

```yaml
profile: my-profile
policy_sets:
  - path: ./scps
    policy_type: scp
  - path: ./trust-policies
    policy_type: resource
    resource_type: trust-policy
  - path: ./bucket-policies
    policy_type: resource
    resource_type: s3-bucket
checks:
  no_public_access:
    resource_type: s3-bucket     # runs only on sets with the same resource type
```

Report file names are prefixed with the set path (`scps/deny.json`). Checks run on the
sets that support them and are skipped on the rest.

The `checks` section is a shortcut for the flat keys `check_no_new_access`,
`reference_path`, `strict_references`, `check_access_not_granted`, `deny_actions`,
`deny_resources` and `check_no_public_access`. Flat keys win if both are set.

## Reports

| Format | File | Use |
|---|---|---|
| `html` | `AccessAnalyzerReport_<time>.html` | Self-contained page for people: verdict, severity cards you can click to filter, search, light/dark theme, print layout. Works offline. |
| `md` | `.md` | Pull request comments and wikis. |
| `xml` / `junit` | `.xml` | Test report tabs in CodeBuild, Azure Pipelines, Jenkins. |
| `sarif` | `.sarif` | GitHub code scanning and other SARIF viewers. |
| `json` / `text` | stdout | Scripts and terminals. Text output shows line, column (1-based) and the learn-more link. |

`--output FILE` writes a single-file report to that path. `--format all` writes html, md
and xml.

## CI examples

### GitHub Actions

```yaml
name: Validate policies
on: [pull_request]
permissions:
  id-token: write       # OIDC to AWS
  contents: read
  security-events: write
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: {fetch-depth: 0}
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/policy-validator
          aws-region: us-east-1
      - run: pip install validate-aws-policies
      # Baseline = the policies on the target branch
      - run: |
          git worktree add ../baseline origin/${{ github.base_ref }}
      - run: |
          validate-aws-policies -d policies --recursive --fail-on error \
            --check-no-new-access --reference-path ../baseline/policies \
            --format sarif --output results.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: {sarif_file: results.sarif}
```

### AWS CodeBuild

```yaml
version: 0.2
phases:
  install:
    commands: [pip install validate-aws-policies]
  build:
    commands:
      - validate-aws-policies -d policies --fail-on error --format xml --output reports/policies.xml
reports:
  policy-validation:
    files: [reports/policies.xml]
    file-format: JUNITXML
```

## Older boto3 versions

The package requires boto3 1.36.0 or newer. Features that depend on API values added later
are detected at run time. If your boto3 does not support one (for example custom checks or
`--policy-type rcp`), the tool exits with code 2 and tells you to upgrade boto3.
