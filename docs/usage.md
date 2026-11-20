# Usage

```bash
validate-aws-policies --policies-path ./policies [options]
```

The tool reads every `*.json` file in the directory (add `--recursive` for sub-directories),
validates each one with IAM Access Analyzer, prints or writes the result, and exits with a
code you can use in scripts. Policy files must be plain JSON policy documents:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}
  ]
}
```

## Choose the AWS account

```bash
validate-aws-policies -d ./policies -p my-profile      # --profile
AWS_PROFILE=my-profile validate-aws-policies -d ./policies
```

## Choose the policy type

The default is `identity`. Policies of another type are checked against the wrong rules, and
for example a resource policy with a `Principal` fails as an identity policy.

```bash
validate-aws-policies -d ./scps   --policy-type scp
validate-aws-policies -d ./rcps   --policy-type rcp
validate-aws-policies -d ./bucket-policies --policy-type resource --resource-type s3-bucket
```

See [Policy Types & Custom Checks](access-analyzer-features.md) for resource types, custom
checks and validating several types in one run.

## Policies from Terraform, CloudFormation, CDK or Pulumi

Instead of policy files, validate the policies in an IaC plan or template:

```bash
validate-aws-policies --input plan.json              # terraform show -json / tofu show -json
validate-aws-policies --input template.yaml --param Env=prod
validate-aws-policies --input cdk.out
validate-aws-policies --input preview.json           # pulumi preview --json
```

Results are named after the resource address, for example `aws_iam_policy.deploy`. See
[Infrastructure as Code Inputs](iac.md).

## Output formats

`--format` (`-f`) selects the output. `json` is the default.

| Format | Where it goes | Use for |
|---|---|---|
| `json` | stdout | scripts (`jq`), other tools |
| `text` | stdout | reading in a terminal |
| `html` | `AccessAnalyzerReport_<YYYYMMDD_HHMMSS>.html` | people. [Sample](assets/sample-report.html) |
| `md`, `markdown` | `AccessAnalyzerReport_<...>.md` | pull request comments, wikis |
| `xml`, `junit` | `AccessAnalyzerReport_<...>.xml` | CI test reports, see [JUnit XML](JUNIT_XML_REPORT.md) |
| `sarif` | `AccessAnalyzerReport_<...>.sarif` | GitHub code scanning |
| `all` | html, md and xml files | archiving |

File reports are written to the current directory. Use `--output FILE` (`-o`) to choose the
path of a single-file format (parent directories are created). The extension must match the
format: `.json`, `.txt` or `.text`, `.html`, `.md`, `.xml`, `.sarif` or `.json` for SARIF.
`--output` cannot be used with `--format all`.

### Reading the JSON

```json
[
  {
    "filePolicy": "my-policy.json",
    "summary": [
      {
        "policyName": "my-policy",
        "issueCode": "PASS_ROLE_WITH_STAR_IN_ACTION_AND_RESOURCE",
        "findingType": "SECURITY_WARNING",
        "details": {
          "findingDetails": "Using wildcards (*) in the action and the resource can be overly permissive because it allows iam:PassRole permissions on all resources. ...",
          "learnMoreLink": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html#...",
          "locations": [
            {"path": [{"value": "Statement"}, {"index": 0}, {"value": "Action"}, {"index": 2}],
             "span": {"start": {"line": 9, "column": 8, "offset": 136},
                      "end": {"line": 9, "column": 15, "offset": 143}}}
          ]
        }
      }
    ]
  }
]
```

A policy without findings has one entry with `findingType` `None` and `details` `No findings`.
`details` is the finding as returned by Access Analyzer. In `locations`, lines start at 1 and
columns at 0. Text output and HTML reports show columns starting at 1.

### Text output

```text
Policy Validation Results
==================================================

Policy: my-policy.json
  - SECURITY_WARNING: PASS_ROLE_WITH_STAR_IN_ACTION_AND_RESOURCE
      Using wildcards (*) in the action and the resource can be overly permissive ...
      at line 9, column 9
      https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html#...

Policy: s3-read.json
  No findings
```

## Failure handling and exit codes

| Code | Meaning |
|---|---|
| `0` | Success. Warnings and suggestions do not fail the run by default. |
| `1` | An `ERROR` finding, a failed custom check, or a finding at or above `--fail-on`. |
| `2` | Configuration error: bad arguments or config file, or a boto3 too old for a requested feature. |
| `3` | AWS API error: missing permissions, expired credentials, throttling after retries. |
| `4` | File error: policies directory or file missing or unreadable. |

By default the run stops at the first `ERROR` finding. `--continue-on-error` and
`--fail-on LEVEL` validate everything first, write the output and reports, and then decide
the exit code. See [Failure handling](access-analyzer-features.md#failure-handling).

## Reports, archives and S3

```bash
validate-aws-policies -d ./policies -f all --zip                 # reports_<timestamp>.zip
validate-aws-policies -d ./policies -f html --upload -b my-bucket
```

Uploaded files go to `s3://<bucket>/AccessAnalyzer/<YYYY>/<MM>/<DD>/<file>`. `--upload`
requires `--bucket` (and the reverse). Uploads retry with exponential backoff. `--dry-run`
cannot be combined with `--upload` or `--zip`.

## Dry run

`--dry-run` validates and prints `json` or `text` results but does not write report files,
create archives or upload.

```bash
validate-aws-policies -d ./policies --dry-run
```

## Logging

Logs go to stderr, results to stdout, so `validate-aws-policies ... > results.json` works.

| Option | Effect |
|---|---|
| (default) | INFO |
| `--verbose` | DEBUG, including the full findings and merged configuration |
| `--quiet` | ERROR only. Results on stdout are still printed. |
| `--log-format json` | One JSON object per log line (`timestamp`, `level`, `message`, `module`, `function`) |

The same settings can come from a config file (`verbose`, `quiet`, `log_format`) or the
`LOG_LEVEL` environment variable. A command-line flag wins.

## Options

Run `validate-aws-policies --help` for the full list. The options are also tabulated in the
[API Reference](api.md#command-line-options).

`-c/--ci` is accepted for compatibility and currently has no effect. For pipelines use
`--fail-on`, `--format xml` or `sarif`, and `--log-format json`.
