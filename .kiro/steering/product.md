# Product: validate-aws-policies

A Python CLI (PyPI package `validate-aws-policies`; the version is in `pyproject.toml`) that validates AWS IAM policies with IAM Access Analyzer and writes reports. It is meant for local use and CI/CD pipelines (GitHub Actions, AWS CodeBuild, Azure Pipelines, GitLab, Jenkins).

- Author: Alejandro Velez (labvel.io). Repo: github.com/velez94/validate-aws-policies. License: Apache 2.0.
- Entry point: `validate-aws-policies` -> `validate_aws_policies.validate_policies:main`.
- Docs: `docs/`, built with Zensical (config in `mkdocs.yml`) and published to https://velez94.github.io/validate-aws-policies/ by `.github/workflows/docs.yml`. `docs/changelog.md` includes the root `CHANGELOG.md`.

## What it does

Input is a directory of policy files, or (`--input`) the policies inside a Terraform/OpenTofu plan, a CloudFormation/CDK template or Pulumi JSON. IaC policies are found through resource tables, grouped by policy type, and reported under their resource address. Policies whose value is unknown before deployment are skipped and listed, never guessed.

1. Reads `*.json` policy files (non-recursive by default, `--recursive` optional), each `policy_sets` entry of a config file, or the IaC input.
2. Sends each policy to Access Analyzer `validate_policy` (paginated) with the policy type (identity default, resource, scp, rcp), resource type and locale.
3. Optionally runs custom policy checks (`CheckNoNewAccess`, `CheckAccessNotGranted`, `CheckNoPublicAccess`) on identity and resource policies. AWS bills these per API call; validation is free.
4. Prints or writes results (`json`, `text`) or a report (`html`, `md`, `xml`/`junit`, `sarif`, `all`).
5. Optionally zips reports and uploads them to S3 under `AccessAnalyzer/YYYY/MM/DD/<file>`.
6. Returns a specific exit code.

## Behavior that matters

- Default: an `ERROR` finding aborts the run (`validate_findings` raises `ValueError`, exit 1). `--continue-on-error` and `--fail-on` validate everything, write the reports, then fail by threshold. A failed custom check is an `ERROR` finding (`CHECK_*` issue codes, `details.source == "custom_check"`) and exits 1 after the reports are written.
- Exit codes (`cli/exit_codes.py`): 0 success, 1 validation or failed check, 2 configuration (including a boto3 too old for a requested value), 3 AWS API error or failed upload, 4 file. CI users depend on these; never renumber them.
- Compatibility is a hard rule within a major version: no flag, config key, exit code or default output is removed or changed, and new behavior is opt-in. Raising the Python or boto3 floor, or flipping a default, needs a major version. Current floors: Python 3.9, boto3 1.36.0.
- Config precedence, lowest to highest: defaults, config file (YAML/TOML), environment variables (`AWS_PROFILE`, `REPORTS_BUCKET`, `POLICIES_PATH`, `LOG_LEVEL`), command line.
- Logs go to stderr and results to stdout, so stdout stays pipeable.
- The HTML report is one self-contained file (no external assets) and must escape every value that comes from a policy or from the API.

## Prerequisites for users

AWS credentials with `access-analyzer:ValidatePolicy`; `access-analyzer:CheckNoNewAccess`, `CheckAccessNotGranted` and `CheckNoPublicAccess` for custom checks; `s3:PutObject` for `--upload`.
