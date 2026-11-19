# Product: validate-aws-policies

A Python CLI (PyPI package `validate_aws_policies`, current version 3.2.0) that validates AWS IAM policy JSON files with the IAM Access Analyzer `ValidatePolicy` API and produces reports. It is meant for local use and CI/CD pipelines (GitHub Actions, AWS CodeBuild, Azure Pipelines).

- Author: Alejandro Velez (labvel.io). Repo: github.com/velez94/validate-aws-policies. License: Apache 2.0.
- Entry point: `validate-aws-policies` -> `validate_aws_policies.validate_policies:main`.
- Docs: `docs/` (mkdocs-material, see `mkdocs.yml`), published to GitHub Pages at https://velez94.github.io/validate-aws-policies/ by `.github/workflows/docs.yml`. `docs/changelog.md` includes the root `CHANGELOG.md`.

## What it does

1. Reads every `*.json` file in a policies directory (non-recursive by default, `--recursive` optional) or in each `policy_sets` entry from a config file.
2. Sends each file to Access Analyzer `validate_policy` (paginated) with the configured policy type (identity default, resource, scp, rcp), resource type and locale.
3. Optionally runs custom policy checks (`CheckNoNewAccess`, `CheckAccessNotGranted`, `CheckNoPublicAccess`) on identity and resource policies. These are billed per API call.
4. Prints or writes results (`json` or `text`), or generates a report (`html`, `md`/`markdown`, `xml`/`junit`, `sarif`, `all`).
5. Optionally zips reports and uploads them to S3 under `AccessAnalyzer/YYYY/MM/DD/<file>`.
6. Returns a specific exit code.

## Behavior that matters

- Default: an `ERROR`-level finding aborts the run (`validate_findings` raises `ValueError`, exit code 1). `--continue-on-error` and `--fail-on` (opt-in) validate everything, write the reports, then fail by threshold. A failed custom check is an ERROR finding (`CHECK_*` issue codes, `details.source == "custom_check"`) and exits 1 after reports are written.
- Backward compatibility is a hard rule in 3.x: no flag, config key, exit code or default output is removed or changed. New features are opt-in and feature-detected against the installed boto3 (floor stays 1.34.138; an unsupported request exits 2).
- Exit codes live in `cli/exit_codes.py`: 0 success, 1 validation or failed check, 2 config (including an SDK too old for a requested feature), 3 AWS API error, 4 file. CI users depend on these, so do not renumber them.
- Config precedence, lowest to highest: defaults, config file (YAML/TOML), environment variables, CLI arguments.
- Environment variables: `AWS_PROFILE`, `REPORTS_BUCKET`, `POLICIES_PATH`, `LOG_LEVEL`.
- Logs go to stderr. Primary output (JSON/text results) goes to stdout, so stdout stays pipeable.
- PDF reports were removed in 3.0 (replaced by Markdown, JUnit XML, and in 3.2 SARIF). `improvements.md` still mentions PDF; treat that as stale.
- The HTML report is one self-contained file (no external assets) and must escape every value that comes from a policy or from the API.

## Pre-requisites for users

AWS credentials (profile or SSO) with `access-analyzer:ValidatePolicy`; `access-analyzer:CheckNoNewAccess`, `CheckAccessNotGranted`, `CheckNoPublicAccess` for custom checks; `s3:PutObject` if uploading.
