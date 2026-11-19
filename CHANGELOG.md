# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

<!-- insertion marker -->
## [Unreleased]

### Fixed

- `verbose`, `quiet` and `log_format` in a config file and the `LOG_LEVEL` environment variable are now applied. They were ignored before. `verbose` and `quiet` together in a file is a configuration error.
- A failed S3 upload now exits with code 3. It exited 0 before.

### Changed

- The `--ci` help text says the flag currently has no effect.
- Documentation rewritten for 3.2 and published with GitHub Pages.

## [3.2.0]

All changes are backward compatible: existing flags, config keys, exit codes and the
default output are unchanged. New behavior is opt-in.

### Added

- Policy types: `--policy-type identity|resource|scp|rcp` (default `identity`, as before), `--resource-type` for resource policies (S3 bucket, access points, trust policy, DynamoDB table), `--locale`, `--max-findings`.
- Custom policy checks: `--check-no-new-access` (with `--reference-path`, `--strict-references`), `--check-access-not-granted` (with `--deny-actions`, `--deny-resources`) and `--check-no-public-access`. A failed check is reported as an ERROR finding and exits with code 1. These API calls are billed by AWS; policy validation is not.
- Failure handling: `--continue-on-error` and `--fail-on {error,security-warning,warning,suggestion,none}`. The default is still to stop at the first ERROR finding.
- `-r/--recursive` discovery, and `policy_sets` in config files to validate SCPs, trust policies and bucket policies in one run.
- `--format sarif` for GitHub code scanning and other SARIF viewers, and `--format all` is now accepted by the CLI (writes html, md and xml).
- New HTML report: self-contained, light/dark theme, severity filters, search, collapsible policies, line/column and learn-more links, print layout.
- Text output shows each finding's message, line, column and learn-more link.
- Config files: `checks:` section, `bucket` accepted as an alias of `bucket_name`.
- Feature detection for older boto3 versions: the package still supports boto3 1.34.138+. Requesting a feature the installed boto3 lacks exits with code 2 and a clear message.
- GitHub Actions workflow that runs ruff and the tests.

### Fixed

- Config files, environment variables and CLI flags are merged consistently: `upload`, `zip`, `ci`, `dry_run`, `format` and `log_format` set in a config file are no longer overwritten by CLI defaults.
- `directory_policies_path`/`upload_report`/`zip_reports` and `policies_path`/`upload`/`zip` are interchangeable in config files. `zip_reports` was previously ignored.
- `upload` without a bucket (from a config file) exits with code 2 instead of 1. `--dry-run` combined with `upload` in a config file is rejected.
- AWS API errors (permissions, throttling, service errors) now exit with code 3 as documented. They exited with 1 before.
- `--output` is honored for html, md, xml and sarif reports.
- HTML and Markdown reports showed "No details available" for every finding. They now show the Access Analyzer message. The HTML report also escapes policy-derived text.
- Findings are no longer silently capped at 100 per policy.
- `--format text` accepts `.txt` as well as `.text` output files.
- JSON log timestamps no longer use the deprecated `datetime.utcnow()`.
- The Access Analyzer client uses adaptive retries.

### Changed

- `ops.create_zip` is deprecated and delegates to `ReportGenerator.create_zip`.
- `test_junit_xml_output.py` moved to `scripts/validate_junit_xml.py`; retry tests moved to `tests/unit/`.
- Policy files are processed in sorted order.

## [v3.1.1] - JUnit XML CodeBuild compatibility fix

## [v3.1.0] - Markdown and JUnit XML reports; PDF reports removed

## [v3.0.0] - CLI modernization: exit codes, config files, `--dry-run`, `--verbose/--quiet`, hyphenated flags

## [v2.0.2](https://github.com/velez94/validate-aws-policies/releases/tag/v2.0.2) - 2024-09-22

<small>[Compare with first commit](https://github.com/velez94/validate-aws-policies/compare/a143292bbc3b4150258d65d243f37c317f14854b...v2.0.2)</small>

### Bug Fixes

- modify flag to upload reports to S3 ([0026e3a](https://github.com/velez94/validate-aws-policies/commit/0026e3ac5ae795ecce3bc78becbfca63b824a4a5) by alejandro.velez).
- fix description for commands ([d9dc9f9](https://github.com/velez94/validate-aws-policies/commit/d9dc9f9bd4978f319afdab758794c2907261786c) by alejandro.velez).

### Docs

- update readme ([14c7f0a](https://github.com/velez94/validate-aws-policies/commit/14c7f0a283c74fdf13a6a61f3dab18e8ea5a95de) by alejandro.velez).

