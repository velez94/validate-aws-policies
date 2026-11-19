# Project Structure

```
src/validate_aws_policies/
├── validate_policies.py          # main(): parse args, setup_logging, merge_config, run PolicyValidator, map errors to exit codes
├── version.py                    # __version__ (keep in sync with pyproject.toml)
├── cli/
│   ├── args.py                   # create_parser, validate_args, parse_args, ArgumentValidationError
│   ├── validation.py             # validate_merged_config (config-file values), apply_checks_section
│   ├── config.py                 # ConfigLoader (defaults < YAML/TOML < env vars), ConfigError
│   └── exit_codes.py             # EXIT_SUCCESS/VALIDATION/CONFIG/AWS/FILE (0-4)
├── core/
│   └── validator.py              # PolicyValidator: policy sets, discovery, validate, checks, output, reports, upload, exit code
├── iam_access_analyzer/
│   ├── iam_access_analyzer.py    # validate_policies(): validate_policy paginator, policy/resource type, locale, retries
│   ├── checks.py                 # run_policy_checks(): CheckNoNewAccess, CheckAccessNotGranted, CheckNoPublicAccess
│   ├── constants.py              # policy/resource types, locales, severities (no boto3 import)
│   └── features.py               # SdkFeatureError, runtime detection of operations/enums in the installed boto3
└── ops/
    ├── ops.py                    # read_policies, validate_findings, upload_file (S3 + retry), create_zip (deprecated)
    ├── findings.py               # helpers for the summary format: message, spans, thresholds, counts
    ├── reports.py                # ReportGenerator: html, markdown, junit xml, sarif, zip
    ├── html_report.py            # render_html(): self-contained HTML (CSS/JS embedded)
    └── sarif.py                  # build_sarif(): SARIF 2.1.0

tests/
├── conftest.py                   # shared fixtures (policy dicts, fixtures dirs)
├── unit/                         # test_args, test_args_integration, test_checks, test_config, test_config_precedence, test_iam_access_analyzer, test_main, test_main_flow, test_new_features, test_reports, test_upload_retry, test_validator
├── integration/                  # empty
└── fixtures/{sample_policies,config_files}

scripts/validate_junit_xml.py     # manual CodeBuild JUnit XML validator
docs/                             # mkdocs site: index, installation, usage, configuration, access-analyzer-features, examples, api, changelog, JUNIT_XML_REPORT
examples/policies/                # sample policy JSON
config.example.{yaml,toml}        # sample config files
.github/workflows/publish.yml     # release pipeline
.github/workflows/test.yml        # ruff, mypy and pytest on Python 3.8-3.13
.kiro/specs/cli-developer-improvements/   # requirements, design, tasks for the 3.x CLI modernization
.kiro/specs/access-analyzer-modernization/ # plan for adopting new Access Analyzer APIs
```

## Data flow

`main()` -> `parse_args()` (validates) -> `setup_logging()` -> `merge_config()` -> `validate_merged_config()` -> optional `boto3.setup_default_session(profile)` -> `PolicyValidator(config).run()`:

1. `_targets` (one set from `policies_path`, or each `policy_sets` entry) and `_get_policy_files` (`*.json`, sorted, relative names)
2. `iam_access_analyzer.validate_policies(files, dir, policy_type=..., ...)` -> list of `{"filePolicy": str, "summary": [{policyName, issueCode, findingType, details}]}`
3. `run_policy_checks` if any check is enabled: adds `checks` and ERROR entries (`CHECK_*`) to the results
4. `_output_results` (json/text to stdout or `--output`)
5. `_generate_reports` (html/md/xml/junit/sarif, `all`, optional zip), skipped on `--dry-run`
6. `_upload_reports` (S3 key `AccessAnalyzer/<Y/m/d>/<name>`) if upload is set
7. exit code: `exceeds_threshold(results, fail_on or "error")` -> 1, decided after outputs are written

## Where to put things

- New CLI flag: `cli/args.py` (use `default=None` for value options), then `merge_config` in `validate_policies.py`.
- New config key or env var: `cli/config.py` (`_load_defaults`, `ENV_VAR_MAP`).
- New output format: `ops/reports.py` method, wire it in `PolicyValidator._generate_reports`, add the choice and extension to `--format` in `cli/args.py`, and add tests.
- New Access Analyzer API call: feature-detect it in `iam_access_analyzer/features.py`, add Stubber-based tests, and keep the boto3 floor unchanged.
- Version bump: `pyproject.toml`, `version.py`, `CHANGELOG.md`.
- New exit code: `cli/exit_codes.py` plus docs; keep existing values.
- Release: bump `pyproject.toml` and `version.py`, update `CHANGELOG.md`, push a `vX.Y.Z` tag.
