# Tech Stack and Conventions

## Stack

- Python >= 3.9. Ruff target `py39`; mypy `python_version = "3.10"` because mypy no longer accepts older targets. Use built-in generics (`list[str]`); do not use `X | Y` unions (3.10+).
- boto3 `>=1.36.0`. That is the oldest release verified to know resource control policies (1.35.0 does not). The three custom checks exist in older releases.
- Build: hatchling, `src/` layout. Publish: `publish.yml` on `v*` tags (build, TestPyPI, PyPI, Sigstore, GitHub release). Pushing a tag publishes to PyPI.
- Runtime deps: boto3, colorama, argcomplete, pyyaml, tomli (only for Python < 3.11).
- Extras: `dev` (pytest, pytest-cov, pytest-mock, moto, ruff, mypy, types-pyyaml) and `docs` (zensical, `<0.2.0`).

## Commands

```bash
pip install -e ".[dev,docs]"
pytest                          # enforces --cov-fail-under=80
ruff check src                  # CI lints src only; some older tests still have long lines
mypy src --ignore-missing-imports
zensical serve                  # docs preview
zensical build --strict         # fails on broken links, anchors and missing snippet files
```

## Code conventions

- Line length 100. Ruff rules: E, W, F, I, B, C4, UP. Type-annotate all functions in `src/` (tests are exempt).
- Use `pathlib.Path` and `with` for files, always with `encoding="utf-8"`.
- Use `logging` (`logger = logging.getLogger(__name__)`), not `print`. `print` is only for primary output (results, `--version`).
- Raise specific exceptions and map them to exit codes in `validate_policies.main()` and `PolicyValidator.run()`. Import the constants from `cli/exit_codes.py`.
- CLI flags use hyphens. Value options use `default=None` and are resolved in `merge_config()` so config-file values are not overwritten; boolean flags only override when set.
- A new option needs: `cli/args.py`, `merge_config()`, validation in `cli/validation.py`, tests, and `docs/` plus `CHANGELOG.md`.
- New Access Analyzer capabilities must be detected at run time (`iam_access_analyzer/features.py`), not assumed from the boto3 version.
- Secrets and bucket names come from env vars or config, never from code or logs. Extractors read only the policy attributes they map and never log other values of a plan.

## Testing

- Tests live in `tests/unit/`. Use botocore `Stubber` for Access Analyzer calls, `unittest.mock` or moto elsewhere. **Tests must not call real AWS**; custom checks cost money per call.
- Terraform/OpenTofu fixtures in `tests/fixtures/iac/` are real tool output. CloudFormation fixtures are hand written. Pulumi fixtures are written from the documented formats (Pulumi was not available to generate them). See the README there.
- Markers `unit`, `integration`, `slow` (`--strict-markers` is on). `tests/integration/` is empty.
- CI (`test.yml`): lint and mypy, Python 3.9 to 3.14, and a `floor` job (Python 3.9 with boto3 1.36.0).

## Known quirks

- Config keys exist in two spellings that `ConfigLoader` keeps in sync per layer: `directory_policies_path`/`policies_path`, `upload_report`/`upload`, `zip_reports`/`zip`, `bucket`/`bucket_name`. Read the canonical names in new code and keep the legacy ones working.
- The default still aborts at the first `ERROR` finding. Making `--continue-on-error` the default is a breaking change for a future major version.
- `--ci` is accepted and stored but has no effect (documented as such).
- `ops.create_zip` is deprecated and delegates to `ReportGenerator.create_zip`.
- The version lives in `pyproject.toml` and `version.py`; bump both and `CHANGELOG.md`.
- `scripts/validate_junit_xml.py` is a manual CodeBuild validator, not a pytest test.
- CloudFormation `Fn::ImportValue` placeholders must be IAM-role-shaped ARNs: Access Analyzer rejects plain strings in `ArnEquals` and unknown services (checked against the live API).
- Design records: `.kiro/specs/access-analyzer-modernization/plan.md` and `.kiro/specs/iac-policy-extraction/`.
