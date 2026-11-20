# Tech Stack and Conventions

## Stack

- Python >= 3.9 (ruff target `py39`, mypy `python_version = 3.10` because mypy no longer supports older targets). Use built-in generics (`list[str]`); do not use `X | Y` unions (3.10+). boto3 floor is `>=1.36.0` (a release that has RCP, verified at 1.36.0 and absent at 1.35.0; the three custom checks exist earlier).
- Build: hatchling, `src/` layout. Publish: GitHub Actions `publish.yml` on `v*` tags (build with hatch, TestPyPI, PyPI, Sigstore, GitHub release).
- Runtime deps: boto3, colorama, json2html, zipp, argcomplete, pyyaml, tomli (only for Python < 3.11).
- Dev extras (`pip install -e ".[dev]"`): pytest, pytest-cov, pytest-mock, moto, ruff, mypy, types-pyyaml. Docs extra: zensical (the docs site is built with Zensical, `modern` variant, configured in `mkdocs.yml`).

## Commands

```bash
pip install -e ".[dev]"
pytest                      # coverage and --cov-fail-under=80 are enforced in addopts
ruff check . && ruff format .
mypy src/                   # strict-ish: disallow_untyped_defs is on for src
pre-commit run --all-files
zensical serve               # docs; use `zensical build --strict` before committing doc changes
```

## Code conventions

- Line length 100. Ruff rules: E, W, F, I, B, C4, UP. Type-annotate all functions in `src/` (tests are exempt).
- Use `pathlib.Path` and `with` context managers for files. Always pass `encoding="utf-8"`.
- Use `logging` (module-level `logger = logging.getLogger(__name__)`), not `print`. `print` is allowed only for primary output (JSON/text results, `--version`).
- Raise specific exceptions and map them to exit codes in `validate_policies.main()` and `PolicyValidator.run()`. Do not return bare `1`; import constants from `cli/exit_codes.py`.
- CLI flags use hyphens (`--policies-path`, `--dry-run`, `--log-format`). Do not reintroduce underscore flags.
- New CLI options need: `cli/args.py` (parser and validation), `merge_config()` in `validate_policies.py`, tests, and docs in `docs/usage.md` / `docs/configuration.md`.
- boto3 clients that make network calls should use botocore `Config(retries=...)`. S3 upload already retries with exponential backoff.
- Secrets and bucket names come from env vars or config, never from code or logs. Note `main()` currently logs the merged config at DEBUG; do not add secrets to config.

## Testing

- Tests in `tests/unit/` (pytest, `pytest-mock`, `moto`; botocore `Stubber` is preferred for Access Analyzer calls). `tests/integration/` is empty. Fixtures in `tests/fixtures/{sample_policies,config_files}`; shared fixtures in `tests/conftest.py`.
- Markers: `unit`, `integration`, `slow` (`--strict-markers` is on).
- Mock AWS (moto or `mocker.patch("boto3.client")`); tests must not call real AWS.
- Run tests from the repo root; `pythonpath = ["src"]` is configured.

## Known issues and drift (verify before relying on them)

- Config keys exist in two spellings that `ConfigLoader` keeps in sync per layer: `directory_policies_path`/`policies_path`, `upload_report`/`upload`, `zip_reports`/`zip`. Read the canonical names in new code; keep the legacy ones working.
- CLI options with `default=None` (`--format`, `--log-format`, `--policy-type`) are resolved in `merge_config()` so config file values are not overwritten. Follow that pattern for new options; boolean flags only override when set.
- Default behavior still aborts at the first `ERROR` finding (reports are not written). `--continue-on-error`/`--fail-on` are the opt-in alternative; making them the default is deferred to 4.0.
- `ci` is stored in config but has no effect (documented as such).
- Custom policy checks are billed by AWS per call (USD 0.0020 at last check). Do not run them in tests against real AWS; use botocore `Stubber`.
- Tested compatibility matrix: Python 3.9 with boto3 1.36.0 (the `floor` CI job in `.github/workflows/test.yml`), and current boto3 on 3.10 to 3.14.
- `ops.create_zip` is deprecated and delegates to `ReportGenerator.create_zip`.
- `README.md` was refreshed for 4.x; `docs/*.md` may still mention removed flags. `version` lives in both `pyproject.toml` and `version.py`; bump both.
- `.kiro/steering/improvements.md` is a historical recommendation list. Many items are already implemented. Check the code before treating an item as open.
- `scripts/validate_junit_xml.py` is a manual validator for CodeBuild JUnit output, not a pytest test.
- IaC extraction (`sources/`): spec in `.kiro/specs/iac-policy-extraction/`. Extractors only read mapped policy attributes (never log other plan values). Terraform/OpenTofu fixtures are real tool output; Pulumi fixtures are written from the documented formats because Pulumi is not available here. CloudFormation placeholders were chosen by testing shapes against the live API (an `ImportValue` placeholder must be an IAM-role-shaped ARN).
- Design and status of the Access Analyzer adoption (policy types, custom checks, policy sets, SARIF): `.kiro/specs/access-analyzer-modernization/plan.md`. Everything in 3.x must stay backward compatible.
- The `--format all` and `bucket` config key mismatches in older docs were fixed in 3.2 (both are accepted now).
