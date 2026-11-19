# Development

## Set up

```bash
git clone https://github.com/velez94/validate-aws-policies.git
cd validate-aws-policies
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,docs]"
pre-commit install            # optional
```

## Everyday commands

```bash
pytest                        # unit tests, enforces 80% coverage
ruff check src               # lint
mypy src --ignore-missing-imports
mkdocs serve                  # docs at http://127.0.0.1:8000
mkdocs build --strict         # fails on broken links and missing files
```

The GitHub Actions workflow `test.yml` runs lint and tests on Python 3.8 to 3.13 for every
pull request.

## Code layout

```text
src/validate_aws_policies/
  validate_policies.py     main(): arguments, logging, config merge, exit codes
  cli/                     args.py, config.py, validation.py, exit_codes.py
  core/validator.py        PolicyValidator workflow
  iam_access_analyzer/     validate_policies, custom checks, constants, SDK feature detection
  ops/                     reports (html, markdown, junit, sarif), S3 upload, finding helpers
tests/unit/                pytest tests; AWS calls are stubbed
docs/                      this site
```

## Rules for changes

- **Do not break users within 3.x.** Never remove or rename a flag, config key or exit
  code, and keep defaults. New behavior is opt-in.
- **Keep the boto3 floor** (`>=1.34.138`) and Python 3.8 syntax (`typing.List`, not
  `list[str]`). New API features must be detected at run time, see
  `iam_access_analyzer/features.py`.
- **Tests never call AWS.** Use botocore's `Stubber` or `unittest.mock`. Custom policy checks
  cost money per call.
- **A new option** needs: `cli/args.py` (use `default=None` for value options so config files
  can supply them), `merge_config()` in `validate_policies.py`, validation in
  `cli/validation.py`, tests, and documentation here.
- **HTML report:** escape every value that comes from a policy or from the API. The report
  must stay one self-contained file with no external requests.

## Documentation

The site is built with [MkDocs Material](https://squidfunk.github.io/mkdocs-material/) from
`docs/` and published to GitHub Pages by `.github/workflows/docs.yml` on every push to
`main` that changes the docs.

- The changelog page includes `CHANGELOG.md` from the repository root. Edit that file.
- `docs/assets/sample-report.html` is a real report. Regenerate it after changing the HTML
  report: run the tool with `--format html` and copy the file.
- `mkdocs build --strict` must pass before you open a pull request.

### One-time GitHub setup

In the repository, open **Settings > Pages** and set **Source** to **GitHub Actions**. Or
with the GitHub CLI:

```bash
gh api -X POST repos/velez94/validate-aws-policies/pages -f build_type=workflow
```

The site is then at <https://velez94.github.io/validate-aws-policies/>.

## Release

1. Update `CHANGELOG.md` (move items from *Unreleased* to the new version).
2. Set the same version in `pyproject.toml` and `src/validate_aws_policies/version.py`.
3. Run the tests and `mkdocs build --strict`.
4. Commit, then tag and push: `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin main vX.Y.Z`.

Pushing a `v*` tag runs `publish.yml`: build, TestPyPI, PyPI, Sigstore signing and a GitHub
release.
