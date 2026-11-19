# Configuration

Every option can be set on the command line, in a YAML or TOML file (`--config FILE`), or,
for a few of them, in an environment variable.

## Precedence

From lowest to highest priority:

1. Built-in defaults
2. Config file
3. Environment variables
4. Command-line arguments

A flag you do not pass never overrides a value from the file or the environment. For
example, `upload: true` in the file stays enabled when you run `--config c.yaml`.

## Config file

=== "YAML"

    ```yaml
    # config.yaml
    profile: my-aws-profile
    policies_path: ./policies
    policy_type: identity            # identity, resource, scp or rcp
    format: html
    zip: true

    upload: true
    bucket_name: my-reports-bucket

    fail_on: warning                 # error, security-warning, warning, suggestion, none
    log_format: json
    ```

=== "TOML"

    ```toml
    # config.toml
    profile = "my-aws-profile"
    policies_path = "./policies"
    policy_type = "identity"
    format = "html"
    zip = true

    upload = true
    bucket_name = "my-reports-bucket"

    fail_on = "warning"
    log_format = "json"
    ```

Run it with `validate-aws-policies --config config.yaml`. The file must end in `.yaml`,
`.yml` or `.toml`. Copy `config.example.yaml` or `config.example.toml` from the repository
for a commented starting point.

## Keys

| Key | Type | Default | Command-line option |
|---|---|---|---|
| `profile` | string | none | `--profile` |
| `policies_path` | string | `./policies` | `--policies-path` |
| `policy_type` | string | `identity` | `--policy-type` |
| `resource_type` | string | none | `--resource-type` |
| `locale` | string | `EN` | `--locale` |
| `recursive` | bool | false | `--recursive` |
| `max_findings` | int | all | `--max-findings` |
| `format` | string | `json` | `--format` |
| `output` | string | none | `--output` |
| `zip` | bool | false | `--zip` |
| `upload` | bool | false | `--upload` |
| `bucket_name` | string | none | `--bucket` |
| `dry_run` | bool | false | `--dry-run` |
| `continue_on_error` | bool | false | `--continue-on-error` |
| `fail_on` | string | none | `--fail-on` |
| `verbose` / `quiet` | bool | false | `--verbose` / `--quiet` |
| `log_format` | string | `text` | `--log-format` |
| `log_level` | string | `INFO` | `LOG_LEVEL` variable |
| `check_no_new_access` | bool | false | `--check-no-new-access` |
| `reference_path` | string | none | `--reference-path` |
| `strict_references` | bool | false | `--strict-references` |
| `check_access_not_granted` | bool | false | `--check-access-not-granted` |
| `deny_actions`, `deny_resources` | list | none | `--deny-actions`, `--deny-resources` |
| `check_no_public_access` | string | none | `--check-no-public-access` |
| `checks` | mapping | none | shortcut for the `check_*` keys |
| `policy_sets` | list | none | config file only |
| `ci` | bool | false | `--ci` (no effect today) |

`checks` and `policy_sets` are described in
[Policy Types & Custom Checks](access-analyzer-features.md#policy-sets). Unknown keys are
ignored.

### Older key names

These names from earlier versions still work and mean the same as the new ones:

| Older | Current |
|---|---|
| `directory_policies_path` | `policies_path` |
| `upload_report` | `upload` |
| `zip_reports` | `zip` |
| `bucket` | `bucket_name` |

## Environment variables

| Variable | Sets | Notes |
|---|---|---|
| `AWS_PROFILE` | `profile` | Also read by boto3 when no profile is set |
| `POLICIES_PATH` | `policies_path` | |
| `REPORTS_BUCKET` | `bucket_name` | |
| `LOG_LEVEL` | `log_level` | `DEBUG`, `INFO`, `WARNING` or `ERROR`. `--verbose` and `--quiet` take priority. |

An environment variable overrides the config file, and a command-line option overrides both.

## Checks the tool runs on your configuration

Invalid combinations stop the run with exit code 2 and a message, before any AWS call:

- `--upload` without a bucket, or `--bucket` without `--upload`
- `--dry-run` together with `--upload` (and, on the command line, `--zip`)
- `resource_type` without `policy_type: resource`
- custom checks with `scp` or `rcp` policies, `check_no_new_access` without `reference_path`,
  `check_access_not_granted` without `deny_actions` or `deny_resources`
- `verbose` and `quiet` both enabled
- an unknown policy type, locale, `fail_on` level or resource type

## AWS configuration

Profiles live in `~/.aws/config`:

```ini
[profile my-sso-profile]
sso_start_url = https://my-sso-portal.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = MyRole
region = us-east-1
```

Run `aws sso login --profile my-sso-profile` first. Without a profile the standard
credential chain applies (environment variables, container or instance role). Set
`AWS_REGION` if your profile has no region.

## S3 upload

Reports are uploaded to:

```text
s3://<bucket>/AccessAnalyzer/<YYYY>/<MM>/<DD>/<file name>
```

for example `s3://my-bucket/AccessAnalyzer/2026/03/06/AccessAnalyzerReport_20260306_150000.html`.

## Example configurations

=== "Development"

    ```yaml
    profile: dev-profile
    policies_path: ./policies
    format: text
    verbose: true
    dry_run: true
    ```

=== "CI/CD"

    ```yaml
    policies_path: ./policies
    format: xml
    fail_on: error
    log_format: json
    quiet: true
    ```

=== "Release archive"

    ```yaml
    profile: prod-profile
    policies_path: ./policies
    format: all
    zip: true
    upload: true
    bucket_name: prod-reports-bucket
    ```
