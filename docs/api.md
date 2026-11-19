# API Reference

## Command-line options

`validate-aws-policies [OPTIONS]`

### General

| Option | Short | Description |
|---|---|---|
| `--help` | `-h` | Show help and exit |
| `--version` | `-v` | Print the version and exit |
| `--config FILE` | | YAML or TOML [config file](configuration.md) |

### Input

| Option | Short | Description |
|---|---|---|
| `--policies-path PATH` | `-d` | Directory with policy `*.json` files. Required unless `--config` provides it. |
| `--recursive` | `-r` | Also read sub-directories |
| `--policy-type TYPE` | `-t` | `identity` (default), `resource`, `scp`, `rcp` |
| `--resource-type TYPE` | | With `resource`: `s3-bucket`, `s3-access-point`, `s3-mrap`, `s3-object-lambda`, `trust-policy`, `dynamodb-table` |
| `--locale LOCALE` | | `DE EN ES FR IT JA KO PT_BR ZH_CN ZH_TW` (default `EN`) |
| `--max-findings N` | | Collect at most N findings per policy |
| `--profile NAME` | `-p` | AWS profile |

### Infrastructure as code

| Option | Description |
|---|---|
| `--input PATH [PATH ...]`, `-i` | Terraform/OpenTofu plan JSON, CloudFormation/CDK template or directory, Pulumi export or preview JSON. Replaces `--policies-path`. |
| `--source SOURCE` | `auto` (default), `terraform-plan`, `cloudformation`, `pulumi` |
| `--reference-input PATH [PATH ...]` | Baseline input for `--check-no-new-access` |
| `--param KEY=VALUE` | CloudFormation parameter, repeatable |
| `--unknown-values {skip,fail}` | Policies unknown before deployment: skip (default) or exit 1 |
| `--only-changed` | Only created or updated resources (Terraform, Pulumi) |

### Output

| Option | Short | Description |
|---|---|---|
| `--format FORMAT` | `-f` | `json` (default), `text`, `html`, `md`, `markdown`, `xml`, `junit`, `sarif`, `all` |
| `--output FILE` | `-o` | Output file. Extension must match the format. Not with `all`. |
| `--zip` | `-z` | ZIP the generated reports |
| `--upload` | `-u` | Upload reports to S3 (needs `--bucket`) |
| `--bucket NAME` | `-b` | S3 bucket (needs `--upload`) |
| `--dry-run` | | Do not write reports, archives or upload |

### Failure handling

| Option | Description |
|---|---|
| `--continue-on-error` | Validate everything and report, then exit 1 on any ERROR |
| `--fail-on LEVEL` | `error`, `security-warning`, `warning`, `suggestion`, `none`. Implies `--continue-on-error`. |

### Custom policy checks

| Option | Description |
|---|---|
| `--check-no-new-access` | Compare with the same-named file in `--reference-path` |
| `--reference-path DIR` | Baseline policies |
| `--strict-references` | A missing baseline file is a failure |
| `--check-access-not-granted` | Fail if `--deny-actions` / `--deny-resources` are granted |
| `--deny-actions A,B` | Comma separated actions |
| `--deny-resources ARN,ARN` | Comma separated resource ARNs |
| `--check-no-public-access TYPE` | Resource type, for example `s3-bucket` or `AWS::S3::Bucket` |

### Logging

| Option | Description |
|---|---|
| `--verbose` | DEBUG logging |
| `--quiet` | ERROR logging only |
| `--log-format {text,json}` | Log line format |
| `--ci`, `-c` | Accepted, no effect |

## Exit codes

| Code | Constant | Meaning |
|---|---|---|
| 0 | `EXIT_SUCCESS` | Success |
| 1 | `EXIT_VALIDATION_ERROR` | ERROR finding, failed custom check, or `--fail-on` threshold reached |
| 2 | `EXIT_CONFIG_ERROR` | Invalid configuration, or boto3 too old for the request |
| 3 | `EXIT_AWS_ERROR` | AWS API error or failed S3 upload |
| 4 | `EXIT_FILE_ERROR` | Policies path or file missing or unreadable |

The constants are in `validate_aws_policies.cli.exit_codes`.

## Result structure

All functions exchange the same list of results, one per policy file:

```python
[
    {
        "filePolicy": "my-policy.json",          # relative to the policies path
        "summary": [
            {
                "policyName": "my-policy",
                "issueCode": "MISSING_VERSION",
                "findingType": "WARNING",        # ERROR, SECURITY_WARNING, WARNING, SUGGESTION
                "details": {...},                # the Access Analyzer finding
            }
        ],
        "checks": [                              # only when custom checks ran
            {"name": "CHECK_NO_NEW_ACCESS", "result": "PASS",   # PASS, FAIL, SKIPPED
             "message": "", "reasons": []}
        ],
    }
]
```

Policies that come from an IaC input have the resource address or logical id as `filePolicy`
and one more key, `source`: `{"type": "terraform-plan", "file": "plan.json", "resourceType":
"aws_iam_policy"}`. Policies skipped because their value is unknown are not part of the
results.

A policy with no findings has one placeholder entry with `findingType` and `issueCode`
`"None"`. Failed custom checks appear in `summary` with `findingType` `ERROR`, an
`issueCode` of `CHECK_NO_NEW_ACCESS`, `CHECK_ACCESS_NOT_GRANTED` or
`CHECK_NO_PUBLIC_ACCESS`, and `details["source"] == "custom_check"`.

## Python API

The Python interface is not covered by the compatibility promise of the command line. The
modules below are stable in practice but may change in a minor release.

### `PolicyValidator`

```python
from validate_aws_policies.core.validator import PolicyValidator

validator = PolicyValidator({
    "policies_path": "./policies",
    "policy_type": "identity",
    "format": "json",
    "dry_run": True,
})
exit_code = validator.run()          # 0..4, see exit codes
```

`PolicyValidator(config: Dict[str, Any])` takes the same keys as the
[config file](configuration.md#keys). `run() -> int` performs the whole workflow:
discover files, validate, run checks, write output and reports, upload, and return the exit
code.

### `validate_policies`

```python
from validate_aws_policies.iam_access_analyzer.iam_access_analyzer import validate_policies

results = validate_policies(
    ["policy1.json", "sub/policy2.json"],
    "./policies",
    policy_type="resource",              # identity, resource, scp, rcp or the API value
    resource_type="s3-bucket",
    locale="EN",
    max_findings=None,
    fail_fast=True,
)
```

| Parameter | Description |
|---|---|
| `list_policies` | File names relative to `policies_path` |
| `policies_path` | Directory (`str` or `Path`) |
| `policy_type` | Default `IDENTITY_POLICY` |
| `resource_type` | Only with resource policies |
| `locale` | Default `EN` |
| `max_findings` | Limit per policy, `None` for all |
| `fail_fast` | `True` (default): raise `ValueError` at the first ERROR finding. `False`: return it. |
| `client` | Optional Access Analyzer client. By default one with adaptive retries is created. |

Raises `FileNotFoundError`, `NotADirectoryError`, `ValueError` (invalid argument or ERROR
finding), `botocore.exceptions.ClientError`, and `SdkFeatureError` when the installed boto3
does not support a requested option.

### `extract` and `validate_policy_documents`

```python
from validate_aws_policies.sources import ExtractOptions, extract
from validate_aws_policies.iam_access_analyzer.iam_access_analyzer import validate_policy_documents

extraction = extract(["plan.json"], source=None, options=ExtractOptions(only_changed=True))
for doc in extraction.documents:          # PolicyDocument: id, text, policy_type, resource_type, ...
    print(doc.id, doc.policy_type, doc.resource_type)
print([s.id for s in extraction.skipped])  # policies whose value is not known yet

results = validate_policy_documents(
    [(doc.id, doc.text) for doc in extraction.documents if doc.policy_type == "identity"],
    policy_type="identity",
)
```

`extract(inputs, source=None, options=None, recursive=False)` reads the inputs and returns an
`ExtractionResult` with `documents` and `skipped`. It raises `FileNotFoundError` for a missing
input and `SourceError` for an input that is not valid or not recognized.
`validate_policy_documents(documents, policy_type, resource_type, locale, max_findings,
fail_fast, client)` validates `(name, json_text)` pairs and returns the same result entries as
`validate_policies`.

### `run_policy_checks`

```python
from validate_aws_policies.iam_access_analyzer.checks import run_policy_checks

run_policy_checks(
    results, "./policies", "identity",
    {"check_no_new_access": True, "reference_path": "./baseline"},
)
```

Modifies `results` in place, adding `checks` and `CHECK_*` ERROR entries. Policies that
already have ERROR findings are skipped. Takes the config keys listed in
[Configuration](configuration.md#keys) and an optional `client` and `resource_type`.

### `ReportGenerator`

```python
from validate_aws_policies.ops.reports import ReportGenerator

gen = ReportGenerator()
html = gen.create_html_report(results, metadata={"tool_version": "3.2.0"})
md = gen.create_markdown_report(results)
xml = gen.create_junit_xml_report(results)
sarif = gen.create_sarif_report(results, base_dir="policies")
archive = gen.create_zip([html, md, xml])
```

Each method writes a file in the current directory and returns its `Path`. Names are
`AccessAnalyzerReport_<YYYYMMDD_HHMMSS>.<ext>` and `reports_<YYYYMMDD_HHMMSS>.zip`.
`metadata` is optional and may contain `tool_version`, `policy_sets` (list of `{path,
policy_type}`), `locale` and `checks` (list of names), shown in the report header.
`base_dir` is the directory used to build file URIs in the SARIF output.

### `upload_file`

```python
from pathlib import Path
from validate_aws_policies.ops.ops import upload_file

ok = upload_file(Path("report.html"), "my-bucket", "AccessAnalyzer/2026/03/06/report.html")
```

Returns `True` on success and `False` after `max_retries` (default 3) failed attempts, with
exponential backoff between them.

## Finding types

Access Analyzer returns four types, ordered here from most to least severe:

| Type | Meaning | JUnit status |
|---|---|---|
| `ERROR` | The policy is invalid or does not work as written | error |
| `SECURITY_WARNING` | The policy allows access that may be unintended or too broad | failure |
| `WARNING` | A problem that does not break the policy | failure |
| `SUGGESTION` | A way to improve the policy | pass |

Common issue codes seen in practice: `UNSUPPORTED_PRINCIPAL` (a resource policy validated as
an identity policy), `MISSING_VERSION`, `PASS_ROLE_WITH_STAR_IN_ACTION_AND_RESOURCE`,
`CREATE_SLR_WITH_STAR_IN_ACTION_AND_RESOURCE`. The complete list, with explanations and fixes,
is in the AWS documentation:
[Access Analyzer policy check reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html).
