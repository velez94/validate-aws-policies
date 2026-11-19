# Design Document: IaC Policy Extraction

## Overview

IaC inputs are turned into a flat list of `PolicyDocument` objects. A group of documents with the same policy type goes through the same Access Analyzer calls, checks, reports and exit-code logic as a directory of policy files. The only new pipeline entry point is a function that validates in-memory documents instead of files.

```text
 plan.json / template.yaml / pulumi.json
        |  sources.detect()  ->  Extractor.extract(path, options)
        v
 ExtractionResult(documents=[PolicyDocument], skipped=[SkippedPolicy])
        |  group by (policy_type, resource_type)
        v
 validate_policy_documents()  ->  run_policy_checks(documents=..., reference_documents=...)
        v
 results (same shape + optional "source")  ->  output / reports / upload / exit code
```

## Module structure

```
src/validate_aws_policies/sources/
  __init__.py          # extract(), detect_source(), SourceError
  base.py              # PolicyDocument, SkippedPolicy, ExtractionResult, ExtractOptions, path helpers
  resource_maps.py     # data tables: TERRAFORM_MAP, CLOUDFORMATION_MAP, PULUMI_MAP
  terraform.py         # terraform-plan extractor (Terraform and OpenTofu)
  cloudformation.py    # template loader (YAML tags) + intrinsic resolver + extractor
  pulumi.py            # stack export and preview extractor
```

Changes to existing modules (all additive):

| Module | Change |
|---|---|
| `iam_access_analyzer/iam_access_analyzer.py` | Split out shared client/option setup and a per-document call; add `validate_policy_documents()`. `validate_policies()` keeps its signature and behavior. |
| `iam_access_analyzer/checks.py` | `run_policy_checks()` accepts `documents` and `reference_documents` (id -> JSON text) so it can run without a directory. |
| `core/validator.py` | `run()` branches to `_run_iac()` when `input` is configured. The output, report, upload and exit-code tail is shared. |
| `cli/args.py`, `validate_policies.py`, `cli/validation.py` | New flags, merge rules, config validation. |
| `ops/sarif.py`, `ops/html_report.py` | Use the optional `source` object. |

## Data model

```python
@dataclass(frozen=True)
class PolicyDocument:
    id: str                      # Policy_Id
    text: str                    # JSON policy document
    policy_type: str             # identity | resource | scp | rcp
    resource_type: Optional[str] # s3-bucket, trust-policy, ... (validate resource types only)
    source_type: str             # terraform-plan | cloudformation | pulumi
    file: str                    # input file
    iac_type: str                # aws_iam_policy, AWS::IAM::Policy, aws:iam/policy:Policy

@dataclass(frozen=True)
class SkippedPolicy:
    id: str; reason: str         # "unknown at plan time", "unresolved intrinsic: Fn::ImportValue"
    file: str; iac_type: str

ExtractionResult(documents, skipped)
ExtractOptions(only_changed, params, unknown_values)
```

## Resource maps

One entry per attribute that holds a policy:

```python
MapEntry(iac_type, path, policy_type, resource_type=None, label=None, type_path=None)
```

- `path` addresses the attribute: `policy`, `Policies[*].PolicyDocument`, `inline_policy[*].policy`. `[*]` fans out over a list.
- `label` is appended to the Policy_Id (`#assume_role_policy`) for resources that produce more than one document.
- `type_path` points to a sibling attribute that decides the policy type (Organizations `type` / `Type`: `SERVICE_CONTROL_POLICY` becomes `scp`, `RESOURCE_CONTROL_POLICY` becomes `rcp`, tag and backup policies are skipped with an info log).

Maps are Python constants, not a packaged data file, so they are always present in the wheel.

## Terraform extractor

Input detection: top-level `format_version` plus `resource_changes`, `planned_values` or `values`.

1. Walk `resource_changes` (plan) or `values.root_module` including `child_modules` (state).
2. Skip `mode != "managed"` and changes whose `actions` are only `["delete"]`. With `only_changed`, keep only `create` and `update` (`replace` included).
3. For each map entry resolve `path` in `change.after` and, in parallel, in `change.after_unknown`.
4. A value that is `None` with `after_unknown == true` is unknown. Look at `configuration` (module calls are nested under `module_calls.<name>.module.resources`): when the resource's `expressions` do not contain the attribute, the attribute is computed and is ignored silently; when they do, report an Unknown_Value.
5. Strings are passed through unchanged. Objects (rare) are serialized with `json.dumps`.

Real plan output (Terraform 1.14) confirmed: `aws_s3_bucket.policy`, `aws_sqs_queue.policy` and `aws_iam_role.inline_policy` appear as unknown computed attributes even when nobody set them, which is why step 4 exists.

## CloudFormation extractor

Loader: `yaml.SafeLoader` subclass with a multi-constructor for `!Tag` that returns `{"Fn::Tag": value}` (`!Ref` returns `{"Ref": value}`, `!GetAtt "A.B"` becomes `["A", "B"]`, `!Sub` keeps string or list form). JSON templates go through `json`.

Resolver: a recursive function over the template with a `Context` (parameters, mappings, conditions, resources, pseudo parameters). It returns a value or raises `Unresolved(reason)`.

| Construct | Resolution |
|---|---|
| `Ref` parameter | `--param`, else `Default`, else Unresolved |
| `Ref` resource | placeholder name `<LogicalId>` (ARN-safe) |
| `Ref` pseudo | `AWS::AccountId` `123456789012`, `AWS::Region` from the profile or `us-east-1`, `AWS::Partition` `aws`, `AWS::StackName` `stack`, `AWS::URLSuffix` `amazonaws.com`, `AWS::NoValue` removes the key |
| `Fn::GetAtt` | `Arn` becomes a service-shaped ARN built from the logical id, other attributes become `<LogicalId>-<Attr>` |
| `Fn::Sub`, `Fn::Join`, `Fn::Select`, `Fn::Split`, `Fn::FindInMap` | evaluated |
| `Fn::If` and Conditions | `Equals`, `Not`, `And`, `Or`, `Condition` evaluated |
| `Fn::ImportValue` | placeholder `arn:aws:iam::123456789012:role/imported-<name>`. Access Analyzer rejects plain strings in `ArnEquals` (`MISSING_ARN_FIELD`) and unknown services (`INVALID_SERVICE`); this shape is clean as principal, condition value and inside resource ARNs (verified against the live API). |
| anything else (`Fn::GetAZs`, `Fn::Transform`, `Fn::Cidr`, unknown) | Unresolved |

Policy-level values are resolved separately per document, so one unresolved document does not discard others in the same resource. `AWS::NoValue` inside statements is removed. Templates with a `Transform` (SAM, macros) are processed but a warning says the transform was not expanded.

## Pulumi extractor

Detection: `deployment.resources` (export) or `steps` (preview). Resource identity: `urn` split on `::` gives type and name. For a preview step use `newState`; skip `op == "delete"`. Read `outputs[attr]`, falling back to `inputs[attr]`. A value equal to the Pulumi unknown marker (`04da6b54-80e4-46f7-96ec-b56ff0331ba9`) or containing it is unknown. Strings are used as given and objects are serialized.

Not verified against a live Pulumi run: Pulumi is not available in the build environment. Fixtures follow the documented export format and the preview `steps[].newState` layout. The docs say so.

## Detection

`detect_source(data)` inspects the parsed document: Terraform (`format_version` with `resource_changes`, `planned_values` or `values`), Pulumi (`deployment` with `resources`, or `steps`), CloudFormation (`Resources` mapping, or `AWSTemplateFormatVersion`). Ambiguous or unknown content raises `SourceError` and the CLI exits with code 2. When an input is a directory, files that are not recognized (for example `manifest.json`, `tree.json` and asset files in `cdk.out`) are ignored; an explicitly named file that is not recognized is an error, and so is a directory without any recognized file.

## Pipeline integration

`PolicyValidator._run_iac()`:

1. Extract from every `input`; extract the Baseline from `reference_input` the same way.
2. Group documents by `(policy_type, resource_type)`.
3. For each group call `validate_policy_documents(docs, policy_type, resource_type, locale, max_findings, fail_fast, client)`, then `run_policy_checks(results, None, policy_type, config, resource_type=..., documents={id: text}, reference_documents={id: text})`.
4. Attach `source` to each result by id.
   `strict_resource_type=True` makes `--check-no-public-access` run only on groups whose resource type matches, so an SQS queue policy is never checked as an S3 bucket policy.
5. Hand over to the shared tail: output, reports, upload, threshold.
6. Skipped policies are logged, put in `metadata` (HTML header) and, with `--unknown-values fail`, turn the exit code into 1.

Result entry (existing keys unchanged, `source` is new and optional):

```json
{"filePolicy": "module.queue.aws_sqs_queue_policy.q",
 "summary": [...],
 "source": {"type": "terraform-plan", "file": "plan.json", "resourceType": "aws_sqs_queue_policy"}}
```

## Reports

- **SARIF:** when `source` exists the artifact URI is `source.file`, the result gets `logicalLocations: [{"name": filePolicy, "kind": "resource"}]`, and no `region` (spans refer to the embedded JSON).
- **HTML:** policy header shows the id plus a chip `terraform-plan . aws_sqs_queue_policy`; the run header lists inputs and the skipped count.
- **JSON, text, Markdown, JUnit:** use the id as the name, no other change.

## CLI

```text
--input PATH [PATH ...]      plan, template, state or directory
--source {auto,terraform-plan,cloudformation,pulumi}
--reference-input PATH [...] baseline for --check-no-new-access
--param KEY=VALUE            CloudFormation parameter (repeatable)
--unknown-values {skip,fail} default skip
--only-changed               Terraform and Pulumi: create/update only
```

`-d` is no longer required when `--input` or a config `input` is present. `--policy-type` and `--resource-type` are ignored with a warning for IaC inputs because the maps decide them. In IaC mode the baseline comes from `--reference-input`; `--reference-path` is for policy files only.

## Error handling

| Situation | Exit |
|---|---|
| input missing or unreadable | 4 |
| not valid JSON/YAML, or not a recognized format | 2 |
| `--input` with `--policies-path` or `policy_sets` | 2 |
| unknown values with `--unknown-values fail` | 1 (after reports) |
| AWS errors | 3 |

## Testing strategy

- **Terraform:** a real `terraform show -json` fixture (Terraform 1.14, provider aws 5.x) and an OpenTofu one, committed under `tests/fixtures/iac/`. Tests assert ids, types, unknown handling and the computed-attribute rule. The generating Terraform project is committed next to the fixture so it can be regenerated.
- **CloudFormation:** hand-written templates (JSON and YAML) for every resolver construct and every mapped resource type.
- **Pulumi:** fixtures written from the documented formats. Tests include the unknown marker and delete steps.
- **Pipeline:** Stubber-based tests that `validate_policy_documents` sends the right `policyType`, resource type and document text; checks use `documents` and `reference_documents`.
- **Live check:** run the Terraform fixture against the real Access Analyzer API (validation is free).
- **Compatibility:** existing 235 tests must pass unchanged; Python 3.9 with boto3 1.36.0 must pass (when written: Python 3.8 with boto3 1.34.138; both floors were raised in 4.0).

## Risks

| Risk | Mitigation |
|---|---|
| Resource maps go stale as providers add resources | Data tables, one place to edit, documented procedure, `--source` independent of maps for unknown types (ignored with a debug log) |
| CloudFormation placeholders cause false findings | Placeholders are well-formed ARNs and names; unresolved values are skipped rather than guessed |
| Pulumi formats change or differ from the fixtures | Tolerant parser (missing keys are skipped), documented as unverified until tested on a live stack |
| Large plans make many billed custom-check calls | `--only-changed`, and the docs say checks bill per policy |
| Plans can hold secrets | Only mapped attributes are read; nothing else is logged or written |
