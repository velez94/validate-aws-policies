# Plan: adopt current IAM Access Analyzer capabilities (backward compatible)

Status: **implemented in 3.2.0** (Phases 0 to 3, delivered together). Decisions taken: `--continue-on-error` stays opt-in until 4.0; failed custom checks exit with code 1. Deviations from the original proposal are listed at the end. Default-changing work is deferred to 4.0.

## 1. What changed in Access Analyzer since the tool was written

Sources: [ValidatePolicy API reference](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ValidatePolicy.html), [CheckNoNewAccess](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_CheckNoNewAccess.html), [CheckAccessNotGranted](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_CheckAccessNotGranted.html), [CheckNoPublicAccess](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_CheckNoPublicAccess.html), [AWS launch post for custom policy checks](https://aws.amazon.com/blogs/security/introducing-iam-access-analyzer-custom-policy-checks/), [June 2024 extension](https://aws.amazon.com/jp/blogs/news/iam-access-analyzer-update-extending-custom-policy-checks-guided-revocation/). I also confirmed the enums against the installed boto3 1.44.7 service model.

| Area | Current API | What the tool does today |
|---|---|---|
| `ValidatePolicy` `policyType` | `IDENTITY_POLICY`, `RESOURCE_POLICY`, `SERVICE_CONTROL_POLICY`, `RESOURCE_CONTROL_POLICY` | Was hardcoded to identity. **done:** `--policy-type identity\|resource\|scp\|rcp`, default `identity`. |
| `ValidatePolicy` `validatePolicyResourceType` | Only with `RESOURCE_POLICY`: S3 bucket, S3 access point, S3 multi-region access point, S3 Object Lambda access point, IAM assume-role (trust) policy, DynamoDB table | Not sent. Resource policies get only the generic checks. |
| `ValidatePolicy` `locale` | DE, EN, ES, FR, IT, JA, KO, PT_BR, ZH_CN, ZH_TW | Hardcoded `EN`. |
| `ValidatePolicy` findings | `findingType` ERROR, SECURITY_WARNING, SUGGESTION, WARNING; each has `locations[].span` (line, column, offset) and `learnMoreLink` | Whole finding is stored in `details`, so these fields already reach JSON/HTML/MD/JUnit. Spans are not shown in text output. |
| Pagination | `validate_policy` paginator | Uses `MaxItems=100`, which silently drops findings after 100 per policy. |
| Custom policy checks (launched Nov 2023, extended mid-2024) | `CheckNoNewAccess` (existing vs. new policy), `CheckAccessNotGranted` (listed actions/resources must not be granted), `CheckNoPublicAccess` (resource policy must not be public for a resource type). Each returns `PASS`/`FAIL` plus `reasons[]` (description, statementId, statementIndex). | Not used. |
| Other features | Unused-access and internal-access analyzers, policy generation from CloudTrail, `GenerateFindingRecommendation` | Out of scope: they need an analyzer in an account and work on deployed resources, not policy files. |

Constraints from the API reference that shape the design:
- `CheckNoNewAccess` and `CheckAccessNotGranted` accept only `IDENTITY_POLICY` or `RESOURCE_POLICY`. SCPs and RCPs cannot be checked.
- `CheckAccessNotGranted` takes an `access` array with at most one item (actions and/or resources).
- `CheckNoPublicAccess` takes a required `resourceType` from a long list (S3, KMS, SQS, SNS, Lambda, DynamoDB, and more) and returns an error for unsupported types.
- New error types to handle: `InvalidParameterException`, `UnprocessableEntityException`.

## 2. Compatibility contract

Every phase must keep all of the following:
1. No flag, config key, env var or exit code is removed, renamed or renumbered. Defaults keep their current values.
2. New behavior is opt-in. Anything that changes default output or exit status waits for 4.0.
3. JSON and report output only gain fields. Existing keys (`filePolicy`, `summary[].policyName|issueCode|findingType|details`) keep their meaning.
4. The boto3 floor stays `>=1.34.138` in 3.x. New APIs are feature-detected at runtime (`client.meta.service_model.operation_names`, enum membership). If the installed SDK is too old, the tool exits with code 2 and a message naming the minimum version. The exact boto3 versions that introduced `CheckNoPublicAccess` and `RESOURCE_CONTROL_POLICY` must be confirmed from the botocore changelog before documenting a floor; I have not verified them. Runtime detection also protects Python 3.8 users, whose pip resolves an older boto3.
5. New tests use botocore `Stubber` against the real service model, since moto may not cover these operations (verify before choosing).

## 3. Phases

### Phase 0: done in this session
- `--policy-type` / `policy_type` config key, default `identity`.
- Config alias handling and precedence fixes, `.txt` for text output, deprecation of `ops.create_zip`, tests (coverage 88.8%).

### Phase 1: ValidatePolicy completeness (3.2.0)
| Item | Design | Compatibility note |
|---|---|---|
| `--resource-type` | Choices from the enum above (short names plus API values). Valid only with `--policy-type resource`; otherwise exit 2. | New flag. |
| `--locale` | Pass through to the API; default `EN`. | Same as today when unset. |
| Findings cap | Drop `MaxItems=100`, keep `PageSize`. Add `--max-findings N` for users who want a cap. | Only differs for policies with more than 100 findings; call it out in the changelog. |
| Retries | Create the `accessanalyzer` client with `Config(retries={"mode": "adaptive", "max_attempts": 3})`, as S3 upload already does. | Update `test_iam_access_analyzer.py`, which asserts `boto3.client("accessanalyzer")` is called with one argument. |
| `--recursive` | Discover `*.json` under subfolders. Report `filePolicy` as the relative path. | Default stays non-recursive. `examples/policies/permissions_set/` shows why it is needed. |
| `--continue-on-error` | Collect all findings, write all reports, then exit 1 if any `ERROR` was found. Default keeps today's abort at the first `ERROR`. | Opt-in. 4.0 flips the default. |
| `--fail-on {error,security-warning,warning,suggestion,none}` | Exit 1 when a finding at or above the level exists. Default `error`. Implies `--continue-on-error`. | Default equals current gating. |
| Text output | Show `line:column` from `locations[].span` and `learnMoreLink`. | Text format is human-oriented; JSON unchanged. |
| Error mapping | `ValidationException`, `InvalidParameterException` -> message with the failing field; throttling -> exit 3 after retries. | Uses existing exit codes. |

### Phase 2: custom policy checks (3.3.0)
CLI (all opt-in, combinable with validation):
- `--check-no-new-access` with `--reference-path DIR`. Each `x.json` is compared to `DIR/x.json` as `existingPolicyDocument`. Missing reference: skip with a warning, or fail with `--strict-references`. Identity and resource types only.
- `--check-access-not-granted` with `--deny-actions a,b` and/or `--deny-resources arn1,arn2`. Sent as one `access` item.
- `--check-no-public-access RESOURCE_TYPE`. Resource policies only. Validate the value against the installed service model enum when present.
- Config file equivalent: a `checks:` mapping with the same options.

Result mapping, to avoid touching the HTML/Markdown/JUnit renderers:
- `FAIL` becomes a summary entry with `findingType: "ERROR"`, `issueCode` one of `CHECK_NO_NEW_ACCESS`, `CHECK_ACCESS_NOT_GRANTED`, `CHECK_NO_PUBLIC_ACCESS`, and `details` containing `source: "custom_check"`, the API `message` and `reasons` (description, statementId, statementIndex).
- `PASS` adds nothing to `summary`. JSON gains an optional `checks` list per policy (`name`, `result`).
- Exit code 1 on any `FAIL`; the same `--fail-on` logic applies.

Open items to verify before coding:
- Billing. Custom checks are separate API calls and ValidatePolicy is not billed the same way. Check the [Access Analyzer pricing page](https://aws.amazon.com/iam/access-analyzer/pricing/) and document it in `docs/usage.md`. I have not verified current prices.
- Quotas and rate limits for the three operations, and whether `access` has size limits on actions/resources.
- Required IAM permissions: `access-analyzer:CheckNoNewAccess`, `CheckAccessNotGranted`, `CheckNoPublicAccess`, in addition to `ValidatePolicy`.

### Phase 3: optional (3.4.0)
- Policy sets in config: `policy_sets: [{path, policy_type, resource_type}]`, so one run can validate SCPs, trust policies and bucket policies together. A single `--policy-type` remains the CLI shorthand.
- `--format sarif` using `locations[].span`, for GitHub code scanning and similar viewers. Additive format.
- `ci` mode: currently stored but unused. Define it (for example `--ci` implies `--continue-on-error` and `--log-format json`) only if there is demand; otherwise document it as a no-op.

### Deferred to 4.0 (breaking, needs a migration note)
- Flip `--continue-on-error` to the default.
- Raise the Python floor and boto3 floor, and drop the legacy config key spellings.
- Remove `ops.create_zip`.

## 4. Test plan
- Stubber-based contract tests for `validate_policy` (each policy type, resource type, locale, pagination across more than 100 findings) and for the three check operations (PASS, FAIL with reasons, error responses).
- CLI tests for flag conflicts: `--resource-type` without `--policy-type resource`, checks with `scp`/`rcp`, `--check-no-new-access` without `--reference-path`.
- Regression tests that pin today's behavior: default invocation sends `IDENTITY_POLICY` and `EN`, JSON shape unchanged, exit codes unchanged, legacy config keys still honored.
- Feature-detection test with a stubbed old service model (operation missing -> exit 2 with the minimum-version message).
- Keep the 80% coverage gate. Add a GitHub Actions `test.yml` (ruff, mypy, pytest on Python 3.8 to 3.13), because only the publish workflow exists today.

## 5. Docs and release
- Update `docs/usage.md`, `docs/configuration.md`, `docs/api.md`, `CHANGELOG.md`, and the IAM permissions section for each phase.
- Bump `pyproject.toml` and `version.py` together. Tag `v3.2.0`, `v3.3.0` after each phase merges.
- Add an example CI snippet (GitHub Actions and CodeBuild) that uses `--check-no-new-access` against a baseline policies directory.

## 6. Decisions needed from the maintainer
1. Is `--continue-on-error` as opt-in acceptable until 4.0, or should the default change in 3.2.0?
2. Should failing custom checks reuse exit code 1, or get a new code (for example 5)? This plan uses 1 so CI scripts that test for non-zero keep working.
3. Do you want Phase 3 (policy sets, SARIF)?

## 7. Implementation notes (3.2.0)

- All phases shipped in one release instead of 3.2/3.3/3.4. Version is 3.2.0.
- `--format all` was already supported by the validator but rejected by the CLI; it is now accepted (html, md, xml). `sarif` is not part of `all`, so the set of files written by `all` is unchanged.
- `--check-no-public-access` takes the AWS resource type (`AWS::S3::Bucket`) or a short form (`s3-bucket`), validated against the installed boto3 model. In `policy_sets` it runs only on sets whose `resource_type` matches.
- AWS API errors now exit 3 as documented (they exited 1 because `PolicyValidator.run` caught them first). This is the one exit-code change; it only affects runs that already failed.
- Pricing confirmed on the [pricing page](https://aws.amazon.com/iam/access-analyzer/pricing/): custom checks are USD 0.0020 per API call; validation is free. Quotas were not verified.
- Verified against the live Access Analyzer API and on Python 3.8 with boto3 1.34.138 (floor).
- Not done: the `ci` flag is still a no-op (documented as demand-driven), and the 4.0 items in section 3.
