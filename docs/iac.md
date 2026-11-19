# Infrastructure as Code Inputs

Validate the policies your infrastructure code is about to deploy, not only policy files.
Point the tool at a Terraform or OpenTofu plan, a CloudFormation or CDK template, or Pulumi
output. It extracts every policy document, validates each one with IAM Access Analyzer using
the right policy type, optionally runs the [custom policy checks](access-analyzer-features.md),
and writes the same reports and exit codes as for policy files.

```bash
terraform show -json tfplan > plan.json
validate-aws-policies --input plan.json --fail-on error
```

No policy files are needed and nothing is deployed. The tool does not need access to your
Terraform state, and it calls no AWS API other than Access Analyzer (and S3 if you use
`--upload`).

## How it works

1. The input is read and its format is detected from the content (or set with `--source`).
2. The extractor looks up resources in a table (see [supported resources](#supported-resources))
   and reads only the attributes that hold policies.
3. Policies are grouped by type (identity, trust policy, S3 bucket policy, SCP, and so on) and
   each group is validated with the matching `policyType` and resource type.
4. Results use the resource address as the policy name, for example
   `module.queue.aws_sqs_queue_policy.q`.

## Terraform and OpenTofu

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json      # tofu show -json tfplan for OpenTofu
validate-aws-policies --input plan.json
```

State JSON (`terraform show -json` without a plan file) is accepted too.

- Policies of resources in modules are included. Resources that are only being deleted and
  data sources are ignored.
- `--only-changed` limits the run to resources planned for create or update, which keeps
  custom-check costs down.
- A policy that depends on another resource, for example a bucket policy that uses the
  bucket ARN, has no value until `apply`. It is [skipped and reported](#values-not-known-before-deployment).
- Attributes that the provider computes and nobody set, such as `aws_s3_bucket.policy` or
  `aws_sqs_queue.policy`, are ignored without a warning.

## CloudFormation, CDK and SAM

```bash
validate-aws-policies --input template.yaml
validate-aws-policies --input template.json --param Environment=prod --param BucketName=logs
```

- JSON and YAML are supported, including the short forms (`!Ref`, `!Sub`, `!GetAtt`, `!If`, ...).
- A directory is scanned for `*.json`, `*.yaml`, `*.yml` and `*.template` files. Files that
  are not templates, such as the `manifest.json` and `tree.json` that `cdk synth` writes, are
  ignored. Add `--recursive` for sub-directories.
- **CDK:** run `cdk synth` and use `--input cdk.out`.
- **SAM and macros:** the tool does not expand `Transform`. Validate the processed template
  instead: after creating a change set, `aws cloudformation get-template --change-set-name <name>
  --stack-name <stack> --template-stage Processed` returns the expanded template. A warning is
  logged when a `Transform` is present.

### Intrinsic functions

| Construct | Result |
|---|---|
| Parameters | `--param KEY=VALUE`, else the `Default`. A parameter with neither makes the policies that use it *unknown*. |
| `Ref` to a resource | the logical id (an ARN for SNS topics and managed policies, a URL for SQS queues) |
| `Fn::GetAtt` of an `Arn` attribute | a well-formed ARN built from the logical id |
| `AWS::AccountId`, `AWS::Region`, `AWS::Partition`, `AWS::StackName`, `AWS::URLSuffix` | `123456789012`, `AWS_REGION` (else `us-east-1`), `aws`, `stack`, `amazonaws.com` |
| `Fn::Sub`, `Fn::Join`, `Fn::Select`, `Fn::Split`, `Fn::FindInMap`, `Fn::ToJsonString` | evaluated |
| `Fn::If`, `Conditions` (`Fn::Equals`, `Fn::Not`, `Fn::And`, `Fn::Or`), `AWS::NoValue` | evaluated; resources whose `Condition` is false are skipped |
| `Fn::ImportValue` | the placeholder `arn:aws:iam::123456789012:role/imported-<name>`, the one shape Access Analyzer accepts as a principal, a condition value and inside resource ARNs |
| anything else, such as `Fn::GetAZs` | the policy is *unknown* |

The placeholders only need to be well formed. If your policy depends on the real value of an
imported or computed value in a way that changes the findings, pass it with `--param`.

## Pulumi

```bash
pulumi stack export > state.json
validate-aws-policies --input state.json

pulumi preview --json > preview.json
validate-aws-policies --input preview.json --only-changed
```

- Both `stack export` (`deployment.resources`) and `preview --json` (`steps[].newState`) work.
  Delete steps are ignored.
- The policy is read from the resource `inputs` (what you wrote) and falls back to `outputs`.
  Values can be JSON strings or objects.
- Values that are not known during a preview carry Pulumi's unknown marker and are reported as
  [unknown](#values-not-known-before-deployment).

!!! note "Verification status"
    Terraform and OpenTofu support is tested against plans produced by the real tools, and
    CloudFormation placeholders were validated against the live Access Analyzer API. The
    Pulumi parser follows the documented JSON layouts and is tested with fixtures written from
    them, not with a live Pulumi run. Please report any layout that is not recognized.

## Supported resources

Resources that are not in these tables are ignored. To add one, add a line to
`sources/resource_maps.py`.

=== "Terraform / OpenTofu"

    | Resource type | Attribute | Policy type |
    |---|---|---|
    | `aws_iam_policy` | `policy` | identity |
    | `aws_iam_role_policy` | `policy` | identity |
    | `aws_iam_user_policy` | `policy` | identity |
    | `aws_iam_group_policy` | `policy` | identity |
    | `aws_iam_role` | `inline_policy[*].policy` | identity |
    | `aws_ssoadmin_permission_set_inline_policy` | `inline_policy` | identity |
    | `aws_iam_role` | `assume_role_policy` | role trust policy |
    | `aws_s3_bucket_policy` | `policy` | resource (s3-bucket) |
    | `aws_s3_access_point` | `policy` | resource (s3-access-point) |
    | `aws_sqs_queue_policy`, `aws_sqs_queue` | `policy` | resource |
    | `aws_sns_topic_policy`, `aws_sns_topic` | `policy` | resource |
    | `aws_kms_key` | `policy` | resource |
    | `aws_secretsmanager_secret_policy` | `policy` | resource |
    | `aws_ecr_repository_policy` | `policy` | resource |
    | `aws_efs_file_system_policy` | `policy` | resource |
    | `aws_backup_vault_policy` | `policy` | resource |
    | `aws_cloudwatch_log_resource_policy` | `policy_document` | resource |
    | `aws_opensearch_domain_policy` | `access_policies` | resource |
    | `aws_organizations_policy` | `content` | SCP or RCP, from `type` |

=== "CloudFormation"

    | Resource type | Property | Policy type |
    |---|---|---|
    | `AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy` | `PolicyDocument` | identity |
    | `AWS::IAM::Role`, `AWS::IAM::User`, `AWS::IAM::Group` | `Policies[*].PolicyDocument` | identity |
    | `AWS::IAM::Role` | `AssumeRolePolicyDocument` | role trust policy |
    | `AWS::S3::BucketPolicy` | `PolicyDocument` | resource (s3-bucket) |
    | `AWS::S3::AccessPoint` | `Policy` | resource (s3-access-point) |
    | `AWS::S3::MultiRegionAccessPointPolicy` | `Policy` | resource (s3-mrap) |
    | `AWS::S3ObjectLambda::AccessPointPolicy` | `PolicyDocument` | resource (s3-object-lambda) |
    | `AWS::SQS::QueuePolicy`, `AWS::SNS::TopicPolicy` | `PolicyDocument` | resource |
    | `AWS::KMS::Key` | `KeyPolicy` | resource |
    | `AWS::SecretsManager::ResourcePolicy` | `ResourcePolicy` | resource |
    | `AWS::ECR::Repository` | `RepositoryPolicyText` | resource |
    | `AWS::EFS::FileSystem` | `FileSystemPolicy` | resource |
    | `AWS::DynamoDB::Table` | `ResourcePolicy.PolicyDocument` | resource (dynamodb-table) |
    | `AWS::Organizations::Policy` | `Content` | SCP or RCP, from `Type` |

=== "Pulumi (classic AWS provider)"

    | Resource type | Attribute | Policy type |
    |---|---|---|
    | `aws:iam/policy:Policy`, `rolePolicy`, `userPolicy`, `groupPolicy` | `policy` | identity |
    | `aws:iam/role:Role` | `inlinePolicies[*].policy` | identity |
    | `aws:ssoadmin/permissionSetInlinePolicy:PermissionSetInlinePolicy` | `inlinePolicy` | identity |
    | `aws:iam/role:Role` | `assumeRolePolicy` | role trust policy |
    | `aws:s3/bucketPolicy:BucketPolicy` | `policy` | resource (s3-bucket) |
    | `aws:s3/accessPoint:AccessPoint` | `policy` | resource (s3-access-point) |
    | `aws:sqs/queuePolicy:QueuePolicy`, `aws:sqs/queue:Queue` | `policy` | resource |
    | `aws:sns/topicPolicy:TopicPolicy`, `aws:sns/topic:Topic` | `policy` | resource |
    | `aws:kms/key:Key` | `policy` | resource |
    | `aws:secretsmanager/secretPolicy:SecretPolicy` | `policy` | resource |
    | `aws:ecr/repositoryPolicy:RepositoryPolicy` | `policy` | resource |
    | `aws:efs/fileSystemPolicy:FileSystemPolicy` | `policy` | resource |
    | `aws:backup/vaultPolicy:VaultPolicy` | `policy` | resource |
    | `aws:cloudwatch/logResourcePolicy:LogResourcePolicy` | `policyDocument` | resource |
    | `aws:opensearch/domainPolicy:DomainPolicy` | `accessPolicies` | resource |
    | `aws:organizations/policy:Policy` | `content` | SCP or RCP, from `type` |

Organizations policies of other types (tag, backup and AI opt-out policies) are not validated by
Access Analyzer and are skipped. Resource policies without a specific resource type are checked
with the generic resource policy rules.

## Values not known before deployment

Some policies cannot be read before the infrastructure exists, for example a bucket policy built
from the bucket ARN. These are never guessed and never sent to Access Analyzer.

- **Default:** the policy is skipped, a warning names it, and the text output and the HTML
  report list it.
- **`--unknown-values fail`:** everything else is still validated and reported, then the run
  exits with code 1.

Typical fixes: run the check after a first deploy using state or a second plan, make the
policy independent of computed values (use a fixed ARN or a name you control), or accept the gap
for policies that your resource-specific checks already cover.

## Compare with a baseline

`--check-no-new-access` compares each policy with the same policy in a baseline input. Policies
are matched by their address or logical id.

```bash
# On the main branch
terraform show -json tfplan > baseline.json

# On the pull request
validate-aws-policies --input plan.json \
  --check-no-new-access --reference-input baseline.json
```

A policy that is not in the baseline is skipped. Add `--strict-references` to fail instead. Use
`--only-changed` to limit billed calls to what the change touches. See
[custom checks](access-analyzer-features.md#custom-policy-checks) for the other checks. In IaC
mode the public-access check runs only on policies of the matching resource type, so
`--check-no-public-access s3-bucket` checks bucket policies and nothing else.

## Options

| Option | Config key | Description |
|---|---|---|
| `--input PATH [PATH ...]` | `input` | Plan, template, Pulumi JSON, or a directory of templates |
| `--source {auto,terraform-plan,cloudformation,pulumi}` | `source` | Format of the input (default: detected) |
| `--reference-input PATH [PATH ...]` | `reference_input` | Baseline for `--check-no-new-access` |
| `--param KEY=VALUE` | `params` (mapping) | CloudFormation parameter, repeatable |
| `--unknown-values {skip,fail}` | `unknown_values` | What to do with unknown policies (default: skip) |
| `--only-changed` | `only_changed` | Terraform and Pulumi: only created or updated resources |
| `--recursive` | `recursive` | Search sub-directories of a directory input |

`--input` replaces `--policies-path` (using both is an error). `--policy-type` and
`--resource-type` do not apply, because the resource type decides them. All other options work:
`--format`, `--output`, `--fail-on`, `--continue-on-error`, `--locale`, `--zip`, `--upload`,
`--dry-run`, the logging options and the custom checks.

Several inputs can be given. Their ids are then prefixed with the file name, for example
`stack-a.template.json:DataBucketPolicy`.

```yaml
# validate.yaml
profile: my-profile
input: [plan.json]
reference_input: [baseline.json]
check_no_new_access: true
unknown_values: skip
fail_on: error
```

## Results and reports

The result of an IaC policy has the same shape as for files, plus a `source` object. Existing
keys are unchanged.

```json
{
  "filePolicy": "module.queue.aws_sqs_queue_policy.q",
  "summary": [{"policyName": "module.queue.aws_sqs_queue_policy.q", "issueCode": "None",
               "findingType": "None", "details": "No findings"}],
  "source": {"type": "terraform-plan", "file": "plan.json", "resourceType": "aws_sqs_queue_policy"}
}
```

- **SARIF:** the artifact is the plan or template, the policy is a logical location, and no line
  region is emitted. Line and column in a finding refer to the policy JSON inside the resource,
  not to your `.tf` or template file.
- **HTML:** every policy shows its source type and resource type, and the header lists the inputs
  and the policies that were not validated.
- **Text output** lists skipped policies at the end. They are not part of the JSON results.

## CI examples

=== "GitHub Actions (Terraform)"

    ```yaml
    - uses: hashicorp/setup-terraform@v3
    - run: terraform init && terraform plan -out=tfplan
    - run: terraform show -json tfplan > plan.json
    - run: pip install validate-aws-policies
    - run: validate-aws-policies --input plan.json --only-changed --fail-on error
    ```

=== "GitHub Actions (CDK)"

    ```yaml
    - run: npx cdk synth
    - run: pip install validate-aws-policies
    - run: validate-aws-policies --input cdk.out --fail-on error -f sarif -o results.sarif
    ```

=== "Pulumi"

    ```yaml
    - run: pulumi preview --json > preview.json
    - run: pip install validate-aws-policies
    - run: validate-aws-policies --input preview.json --only-changed --fail-on error
    ```

=== "CodeBuild"

    ```yaml
    phases:
      build:
        commands:
          - terraform show -json tfplan > plan.json
          - validate-aws-policies --input plan.json -f xml -o reports/policies.xml
    reports:
      policy-validation:
        files: ['reports/policies.xml']
        file-format: JUNITXML
    ```

## Security notes

A Terraform plan can contain secrets. The tool reads only the policy attributes listed in the
tables above. It does not log or write any other value of the plan, even with `--verbose`.
Reports contain the policy documents and the resource addresses, so treat them like the
policies themselves.

## Troubleshooting

**"Unrecognized input"** The file is not a plan, template or Pulumi JSON. For Terraform use
`terraform show -json <planfile>`, not the binary plan or `terraform plan -json` (which streams
log lines).

**A policy is missing from the results** Check that the resource type is in the tables, that
the plan action is not only `delete`, and that `--only-changed` is not hiding an unchanged
resource. Run with `--verbose` to see which inputs were read and which computed attributes were
ignored.

**A policy is listed as not validated** Its value is unknown before deployment. See
[the section above](#values-not-known-before-deployment).

**Unexpected findings in CloudFormation policies** A placeholder for a reference may differ
from the real value. Pass real values with `--param`.
