# Requirements Document

## Introduction

Validate the IAM policies that infrastructure-as-code (IaC) tools are about to deploy, not only standalone policy JSON files. The tool extracts policy documents from Terraform and OpenTofu plans, CloudFormation and CDK templates, and Pulumi previews or stack exports, then runs them through the existing pipeline: IAM Access Analyzer validation, custom policy checks, reports and exit codes.

AWS publishes `tf-policy-validator` (Terraform) and `cfn-policy-validator` (CloudFormation). This feature adds one CLI that covers Terraform, CloudFormation and Pulumi with the reports, thresholds and checks users already have. Pulumi has no AWS-published validator.

All requirements are additive. Existing flags, config keys, exit codes, defaults and the result format keep working unchanged (3.x compatibility contract).

## Glossary

- **IaC_Source**: A supported input format: `terraform-plan`, `cloudformation`, `pulumi`.
- **Extractor**: Component that reads an IaC input and returns Policy_Documents.
- **Policy_Document**: One policy found in an IaC input: id, JSON text, policy type, optional resource type, origin.
- **Policy_Id**: Stable identifier of a Policy_Document: the Terraform address, the CloudFormation logical id, or the Pulumi type and name.
- **Unknown_Value**: A value that is not known before deployment (Terraform `after_unknown`, an unresolvable CloudFormation intrinsic, a Pulumi unknown marker).
- **Resource_Map**: Data table that says, per IaC resource type, which attributes hold policies and of which policy type.
- **Baseline**: A second IaC input (for example the plan from the main branch) used as the reference for `CheckNoNewAccess`.
- **Pipeline**: Validation, custom checks, reports, upload and exit code handling that already exists.

## Requirements

### Requirement 1: Input selection

**User Story:** As a pipeline author, I want to point the tool at a plan or template instead of a policy directory, so that I validate exactly what will be deployed.

#### Acceptance Criteria

1. THE CLI SHALL accept `--input PATH [PATH ...]` and `--source {auto,terraform-plan,cloudformation,pulumi}` (default `auto` when `--input` is given).
2. WHEN `--source auto` is used, THE CLI SHALL detect the format from the file content, not from its name.
3. WHEN a directory is given as input, THE CLI SHALL read the CloudFormation template files in it (`*.json`, `*.yaml`, `*.yml`, `*.template`), recursively only with `--recursive`.
4. WHEN `--input` is not given, THE CLI SHALL behave exactly as before.
5. IF `--input` and `policy_sets` are both configured, THEN THE CLI SHALL exit with code 2.
6. IF an input file is missing, unreadable or not in the selected format, THEN THE CLI SHALL exit with code 4 for a file problem and code 2 for a format problem, with a message naming the file.
7. THE CLI SHALL accept the same settings in a config file (`source`, `input`, `reference_input`, `params`, `unknown_values`, `only_changed`).

### Requirement 2: Terraform and OpenTofu plans

**User Story:** As a Terraform user, I want the policies in `terraform show -json` output validated, so that bad policies fail the pull request before `apply`.

#### Acceptance Criteria

1. THE Extractor SHALL read the JSON produced by `terraform show -json <plan>` and `tofu show -json <plan>`, and state JSON as well.
2. THE Extractor SHALL use `resource_changes` for plans, including resources in child modules, and SHALL ignore data sources and resources whose planned action is only `delete`.
3. THE Extractor SHALL map at least these resource types: `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_iam_group_policy`, `aws_iam_role` (`assume_role_policy` as a trust policy and `inline_policy[*].policy`), `aws_s3_bucket_policy`, `aws_s3_access_point`, `aws_sqs_queue_policy`, `aws_sqs_queue`, `aws_sns_topic_policy`, `aws_sns_topic`, `aws_kms_key`, `aws_secretsmanager_secret_policy`, `aws_ecr_repository_policy`, `aws_organizations_policy` (SCP or RCP by its `type`), `aws_ssoadmin_permission_set_inline_policy`, `aws_efs_file_system_policy`, `aws_backup_vault_policy`, `aws_cloudwatch_log_resource_policy`, `aws_opensearch_domain_policy`.
4. WHEN a mapped attribute is unknown and the configuration sets it, THE Extractor SHALL treat it as an Unknown_Value (Requirement 5).
5. WHEN a mapped attribute is unknown and the configuration does not set it (a computed attribute such as `aws_s3_bucket.policy`), THE Extractor SHALL ignore it without a warning.
6. THE Policy_Id SHALL be the resource address, with `#<attribute>` appended when a resource yields more than one document.
7. WHEN `--only-changed` is set, THE Extractor SHALL return only resources planned for `create` or `update`.

### Requirement 3: CloudFormation, CDK and SAM output

**User Story:** As a CloudFormation or CDK user, I want template policies validated, including templates that use intrinsic functions.

#### Acceptance Criteria

1. THE Extractor SHALL read JSON and YAML templates, including the short-form tags (`!Ref`, `!Sub`, `!GetAtt`, `!Join`, `!If`, and the rest of the `Fn::` family).
2. THE Extractor SHALL map at least: `AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy`, `AWS::IAM::Role` (trust policy and `Policies[*]`), `AWS::IAM::User`, `AWS::IAM::Group`, `AWS::S3::BucketPolicy`, `AWS::S3::AccessPoint`, `AWS::SQS::QueuePolicy`, `AWS::SNS::TopicPolicy`, `AWS::KMS::Key`, `AWS::SecretsManager::ResourcePolicy`, `AWS::ECR::Repository`, `AWS::Organizations::Policy` (SCP or RCP by `Type`), `AWS::DynamoDB::Table`, `AWS::EFS::FileSystem`.
3. THE Extractor SHALL resolve `Ref`, `Fn::Sub`, `Fn::Join`, `Fn::Select`, `Fn::Split`, `Fn::FindInMap`, `Fn::If` with `Conditions` (`Fn::Equals`, `Fn::Not`, `Fn::And`, `Fn::Or`), `Fn::GetAtt`, `Fn::ImportValue` and the `AWS::` pseudo parameters, using template parameter defaults and `--param KEY=VALUE` overrides.
4. WHEN a reference points to another resource, THE Extractor SHALL substitute a well-formed placeholder (a name for `Ref`, an ARN for `Fn::GetAtt` of `Arn`) so the policy still validates.
5. WHEN an intrinsic cannot be resolved, THE Extractor SHALL treat the policy as an Unknown_Value.
6. THE Policy_Id SHALL be the logical id, with `#<property>` appended when a resource yields more than one document.
7. THE CLI SHALL document that CDK users run `cdk synth` and SAM users translate the template first.

### Requirement 4: Pulumi

**User Story:** As a Pulumi user, I want the policies in a preview or exported stack validated.

#### Acceptance Criteria

1. THE Extractor SHALL read `pulumi stack export` JSON (`deployment.resources`) and `pulumi preview --json` (`steps[].newState`).
2. THE Extractor SHALL map at least the AWS classic provider resources for the policy types in Requirement 2.3, using the Pulumi type tokens (for example `aws:iam/policy:Policy`).
3. THE Extractor SHALL accept a policy value that is a JSON string or an object.
4. THE Extractor SHALL read `inputs` first (what the author wrote) and `outputs` second, so provider-generated defaults are not validated.
5. WHEN a preview step is a `delete`, THE Extractor SHALL skip it.
6. WHEN a policy value is the Pulumi unknown marker, THE Extractor SHALL treat it as an Unknown_Value.
7. THE Policy_Id SHALL be `<type>::<name>` from the resource URN.

### Requirement 5: Unknown values

**User Story:** As a user, I want to know which policies could not be checked and decide whether that fails the build.

#### Acceptance Criteria

1. THE CLI SHALL skip an Unknown_Value policy by default, log a warning that names the Policy_Id, and list the skipped policies in the reports.
2. WHERE `--unknown-values fail` is set, THE CLI SHALL still validate everything else and then exit with code 1.
3. THE CLI SHALL NOT send placeholder text for an Unknown_Value to Access Analyzer.

### Requirement 6: Pipeline reuse

**User Story:** As a user, I want IaC policies to get the same validation, checks, reports and exit codes as policy files.

#### Acceptance Criteria

1. THE CLI SHALL group extracted policies by policy type and resource type and validate each group with the matching Access Analyzer `policyType` and `validatePolicyResourceType`.
2. THE CLI SHALL honor `--locale`, `--max-findings`, `--fail-on`, `--continue-on-error`, `--format`, `--output`, `--zip`, `--upload`, `--dry-run` and the logging options for IaC inputs.
3. THE CLI SHALL run the custom policy checks on IaC policies with the same rules as for files (identity and resource policies only).
4. WHEN `--reference-input` is given, THE CLI SHALL use the Baseline policy with the same Policy_Id as `existingPolicyDocument` for `CheckNoNewAccess`, and SHALL skip, or with `--strict-references` fail, a policy that has no Baseline entry.
5. THE result entry of an IaC policy SHALL use the Policy_Id as `filePolicy` and SHALL add an optional `source` object (`type`, `file`, `resourceType`). Existing keys SHALL NOT change.
6. THE SARIF report SHALL use the input file as the artifact and the Policy_Id as a logical location, and SHALL NOT emit a line region, because positions refer to the embedded document.
7. THE HTML report SHALL show the source type, input file and resource type of each policy and the number of skipped policies.

### Requirement 7: Safety and compatibility

#### Acceptance Criteria

1. THE Extractor SHALL read only the mapped policy attributes. THE CLI SHALL NOT log or write other plan values, such as sensitive attributes, at any log level.
2. THE package SHALL add no required dependency. YAML parsing SHALL use PyYAML, which is already a dependency.
3. THE code SHALL keep Python 3.9 syntax and the boto3 floor (3.8 and boto3 below 1.36.0 were dropped in 4.0).
4. WHEN `--input` is used with `--policies-path`, THE CLI SHALL exit with code 2.
5. Resource maps SHALL be data tables with tests built from real tool output where a tool is available (Terraform, OpenTofu).
