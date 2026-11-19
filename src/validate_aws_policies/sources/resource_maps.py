"""Which resource attributes hold policy documents, per IaC tool.

These tables are data. To support another resource, add one ``MapEntry``.
``resource_type`` uses the short names of ``--resource-type`` and is only set where
Access Analyzer has a resource-specific check; other resource policies are validated
with the generic resource policy checks.
"""


from .base import MapEntry

M = MapEntry

TERRAFORM_MAP: tuple[MapEntry, ...] = (
    # Identity policies
    M("aws_iam_policy", "policy", "identity"),
    M("aws_iam_role_policy", "policy", "identity"),
    M("aws_iam_user_policy", "policy", "identity"),
    M("aws_iam_group_policy", "policy", "identity"),
    M("aws_iam_role", "inline_policy[*].policy", "identity", label="inline_policy"),
    M("aws_ssoadmin_permission_set_inline_policy", "inline_policy", "identity"),
    # Role trust policy
    M("aws_iam_role", "assume_role_policy", "resource", "trust-policy", label="assume_role_policy"),
    # Resource policies
    M("aws_s3_bucket_policy", "policy", "resource", "s3-bucket"),
    M("aws_s3_access_point", "policy", "resource", "s3-access-point"),
    M("aws_sqs_queue_policy", "policy", "resource"),
    M("aws_sqs_queue", "policy", "resource"),
    M("aws_sns_topic_policy", "policy", "resource"),
    M("aws_sns_topic", "policy", "resource"),
    M("aws_kms_key", "policy", "resource"),
    M("aws_secretsmanager_secret_policy", "policy", "resource"),
    M("aws_ecr_repository_policy", "policy", "resource"),
    M("aws_efs_file_system_policy", "policy", "resource"),
    M("aws_backup_vault_policy", "policy", "resource"),
    M("aws_cloudwatch_log_resource_policy", "policy_document", "resource"),
    M("aws_opensearch_domain_policy", "access_policies", "resource"),
    # Organizations (type decides SCP or RCP)
    M("aws_organizations_policy", "content", "scp", type_path="type"),
)

CLOUDFORMATION_MAP: tuple[MapEntry, ...] = (
    M("AWS::IAM::Policy", "Properties.PolicyDocument", "identity"),
    M("AWS::IAM::ManagedPolicy", "Properties.PolicyDocument", "identity"),
    M("AWS::IAM::Role", "Properties.Policies[*].PolicyDocument", "identity", label="Policies"),
    M("AWS::IAM::User", "Properties.Policies[*].PolicyDocument", "identity", label="Policies"),
    M("AWS::IAM::Group", "Properties.Policies[*].PolicyDocument", "identity", label="Policies"),
    M(
        "AWS::IAM::Role",
        "Properties.AssumeRolePolicyDocument",
        "resource",
        "trust-policy",
        label="AssumeRolePolicyDocument",
    ),
    M("AWS::S3::BucketPolicy", "Properties.PolicyDocument", "resource", "s3-bucket"),
    M("AWS::S3::AccessPoint", "Properties.Policy", "resource", "s3-access-point"),
    M(
        "AWS::S3::MultiRegionAccessPointPolicy",
        "Properties.Policy",
        "resource",
        "s3-mrap",
    ),
    M(
        "AWS::S3ObjectLambda::AccessPointPolicy",
        "Properties.PolicyDocument",
        "resource",
        "s3-object-lambda",
    ),
    M("AWS::SQS::QueuePolicy", "Properties.PolicyDocument", "resource"),
    M("AWS::SNS::TopicPolicy", "Properties.PolicyDocument", "resource"),
    M("AWS::KMS::Key", "Properties.KeyPolicy", "resource"),
    M("AWS::SecretsManager::ResourcePolicy", "Properties.ResourcePolicy", "resource"),
    M("AWS::ECR::Repository", "Properties.RepositoryPolicyText", "resource"),
    M("AWS::EFS::FileSystem", "Properties.FileSystemPolicy", "resource"),
    M(
        "AWS::DynamoDB::Table",
        "Properties.ResourcePolicy.PolicyDocument",
        "resource",
        "dynamodb-table",
    ),
    M("AWS::Organizations::Policy", "Properties.Content", "scp", type_path="Properties.Type"),
)

PULUMI_MAP: tuple[MapEntry, ...] = (
    M("aws:iam/policy:Policy", "policy", "identity"),
    M("aws:iam/rolePolicy:RolePolicy", "policy", "identity"),
    M("aws:iam/userPolicy:UserPolicy", "policy", "identity"),
    M("aws:iam/groupPolicy:GroupPolicy", "policy", "identity"),
    M("aws:iam/role:Role", "inlinePolicies[*].policy", "identity", label="inlinePolicies"),
    M(
        "aws:ssoadmin/permissionSetInlinePolicy:PermissionSetInlinePolicy",
        "inlinePolicy",
        "identity",
    ),
    M(
        "aws:iam/role:Role",
        "assumeRolePolicy",
        "resource",
        "trust-policy",
        label="assumeRolePolicy",
    ),
    M("aws:s3/bucketPolicy:BucketPolicy", "policy", "resource", "s3-bucket"),
    M("aws:s3/accessPoint:AccessPoint", "policy", "resource", "s3-access-point"),
    M("aws:sqs/queuePolicy:QueuePolicy", "policy", "resource"),
    M("aws:sqs/queue:Queue", "policy", "resource"),
    M("aws:sns/topicPolicy:TopicPolicy", "policy", "resource"),
    M("aws:sns/topic:Topic", "policy", "resource"),
    M("aws:kms/key:Key", "policy", "resource"),
    M("aws:secretsmanager/secretPolicy:SecretPolicy", "policy", "resource"),
    M("aws:ecr/repositoryPolicy:RepositoryPolicy", "policy", "resource"),
    M("aws:efs/fileSystemPolicy:FileSystemPolicy", "policy", "resource"),
    M("aws:backup/vaultPolicy:VaultPolicy", "policy", "resource"),
    M("aws:cloudwatch/logResourcePolicy:LogResourcePolicy", "policyDocument", "resource"),
    M("aws:opensearch/domainPolicy:DomainPolicy", "accessPolicies", "resource"),
    M("aws:organizations/policy:Policy", "content", "scp", type_path="type"),
)
