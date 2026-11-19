"""Constants for IAM Access Analyzer policy validation and custom policy checks.

This module has no third-party imports so the CLI can use it cheaply.
"""


# Friendly CLI/config names -> ValidatePolicy ``policyType`` values
POLICY_TYPES: dict[str, str] = {
    "identity": "IDENTITY_POLICY",
    "resource": "RESOURCE_POLICY",
    "scp": "SERVICE_CONTROL_POLICY",
    "rcp": "RESOURCE_CONTROL_POLICY",
}
DEFAULT_POLICY_TYPE = "IDENTITY_POLICY"

# Policy types supported by the custom policy check APIs
# (CheckNoNewAccess and CheckAccessNotGranted do not accept SCPs or RCPs).
CHECKABLE_POLICY_TYPES: tuple[str, ...] = ("identity", "resource")

# Friendly names -> ValidatePolicy ``validatePolicyResourceType`` values.
# Only valid together with the ``resource`` policy type.
RESOURCE_TYPES: dict[str, str] = {
    "s3-bucket": "AWS::S3::Bucket",
    "s3-access-point": "AWS::S3::AccessPoint",
    "s3-mrap": "AWS::S3::MultiRegionAccessPoint",
    "s3-object-lambda": "AWS::S3ObjectLambda::AccessPoint",
    "trust-policy": "AWS::IAM::AssumeRolePolicyDocument",
    "dynamodb-table": "AWS::DynamoDB::Table",
}

LOCALES: tuple[str, ...] = (
    "DE",
    "EN",
    "ES",
    "FR",
    "IT",
    "JA",
    "KO",
    "PT_BR",
    "ZH_CN",
    "ZH_TW",
)
DEFAULT_LOCALE = "EN"

# ValidatePolicy finding types, most severe first.
SEVERITY_ORDER: tuple[str, ...] = ("ERROR", "SECURITY_WARNING", "WARNING", "SUGGESTION")

# --fail-on values -> finding type threshold ("none" never fails)
FAIL_ON_LEVELS: dict[str, str] = {
    "error": "ERROR",
    "security-warning": "SECURITY_WARNING",
    "warning": "WARNING",
    "suggestion": "SUGGESTION",
    "none": "",
}

# Custom policy check names (config/CLI) and the issue codes used in reports
CHECK_NO_NEW_ACCESS = "CHECK_NO_NEW_ACCESS"
CHECK_ACCESS_NOT_GRANTED = "CHECK_ACCESS_NOT_GRANTED"
CHECK_NO_PUBLIC_ACCESS = "CHECK_NO_PUBLIC_ACCESS"

# Operations introduced after the 3.0 SDK floor; feature-detected at runtime.
CHECK_OPERATIONS: dict[str, str] = {
    CHECK_NO_NEW_ACCESS: "CheckNoNewAccess",
    CHECK_ACCESS_NOT_GRANTED: "CheckAccessNotGranted",
    CHECK_NO_PUBLIC_ACCESS: "CheckNoPublicAccess",
}
