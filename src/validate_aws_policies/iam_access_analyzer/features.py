"""Runtime feature detection for the installed boto3/botocore.

The package keeps a low boto3 floor so existing installs keep working. Newer
Access Analyzer capabilities are detected from the service model at runtime and
reported with a clear message when the installed SDK is too old.
"""

from typing import Any, List, Optional


class SdkFeatureError(Exception):
    """Raised when the installed boto3/botocore lacks a required capability."""


UPGRADE_HINT = "Upgrade it with: pip install --upgrade boto3 botocore"


def ensure_operation(client: Any, operation: str) -> None:
    """Fail clearly if the client does not support an API operation.

    Args:
        client: boto3 Access Analyzer client
        operation: API operation name, e.g. ``CheckNoNewAccess``

    Raises:
        SdkFeatureError: If the operation is missing from the service model
    """
    names = client.meta.service_model.operation_names
    if operation not in names:
        raise SdkFeatureError(
            f"The installed boto3 does not support the Access Analyzer operation "
            f"{operation}. {UPGRADE_HINT}"
        )


def enum_values(client: Any, shape: str, member: str) -> Optional[List[str]]:
    """Return the allowed enum values of a request member, or None if unknown."""
    try:
        values = client.meta.service_model.shape_for(shape).members[member].enum
    except (KeyError, AttributeError):
        return None
    return list(values) if values else None


def ensure_enum_value(client: Any, shape: str, member: str, value: str, label: str) -> None:
    """Fail clearly if the SDK model does not know an enum value.

    Args:
        client: boto3 Access Analyzer client
        shape: Request shape name, e.g. ``ValidatePolicyRequest``
        member: Member name, e.g. ``policyType``
        value: Value the tool wants to send
        label: Human readable name for the message

    Raises:
        SdkFeatureError: If the model lists enum values and ``value`` is not one of them
    """
    allowed = enum_values(client, shape, member)
    if allowed and value not in allowed:
        raise SdkFeatureError(
            f"{label} '{value}' is not supported by the installed boto3 "
            f"(supported: {', '.join(allowed)}). {UPGRADE_HINT}"
        )


def normalize_resource_type(value: str, allowed: List[str]) -> str:
    """Map a friendly resource type name to an API value.

    Accepts the API value (``AWS::S3::Bucket``) or a short form that drops the
    ``AWS::`` prefix and replaces ``::`` with ``-`` (``s3-bucket``,
    ``kms-key``), case-insensitively.

    Args:
        value: User supplied resource type
        allowed: API values accepted by the service

    Returns:
        The matching API value

    Raises:
        ValueError: If nothing matches
    """
    lowered = value.strip().lower()
    for api_value in allowed:
        short = api_value.lower().replace("::", "-")
        if lowered in (api_value.lower(), short, short.replace("aws-", "", 1)):
            return api_value
    raise ValueError(
        f"Unsupported resource type '{value}'. Supported: "
        + ", ".join(sorted(allowed))
    )
