"""Use boto3 and IAM access Analyzer API."""

import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Optional, Union

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from colorama import Fore

from ..ops.ops import read_policies, validate_findings
from .constants import (  # noqa: F401  (POLICY_TYPES re-exported for backward compatibility)
    DEFAULT_LOCALE,
    DEFAULT_POLICY_TYPE,
    LOCALES,
    POLICY_TYPES,
    RESOURCE_TYPES,
)
from .features import ensure_enum_value

logger = logging.getLogger(__name__)

CLIENT_CONFIG = Config(retries={"max_attempts": 3, "mode": "adaptive"})


def get_client() -> Any:
    """Create an Access Analyzer client with adaptive retries."""
    return boto3.client("accessanalyzer", config=CLIENT_CONFIG)


def resolve_policy_type(policy_type: str) -> str:
    """Map a short name (identity, resource, scp, rcp) or API value to the API value.

    Raises:
        ValueError: If the policy type is unknown
    """
    api_value = POLICY_TYPES.get(policy_type.lower(), policy_type)
    if api_value not in POLICY_TYPES.values():
        raise ValueError(f"Unsupported policy type: {policy_type}")
    return api_value


def resolve_resource_type(resource_type: str) -> str:
    """Map a short name (s3-bucket, trust-policy, ...) or API value to the API value.

    Raises:
        ValueError: If the resource type is unknown
    """
    api_value = RESOURCE_TYPES.get(resource_type.lower(), resource_type)
    if api_value not in RESOURCE_TYPES.values():
        raise ValueError(
            f"Unsupported resource type: {resource_type}. "
            f"Supported: {', '.join(sorted(RESOURCE_TYPES))}"
        )
    return api_value


def _check_options(
    policy_type: str,
    resource_type: Optional[str],
    locale: str,
    max_findings: Optional[int],
) -> tuple[str, Optional[str], str]:
    """Validate and normalize the options shared by all validate functions."""
    api_policy_type = resolve_policy_type(policy_type)
    api_resource_type = resolve_resource_type(resource_type) if resource_type else None
    if api_resource_type and api_policy_type != "RESOURCE_POLICY":
        raise ValueError("resource_type is only valid with policy type 'resource'")

    locale = (locale or DEFAULT_LOCALE).upper()
    if locale not in LOCALES:
        raise ValueError(f"Unsupported locale: {locale}. Supported: {', '.join(LOCALES)}")
    if max_findings is not None and max_findings < 1:
        raise ValueError("max_findings must be a positive integer")
    return api_policy_type, api_resource_type, locale


def _make_paginator(
    client: Optional[Any], api_policy_type: str, api_resource_type: Optional[str]
) -> tuple[Any, Any]:
    """Create the client (if needed) and the validate_policy paginator."""
    try:
        if client is None:
            client = get_client()
        # Newer enum values are checked against the installed SDK model so an old
        # boto3 gives a clear message instead of a parameter validation error.
        if api_policy_type == "RESOURCE_CONTROL_POLICY":
            ensure_enum_value(
                client, "ValidatePolicyRequest", "policyType", api_policy_type, "Policy type"
            )
        if api_resource_type:
            ensure_enum_value(
                client,
                "ValidatePolicyRequest",
                "validatePolicyResourceType",
                api_resource_type,
                "Resource type",
            )
        paginator = client.get_paginator("validate_policy")
        logger.debug("Successfully initialized AWS Access Analyzer client")
    except ClientError as e:
        error_msg = f"Failed to initialize AWS Access Analyzer client: {e}"
        logger.error(error_msg)
        raise
    return client, paginator


def _validate_content(
    paginator: Any,
    name: str,
    content: str,
    api_policy_type: str,
    api_resource_type: Optional[str],
    locale: str,
    max_findings: Optional[int],
    fail_fast: bool,
    policy_name: Optional[str] = None,
) -> dict[str, Any]:
    """Validate one policy document and return its report entry.

    ``policy_name`` is only set for documents that are not files (IaC), so the
    ``policyName`` of file results stays the file name without extension.
    """
    request_options: dict[str, Any] = {}
    if api_resource_type:
        request_options["validatePolicyResourceType"] = api_resource_type

    pagination: dict[str, Any] = {"PageSize": 20}
    if max_findings:
        pagination["MaxItems"] = max_findings

    # Call AWS Access Analyzer API with pagination
    response_iterator = paginator.paginate(
        policyDocument=content,
        policyType=api_policy_type,
        locale=locale,
        PaginationConfig=pagination,
        **request_options,
    )

    # Collect all findings across pages
    findings: list[dict[str, Any]] = []
    for page in response_iterator:
        findings.extend(page.get("findings", []))

    logger.debug(f"Found {len(findings)} findings for {name}")

    # Validate and format findings
    if fail_fast:
        if policy_name is None:
            return validate_findings(name, findings)
        return validate_findings(name, findings, policy_name=policy_name)
    return validate_findings(name, findings, fail_fast=False, policy_name=policy_name)


def validate_policies(
    list_policies: list[str],
    policies_path: Union[str, Path],
    policy_type: str = DEFAULT_POLICY_TYPE,
    resource_type: Optional[str] = None,
    locale: str = DEFAULT_LOCALE,
    max_findings: Optional[int] = None,
    fail_fast: bool = True,
    client: Optional[Any] = None,
) -> list[dict[str, Any]]:
    """
    Validate AWS policies using IAM Access Analyzer API.

    This function validates a list of policy files using the AWS IAM Access Analyzer
    service. It reads each policy file, sends it to the Access Analyzer API for
    validation, and collects findings for each policy.

    Args:
        list_policies: Policy file names relative to ``policies_path``
            (e.g., ['policy1.json'] or ['sub/policy2.json'])
        policies_path: Path to the directory containing policy files (string or Path object)
        policy_type: Access Analyzer policy type. Either an API value
            (IDENTITY_POLICY, RESOURCE_POLICY, SERVICE_CONTROL_POLICY,
            RESOURCE_CONTROL_POLICY) or a short name (identity, resource, scp, rcp).
            Defaults to IDENTITY_POLICY.
        resource_type: Optional resource type for resource policies (for example
            ``s3-bucket`` or ``AWS::S3::Bucket``). Only valid with policy type resource.
        locale: Language of the finding messages (default EN)
        max_findings: Stop collecting after this many findings per policy.
            None (default) collects all findings.
        fail_fast: Raise ``ValueError`` on the first ERROR finding (default). When
            False, ERROR findings are returned in the report instead.
        client: Optional Access Analyzer client (created with adaptive retries if omitted)

    Returns:
        List of validation reports, each containing:
            - filePolicy: Policy filename
            - summary: List of findings with issueCode, findingType, and details

    Raises:
        FileNotFoundError: If the policies directory or a policy file doesn't exist
        ClientError: If AWS API call fails (e.g., authentication, authorization, service errors)
        ValueError: If a policy contains ERROR-level findings and ``fail_fast`` is True,
            or if an argument is invalid
        SdkFeatureError: If the installed boto3 does not support the requested option

    Example:
        >>> policies = ['scp-policy.json', 'identity-policy.json']
        >>> path = Path('./policies')
        >>> results = validate_policies(policies, path)
        >>> print(results[0]['summary'])
    """
    report: list[dict[str, Any]] = []

    api_policy_type, api_resource_type, locale = _check_options(
        policy_type, resource_type, locale, max_findings
    )

    # Convert to Path object for consistent handling
    policies_dir = Path(policies_path)

    # Validate that the policies directory exists
    if not policies_dir.exists():
        error_msg = f"Policies directory not found: {policies_dir}"
        logger.error(error_msg)
        raise FileNotFoundError(error_msg)

    if not policies_dir.is_dir():
        error_msg = f"Policies path is not a directory: {policies_dir}"
        logger.error(error_msg)
        raise NotADirectoryError(error_msg)

    client, paginator = _make_paginator(client, api_policy_type, api_resource_type)

    # Validate each policy file
    for policy_filename in list_policies:
        logger.info(f"{Fore.GREEN}Validating {policy_filename}...{Fore.RESET}")

        # Construct full path to policy file
        policy_file = policies_dir / policy_filename

        try:
            # Read policy content
            policy_content = read_policies(policy_file)

            if policy_content is None:
                logger.warning(f"Skipping {policy_filename}: Unable to read file")
                continue

            report.append(
                _validate_content(
                    paginator,
                    policy_filename,
                    policy_content,
                    api_policy_type,
                    api_resource_type,
                    locale,
                    max_findings,
                    fail_fast,
                )
            )

        except FileNotFoundError:
            logger.error(f"Policy file not found: {policy_file}")
            raise
        except ValueError:
            # ERROR-level finding (fail_fast); already logged by validate_findings
            raise
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            logger.error(
                f"AWS API error while validating {policy_filename}: [{error_code}] {error_msg}"
            )
            raise
        except Exception as e:
            logger.error(f"Unexpected error validating {policy_filename}: {e}")
            raise

    logger.info(f"Successfully validated {len(report)} policies")
    return report


def validate_policy_documents(
    documents: Sequence[tuple[str, str]],
    policy_type: str = DEFAULT_POLICY_TYPE,
    resource_type: Optional[str] = None,
    locale: str = DEFAULT_LOCALE,
    max_findings: Optional[int] = None,
    fail_fast: bool = True,
    client: Optional[Any] = None,
) -> list[dict[str, Any]]:
    """
    Validate policy documents that are already in memory (for example from IaC).

    Works like :func:`validate_policies` but takes ``(name, json_text)`` pairs instead of
    file names. The name is used as ``filePolicy`` and ``policyName`` in the report.

    Args:
        documents: Pairs of ``(name, policy document text)``
        policy_type: identity, resource, scp, rcp or the API value
        resource_type: Only with resource policies
        locale: Language of the finding messages
        max_findings: Limit of findings collected per policy (None for all)
        fail_fast: Raise ``ValueError`` at the first ERROR finding when True
        client: Optional Access Analyzer client

    Returns:
        One report entry per document, in the same format as :func:`validate_policies`

    Raises:
        ValueError: Invalid argument, or an ERROR finding with ``fail_fast``
        ClientError: If the API call fails
        SdkFeatureError: If the installed boto3 does not support a requested option
    """
    api_policy_type, api_resource_type, locale = _check_options(
        policy_type, resource_type, locale, max_findings
    )
    report: list[dict[str, Any]] = []
    if not documents:
        return report

    client, paginator = _make_paginator(client, api_policy_type, api_resource_type)

    for name, content in documents:
        logger.info(f"{Fore.GREEN}Validating {name}...{Fore.RESET}")
        try:
            report.append(
                _validate_content(
                    paginator,
                    name,
                    content,
                    api_policy_type,
                    api_resource_type,
                    locale,
                    max_findings,
                    fail_fast,
                    policy_name=name,
                )
            )
        except ValueError:
            raise
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            logger.error(f"AWS API error while validating {name}: [{error_code}] {error_msg}")
            raise

    logger.info(f"Successfully validated {len(report)} policies")
    return report
