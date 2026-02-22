"""Use boto3 and IAM access Analyzer API."""

import logging
from pathlib import Path
from typing import Any, Dict, List, Union

import boto3
from botocore.exceptions import ClientError
from colorama import Fore

from ..ops.ops import read_policies, validate_findings

logger = logging.getLogger(__name__)


def validate_policies(
    list_policies: List[str], policies_path: Union[str, Path]
) -> List[Dict[str, Any]]:
    """
    Validate AWS policies using IAM Access Analyzer API.

    This function validates a list of policy files using the AWS IAM Access Analyzer
    service. It reads each policy file, sends it to the Access Analyzer API for
    validation, and collects findings for each policy.

    Args:
        list_policies: List of policy filenames to validate (e.g., ['policy1.json'])
        policies_path: Path to the directory containing policy files (string or Path object)

    Returns:
        List of validation reports, each containing:
            - filePolicy: Policy filename
            - summary: List of findings with issueCode, findingType, and details

    Raises:
        FileNotFoundError: If the policies directory or a policy file doesn't exist
        ClientError: If AWS API call fails (e.g., authentication, authorization, service errors)
        ValueError: If a policy contains ERROR-level findings (raised by validate_findings)

    Example:
        >>> policies = ['scp-policy.json', 'identity-policy.json']
        >>> path = Path('./policies')
        >>> results = validate_policies(policies, path)
        >>> print(results[0]['summary'])
    """
    report: List[Dict[str, Any]] = []

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

    # Initialize AWS client
    try:
        client = boto3.client("accessanalyzer")
        paginator = client.get_paginator("validate_policy")
        logger.debug("Successfully initialized AWS Access Analyzer client")
    except ClientError as e:
        error_msg = f"Failed to initialize AWS Access Analyzer client: {e}"
        logger.error(error_msg)
        raise

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

            # Call AWS Access Analyzer API with pagination
            response_iterator = paginator.paginate(
                policyDocument=policy_content,
                policyType="IDENTITY_POLICY",  # Options: 'RESOURCE_POLICY'|'SERVICE_CONTROL_POLICY'
                locale="EN",
                PaginationConfig={
                    "MaxItems": 100,
                    "PageSize": 20,
                },
            )

            # Collect all findings across pages
            findings: List[Dict[str, Any]] = []
            for page in response_iterator:
                findings.extend(page.get("findings", []))

            logger.debug(f"Found {len(findings)} findings for {policy_filename}")

            # Validate and format findings
            report.append(validate_findings(policy_filename, findings))

        except FileNotFoundError:
            logger.error(f"Policy file not found: {policy_file}")
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
