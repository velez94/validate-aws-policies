"""IAM Access Analyzer custom policy checks.

Wraps the ``CheckNoNewAccess``, ``CheckAccessNotGranted`` and ``CheckNoPublicAccess``
APIs. A failing check is added to the validation report as an ERROR finding
(``issueCode`` CHECK_NO_NEW_ACCESS, CHECK_ACCESS_NOT_GRANTED or CHECK_NO_PUBLIC_ACCESS,
``details.source == "custom_check"``) so every report format and the exit code logic
handle it without special cases. Every executed check, passing or not, is also
listed under the optional ``checks`` key of the policy result.
"""

import logging
from pathlib import Path
from typing import Any, Optional

from ..ops.findings import is_placeholder
from .constants import (
    CHECK_ACCESS_NOT_GRANTED,
    CHECK_NO_NEW_ACCESS,
    CHECK_NO_PUBLIC_ACCESS,
    CHECK_OPERATIONS,
    CHECKABLE_POLICY_TYPES,
    POLICY_TYPES,
)
from .features import ensure_operation, enum_values, normalize_resource_type
from .iam_access_analyzer import get_client, resolve_resource_type

logger = logging.getLogger(__name__)

CHECKS_DOC_URL = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-custom-policy-checks.html"
)

PASS = "PASS"
FAIL = "FAIL"
SKIPPED = "SKIPPED"


def checks_requested(config: dict[str, Any]) -> bool:
    """True if any custom policy check is enabled in the configuration."""
    return bool(
        config.get("check_no_new_access")
        or config.get("check_access_not_granted")
        or config.get("check_no_public_access")
    )


def resolve_public_access_resource_type(client: Any, value: str) -> str:
    """Map a friendly resource type (``s3-bucket``, ``kms-key``) to the API value.

    Raises:
        ValueError: If the SDK model lists resource types and none match
    """
    allowed = enum_values(client, "CheckNoPublicAccessRequest", "resourceType")
    if not allowed:
        return value
    return normalize_resource_type(value, allowed)


def _failure_entry(
    policy_name: str, code: str, message: str, reasons: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "policyName": policy_name,
        "issueCode": code,
        "findingType": "ERROR",
        "details": {
            "source": "custom_check",
            "check": code,
            "findingDetails": message,
            "message": message,
            "reasons": reasons,
            "learnMoreLink": CHECKS_DOC_URL,
        },
    }


def _record(
    result: dict[str, Any],
    name: str,
    outcome: str,
    message: str = "",
    reasons: Optional[list[dict[str, Any]]] = None,
) -> None:
    """Store a check outcome and, for failures, an ERROR entry in the summary."""
    reasons = reasons or []
    result.setdefault("checks", []).append(
        {"name": name, "result": outcome, "message": message, "reasons": reasons}
    )
    if outcome != FAIL:
        return
    summary = result.setdefault("summary", [])
    # The "No findings" placeholder would contradict a failed check.
    summary[:] = [entry for entry in summary if not is_placeholder(entry)]
    file_policy = result.get("filePolicy", "")
    policy_name = file_policy if result.get("source") else Path(file_policy).stem
    summary.append(_failure_entry(policy_name, name, message, reasons))


def _normalize_reasons(raw: Any) -> list[dict[str, Any]]:
    return [
        {key: item[key] for key in ("description", "statementId", "statementIndex") if key in item}
        for item in (raw or [])
    ]


def run_policy_checks(
    results: list[dict[str, Any]],
    policies_dir: Optional[Path],
    policy_type: str,
    config: dict[str, Any],
    client: Optional[Any] = None,
    resource_type: Optional[str] = None,
    documents: Optional[dict[str, str]] = None,
    reference_documents: Optional[dict[str, str]] = None,
    strict_resource_type: bool = False,
) -> None:
    """Run the enabled custom policy checks on already validated policies.

    Results are modified in place. Policies that already have ERROR findings are
    skipped, since the checks need a well formed policy.

    Args:
        results: Output of ``validate_policies`` for ``policies_dir``
        policies_dir: Directory the result file names are relative to (None when
            ``documents`` is given)
        policy_type: ``identity``, ``resource``, ``scp`` or ``rcp``
        config: Configuration with ``check_no_new_access``, ``reference_path``,
            ``strict_references``, ``check_access_not_granted``, ``deny_actions``,
            ``deny_resources`` and ``check_no_public_access``
        client: Optional Access Analyzer client
        resource_type: Resource type of the policy set (policy sets only). When it
            differs from the ``check_no_public_access`` resource type, the public
            access check is skipped for this set.

        documents: Policy texts by result name, for policies that are not files (IaC).
            When given, nothing is read from ``policies_dir``.
        strict_resource_type: Run ``check_no_public_access`` only on policies whose
            ``resource_type`` matches it. Used for IaC, where a group without a specific
            resource type (for example an SQS queue policy) must not be checked as an
            S3 bucket policy.
        reference_documents: Baseline policy texts by result name, used by
            ``CheckNoNewAccess`` instead of files in ``reference_path``

    Raises:
        SdkFeatureError: If the installed boto3 lacks a required operation
        ClientError: If an API call fails
    """
    if not checks_requested(config):
        return

    kind = policy_type.lower()
    if kind not in CHECKABLE_POLICY_TYPES:
        logger.warning(f"Custom policy checks do not support '{kind}' policies; skipping checks")
        return

    api_type = POLICY_TYPES[kind]
    if client is None:
        client = get_client()

    run_new_access = bool(config.get("check_no_new_access"))
    run_not_granted = bool(config.get("check_access_not_granted"))
    public_access_type = config.get("check_no_public_access")
    run_public = bool(public_access_type) and kind == "resource"
    if public_access_type and kind != "resource":
        logger.info("check_no_public_access applies to resource policies only; skipping it here")

    for enabled, code in (
        (run_new_access, CHECK_NO_NEW_ACCESS),
        (run_not_granted, CHECK_ACCESS_NOT_GRANTED),
        (run_public, CHECK_NO_PUBLIC_ACCESS),
    ):
        if enabled:
            ensure_operation(client, CHECK_OPERATIONS[code])

    api_public_type = (
        resolve_public_access_resource_type(client, str(public_access_type)) if run_public else ""
    )
    if run_public and strict_resource_type and not resource_type:
        logger.info("Skipping CheckNoPublicAccess for policies without a specific resource type")
        run_public = False
    if run_public and resource_type:
        try:
            set_api_type = resolve_resource_type(resource_type)
        except ValueError:
            set_api_type = resource_type
        if set_api_type != api_public_type:
            logger.info(
                f"Skipping CheckNoPublicAccess for {resource_type} policies "
                f"(configured for {api_public_type})"
            )
            run_public = False
    reference_dir = Path(config["reference_path"]) if config.get("reference_path") else None
    actions = list(config.get("deny_actions") or [])
    resources = list(config.get("deny_resources") or [])

    for result in results:
        name = result.get("filePolicy", "")
        if any(f.get("findingType") == "ERROR" for f in result.get("summary", [])):
            logger.info(f"Skipping custom checks for {name}: policy has ERROR findings")
            continue

        if documents is not None:
            if name not in documents:
                continue
            document = documents[name]
        else:
            if policies_dir is None:
                raise ValueError("policies_dir or documents is required")
            document = (policies_dir / name).read_text(encoding="utf-8")

        if run_new_access:
            _check_new_access(
                client, result, name, document, api_type, reference_dir, config, reference_documents
            )
        if run_not_granted:
            access: dict[str, list[str]] = {}
            if actions:
                access["actions"] = actions
            if resources:
                access["resources"] = resources
            logger.info(f"Checking {name} does not grant the denied access...")
            response = client.check_access_not_granted(
                policyDocument=document, access=[access], policyType=api_type
            )
            _record_response(result, CHECK_ACCESS_NOT_GRANTED, response)
        if run_public:
            logger.info(f"Checking {name} does not allow public access to {api_public_type}...")
            response = client.check_no_public_access(
                policyDocument=document, resourceType=api_public_type
            )
            _record_response(result, CHECK_NO_PUBLIC_ACCESS, response)


def _check_new_access(
    client: Any,
    result: dict[str, Any],
    name: str,
    document: str,
    api_type: str,
    reference_dir: Optional[Path],
    config: dict[str, Any],
    reference_documents: Optional[dict[str, str]] = None,
) -> None:
    if reference_documents is not None:
        reference_text = reference_documents.get(name)
        reference_label = "the reference input"
    else:
        reference_file = reference_dir / name if reference_dir else None
        reference_text = (
            reference_file.read_text(encoding="utf-8")
            if reference_file is not None and reference_file.is_file()
            else None
        )
        reference_label = str(reference_file)

    if reference_text is None:
        missing = f"No reference policy found for {name} in {reference_label}"
        if reference_documents is None:
            missing = f"No reference policy found at {reference_label}"
        if config.get("strict_references"):
            logger.error(missing)
            _record(result, CHECK_NO_NEW_ACCESS, FAIL, missing)
        else:
            logger.warning(f"{missing}; skipping CheckNoNewAccess for {name}")
            _record(result, CHECK_NO_NEW_ACCESS, SKIPPED, missing)
        return

    logger.info(f"Checking {name} grants no new access compared to {reference_label}...")
    response = client.check_no_new_access(
        existingPolicyDocument=reference_text,
        newPolicyDocument=document,
        policyType=api_type,
    )
    _record_response(result, CHECK_NO_NEW_ACCESS, response)


def _record_response(result: dict[str, Any], code: str, response: dict[str, Any]) -> None:
    outcome = FAIL if response.get("result") == FAIL else PASS
    message = response.get("message", "")
    if outcome == FAIL:
        logger.error(f"{code} failed for {result.get('filePolicy')}: {message}")
    _record(result, code, outcome, message, _normalize_reasons(response.get("reasons")))
