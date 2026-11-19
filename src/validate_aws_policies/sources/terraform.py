"""Extract policies from Terraform and OpenTofu plans (``terraform show -json``)."""

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .base import (
    ORGANIZATION_POLICY_TYPES,
    TERRAFORM,
    ExtractionResult,
    ExtractOptions,
    MapEntry,
    PolicyDocument,
    SkippedPolicy,
    document_id,
    policy_text,
    walk_path,
)
from .resource_maps import TERRAFORM_MAP

logger = logging.getLogger(__name__)

CHANGED_ACTIONS = {"create", "update"}


def is_terraform(data: Any) -> bool:
    """True if the parsed JSON looks like Terraform plan or state output."""
    return (
        isinstance(data, dict)
        and "format_version" in data
        and any(key in data for key in ("resource_changes", "planned_values", "values"))
    )


def _module_names(module_address: Optional[str]) -> Tuple[str, ...]:
    return tuple(re.findall(r"module\.([^.\[\]]+)", module_address or ""))


def _configured_attributes(data: Dict[str, Any]) -> Dict[Tuple[Tuple[str, ...], str], Set[str]]:
    """Map (module path, ``type.name``) to the attributes the configuration sets."""
    configured: Dict[Tuple[Tuple[str, ...], str], Set[str]] = {}

    def visit(module: Dict[str, Any], path: Tuple[str, ...]) -> None:
        for resource in module.get("resources", []) or []:
            key = (path, f"{resource.get('type')}.{resource.get('name')}")
            expressions = resource.get("expressions") or {}
            configured[key] = set(expressions)
        for name, call in (module.get("module_calls") or {}).items():
            visit(call.get("module") or {}, path + (name,))

    root = (data.get("configuration") or {}).get("root_module")
    if isinstance(root, dict):
        visit(root, ())
    return configured


def _entries_for(resource_type: str) -> List[MapEntry]:
    return [entry for entry in TERRAFORM_MAP if entry.iac_type == resource_type]


def _planned_resources(data: Dict[str, Any], options: ExtractOptions) -> List[Dict[str, Any]]:
    """Normalize a plan or a state into ``address/type/module/after/unknown`` records."""
    records: List[Dict[str, Any]] = []

    if "resource_changes" in data:
        for change in data.get("resource_changes") or []:
            if change.get("mode") != "managed":
                continue
            detail = change.get("change") or {}
            actions = set(detail.get("actions") or [])
            if actions and actions <= {"delete"}:
                continue
            if options.only_changed and not (actions & CHANGED_ACTIONS):
                continue
            records.append(
                {
                    "address": change.get("address", ""),
                    "type": change.get("type", ""),
                    "name": change.get("name", ""),
                    "module": change.get("module_address"),
                    "after": detail.get("after"),
                    "unknown": detail.get("after_unknown"),
                }
            )
        return records

    def visit(module: Dict[str, Any]) -> None:
        for resource in module.get("resources", []) or []:
            if resource.get("mode") != "managed":
                continue
            address = resource.get("address", "")
            records.append(
                {
                    "address": address,
                    "type": resource.get("type", ""),
                    "name": resource.get("name", ""),
                    "module": address.rsplit(".", 2)[0] if address.startswith("module.") else None,
                    "after": resource.get("values"),
                    "unknown": None,
                }
            )
        for child in module.get("child_modules", []) or []:
            visit(child)

    root = (data.get("values") or {}).get("root_module") or (
        (data.get("planned_values") or {}).get("root_module")
    )
    if isinstance(root, dict):
        visit(root)
    return records


def _policy_type(entry: MapEntry, after: Dict[str, Any]) -> Optional[str]:
    if not entry.type_path:
        return entry.policy_type
    declared = after.get(entry.type_path) or "SERVICE_CONTROL_POLICY"
    return ORGANIZATION_POLICY_TYPES.get(str(declared))


def extract_terraform(
    data: Dict[str, Any], file: str, options: Optional[ExtractOptions] = None
) -> ExtractionResult:
    """Extract policy documents from parsed ``terraform show -json`` output.

    Only the mapped policy attributes are read; no other value of the plan is
    logged or kept.
    """
    options = options or ExtractOptions()
    result = ExtractionResult()
    configured = _configured_attributes(data)

    for record in _planned_resources(data, options):
        entries = _entries_for(record["type"])
        after = record["after"]
        if not entries or not isinstance(after, dict):
            continue

        for entry in entries:
            policy_type = _policy_type(entry, after)
            if policy_type is None:
                logger.info(
                    f"Skipping {record['address']}: policy type "
                    f"{after.get(entry.type_path or '')} is not validated by Access Analyzer"
                )
                continue

            parts = entry.path.split(".")
            for indices, list_key, value, unknown in walk_path(
                after, record["unknown"], parts
            ):
                policy_id = document_id(record["address"], entry, indices, list_key)

                if unknown:
                    attribute = parts[0][:-3] if parts[0].endswith("[*]") else parts[0]
                    key = (_module_names(record["module"]), f"{record['type']}.{record['name']}")
                    known_config = configured.get(key)
                    if known_config is not None and attribute not in known_config:
                        # Computed by the provider (for example aws_s3_bucket.policy)
                        logger.debug(f"Ignoring computed attribute {attribute} of {policy_id}")
                        continue
                    result.skipped.append(
                        SkippedPolicy(
                            policy_id, "not known until apply", file, record["type"]
                        )
                    )
                    continue

                text = policy_text(value)
                if text is None:
                    continue
                result.documents.append(
                    PolicyDocument(
                        id=policy_id,
                        text=text,
                        policy_type=policy_type,
                        resource_type=entry.resource_type,
                        source_type=TERRAFORM,
                        file=file,
                        iac_type=record["type"],
                    )
                )
    return result
