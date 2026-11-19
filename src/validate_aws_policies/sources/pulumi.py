"""Extract policies from Pulumi ``stack export`` and ``preview --json`` output.

The formats are taken from the Pulumi documentation. The extractor is tolerant:
missing keys are skipped instead of failing.
"""

import logging
from typing import Any, Dict, List, Optional

from .base import (
    ORGANIZATION_POLICY_TYPES,
    PULUMI,
    ExtractionResult,
    ExtractOptions,
    MapEntry,
    PolicyDocument,
    SkippedPolicy,
    document_id,
    policy_text,
    walk_path,
)
from .resource_maps import PULUMI_MAP

logger = logging.getLogger(__name__)

# Pulumi's marker for a value that is not known during a preview
UNKNOWN_MARKER = "04da6b54-80e4-46f7-96ec-b56ff0331ba9"


def is_pulumi(data: Any) -> bool:
    """True if the parsed JSON looks like a Pulumi stack export or preview."""
    if not isinstance(data, dict):
        return False
    deployment = data.get("deployment")
    if isinstance(deployment, dict) and "resources" in deployment:
        return True
    return isinstance(data.get("steps"), list)


def _contains_unknown(value: Any) -> bool:
    if isinstance(value, str):
        return UNKNOWN_MARKER in value
    if isinstance(value, dict):
        return any(_contains_unknown(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_unknown(v) for v in value)
    return False


def _states(data: Dict[str, Any], options: ExtractOptions) -> List[Dict[str, Any]]:
    """Resource states from a stack export or the new states of a preview."""
    states: List[Dict[str, Any]] = []
    deployment = data.get("deployment")
    if isinstance(deployment, dict) and "resources" in deployment:
        for resource in deployment.get("resources") or []:
            states.append({**resource, "_op": "same"})
        return states

    for step in data.get("steps") or []:
        op = step.get("op", "")
        if op in ("delete", "discard", "remove-pending-replace", "delete-replaced"):
            continue
        if options.only_changed and op not in ("create", "update", "replace", "create-replacement"):
            continue
        state = step.get("newState") or {}
        if not state:
            continue
        states.append({"urn": step.get("urn") or state.get("urn"), "_op": op, **state})
    return states


def _name_and_type(state: Dict[str, Any]) -> Optional[tuple]:
    urn = state.get("urn") or ""
    resource_type = state.get("type") or ""
    parts = urn.split("::")
    if len(parts) >= 4:
        return parts[2] if not resource_type else resource_type, parts[3]
    return (resource_type, urn) if resource_type else None


def _lookup(state: Dict[str, Any], key: str) -> Any:
    """Read an attribute from ``inputs`` first (what the author wrote), then ``outputs``."""
    for section in ("inputs", "outputs"):
        values = state.get(section)
        if isinstance(values, dict) and values.get(key) is not None:
            return values[key]
    return None


def extract_pulumi(
    data: Dict[str, Any], file: str, options: Optional[ExtractOptions] = None
) -> ExtractionResult:
    """Extract policy documents from parsed Pulumi JSON."""
    options = options or ExtractOptions()
    result = ExtractionResult()
    by_type: Dict[str, List[MapEntry]] = {}
    for entry in PULUMI_MAP:
        by_type.setdefault(entry.iac_type, []).append(entry)

    for state in _states(data, options):
        identity = _name_and_type(state)
        if identity is None:
            continue
        resource_type, name = identity
        entries = by_type.get(resource_type)
        if not entries:
            continue
        base = f"{resource_type}::{name}"

        for entry in entries:
            policy_type: str = entry.policy_type
            if entry.type_path:
                declared = _lookup(state, entry.type_path) or "SERVICE_CONTROL_POLICY"
                mapped_type = ORGANIZATION_POLICY_TYPES.get(str(declared))
                if mapped_type is None:
                    logger.info(f"Skipping {base}: policy type {declared} is not validated")
                    continue
                policy_type = mapped_type

            top = entry.path.split(".")[0]
            key = top[:-3] if top.endswith("[*]") else top
            raw = _lookup(state, key)
            if raw is None:
                continue
            container = {key: raw}
            for indices, list_key, value, _unknown in walk_path(
                container, None, entry.path.split(".")
            ):
                policy_id = document_id(base, entry, indices, list_key)
                if _contains_unknown(value):
                    result.skipped.append(
                        SkippedPolicy(policy_id, "not known until deployment", file, resource_type)
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
                        source_type=PULUMI,
                        file=file,
                        iac_type=resource_type,
                    )
                )
    return result
