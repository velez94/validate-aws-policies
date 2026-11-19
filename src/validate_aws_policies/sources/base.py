"""Shared model and helpers for the IaC policy extractors."""

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Optional

TERRAFORM = "terraform-plan"
CLOUDFORMATION = "cloudformation"
PULUMI = "pulumi"
SOURCES = (TERRAFORM, CLOUDFORMATION, PULUMI)


class SourceError(Exception):
    """The input is not in the expected IaC format (exit code 2)."""


@dataclass(frozen=True)
class MapEntry:
    """Where one kind of IaC resource keeps a policy document.

    Attributes:
        iac_type: Resource type in the IaC tool (``aws_iam_policy``, ``AWS::IAM::Policy``)
        path: Dotted attribute path; ``[*]`` fans out over a list
        policy_type: ``identity``, ``resource``, ``scp`` or ``rcp``
        resource_type: Short ValidatePolicy resource type (``s3-bucket``, ``trust-policy``)
        label: Suffix of the policy id for resources with several documents
        type_path: Sibling attribute that decides the policy type (Organizations policies)
    """

    iac_type: str
    path: str
    policy_type: str
    resource_type: Optional[str] = None
    label: Optional[str] = None
    type_path: Optional[str] = None


@dataclass(frozen=True)
class PolicyDocument:
    """One policy found in an IaC input."""

    id: str
    text: str
    policy_type: str
    resource_type: Optional[str]
    source_type: str
    file: str
    iac_type: str


@dataclass(frozen=True)
class SkippedPolicy:
    """A policy that could not be validated because its value is not known."""

    id: str
    reason: str
    file: str
    iac_type: str


@dataclass
class ExtractionResult:
    documents: list[PolicyDocument] = field(default_factory=list)
    skipped: list[SkippedPolicy] = field(default_factory=list)

    def extend(self, other: "ExtractionResult") -> None:
        self.documents.extend(other.documents)
        self.skipped.extend(other.skipped)


@dataclass
class ExtractOptions:
    only_changed: bool = False
    params: dict[str, str] = field(default_factory=dict)
    region: str = "us-east-1"


# Organizations policy types that Access Analyzer can validate
ORGANIZATION_POLICY_TYPES = {
    "SERVICE_CONTROL_POLICY": "scp",
    "RESOURCE_CONTROL_POLICY": "rcp",
}


def policy_text(value: Any) -> Optional[str]:
    """Return a policy value as JSON text, or None when there is no policy.

    Strings are passed through unchanged (including invalid JSON, which Access
    Analyzer reports as an ERROR). Objects are serialized.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value if value.strip() else None
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return None


def walk_path(
    value: Any,
    unknown: Any,
    parts: list[str],
    indices: tuple[int, ...] = (),
    list_key: Optional[str] = None,
) -> Iterator[tuple[tuple[int, ...], Optional[str], Any, bool]]:
    """Resolve a dotted path with ``[*]`` fan-out in a value and its unknown mask.

    ``unknown`` mirrors ``value`` as in Terraform's ``after_unknown`` (``True`` for an
    unknown value, a dict or list for nested structures). Pass ``None`` when there is
    no mask.

    Yields:
        ``(indices, list_key, leaf, is_unknown)`` for every leaf found
    """
    if unknown is True:
        yield indices, list_key, None, True
        return
    if not parts:
        yield indices, list_key, value, False
        return
    if not isinstance(value, dict):
        return

    part, rest = parts[0], parts[1:]
    fan_out = part.endswith("[*]")
    key = part[:-3] if fan_out else part
    child = value.get(key)
    child_unknown = unknown.get(key) if isinstance(unknown, dict) else None

    if not fan_out:
        if child is None and child_unknown is not True:
            return
        yield from walk_path(child, child_unknown, rest, indices, list_key)
        return

    if child_unknown is True:
        yield indices, key, None, True
        return
    if not isinstance(child, list):
        return
    for index, item in enumerate(child):
        item_unknown = (
            child_unknown[index]
            if isinstance(child_unknown, list) and index < len(child_unknown)
            else None
        )
        yield from walk_path(item, item_unknown, rest, indices + (index,), key)


def document_id(
    base: str, entry: MapEntry, indices: tuple[int, ...], list_key: Optional[str]
) -> str:
    """Build a policy id from a resource address and the map entry."""
    label = entry.label
    if indices:
        label = (label or list_key or "") + "".join(f"[{i}]" for i in indices)
    return f"{base}#{label}" if label else base
