"""Validation of the merged configuration (config file + environment + CLI).

``cli.args.validate_args`` can only check what was typed on the command line.
Values that come from a config file are checked here, after merging.
"""

from pathlib import Path
from typing import Any

from ..iam_access_analyzer.constants import (
    CHECKABLE_POLICY_TYPES,
    FAIL_ON_LEVELS,
    LOCALES,
    POLICY_TYPES,
    RESOURCE_TYPES,
)

INPUT_SOURCES = ("auto", "terraform-plan", "cloudformation", "pulumi")


def apply_checks_section(config: dict[str, Any]) -> None:
    """Flatten the optional ``checks`` mapping of a config file.

    Example::

        checks:
          no_new_access: {reference_path: ./baseline, strict: true}
          access_not_granted: {actions: ["iam:*"], resources: []}
          no_public_access: {resource_type: s3-bucket}

    Flat keys that are already set (``check_no_new_access`` and so on) win.
    """
    section = config.get("checks")
    if not isinstance(section, dict):
        return

    no_new = section.get("no_new_access")
    if isinstance(no_new, dict) and no_new.get("enabled", True):
        config.setdefault("check_no_new_access", True)
        if no_new.get("reference_path"):
            config.setdefault("reference_path", no_new["reference_path"])
        if no_new.get("strict"):
            config.setdefault("strict_references", True)
    elif no_new is True:
        config.setdefault("check_no_new_access", True)

    not_granted = section.get("access_not_granted")
    if isinstance(not_granted, dict) and not_granted.get("enabled", True):
        config.setdefault("check_access_not_granted", True)
        if not_granted.get("actions"):
            config.setdefault("deny_actions", not_granted["actions"])
        if not_granted.get("resources"):
            config.setdefault("deny_resources", not_granted["resources"])

    public = section.get("no_public_access")
    if isinstance(public, dict) and public.get("resource_type"):
        config.setdefault("check_no_public_access", public["resource_type"])
    elif isinstance(public, str) and public:
        config.setdefault("check_no_public_access", public)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [str(item) for item in value]


def _resource_type_known(value: str) -> bool:
    return value.lower() in RESOURCE_TYPES or value in RESOURCE_TYPES.values()


def validate_merged_config(config: dict[str, Any]) -> list[str]:
    """Return a list of configuration errors (empty when the config is usable)."""
    errors: list[str] = []

    policy_type = str(config.get("policy_type") or "identity").lower()
    if policy_type not in POLICY_TYPES:
        errors.append(
            f"Unsupported policy_type '{policy_type}'. Supported: {', '.join(POLICY_TYPES)}"
        )

    locale = config.get("locale")
    if locale and str(locale).upper() not in LOCALES:
        errors.append(f"Unsupported locale '{locale}'. Supported: {', '.join(LOCALES)}")

    fail_on = config.get("fail_on")
    if fail_on is not None and fail_on not in FAIL_ON_LEVELS:
        errors.append(f"Unsupported fail_on '{fail_on}'. Supported: {', '.join(FAIL_ON_LEVELS)}")

    if config.get("verbose") and config.get("quiet"):
        errors.append("verbose and quiet cannot both be enabled")

    max_findings = config.get("max_findings")
    if max_findings is not None and (not isinstance(max_findings, int) or max_findings < 1):
        errors.append("max_findings must be a positive integer")

    # Infrastructure as code inputs
    input_paths = config.get("input")
    if input_paths:
        if config.get("policy_sets"):
            errors.append("input cannot be combined with policy_sets")
        source = config.get("source")
        if source is not None and source not in INPUT_SOURCES:
            errors.append(
                f"Unsupported source '{source}'. Supported: auto, terraform-plan, "
                "cloudformation, pulumi"
            )
    unknown_values = config.get("unknown_values")
    if unknown_values is not None and unknown_values not in ("skip", "fail"):
        errors.append(f"Unsupported unknown_values '{unknown_values}'. Supported: skip, fail")

    # Policy sets and resource types
    sets = config.get("policy_sets")
    types_in_use = [policy_type]
    if sets:
        if not isinstance(sets, list) or not all(isinstance(item, dict) for item in sets):
            errors.append("policy_sets must be a list of mappings with a 'path' key")
            sets = []
        types_in_use = []
        for index, entry in enumerate(sets, 1):
            label = f"policy_sets[{index}]"
            if not entry.get("path"):
                errors.append(f"{label}: 'path' is required")
            elif not Path(str(entry["path"])).is_dir():
                errors.append(f"{label}: path is not a directory: {entry['path']}")
            set_type = str(entry.get("policy_type") or policy_type).lower()
            if set_type not in POLICY_TYPES:
                errors.append(f"{label}: unsupported policy_type '{set_type}'")
            types_in_use.append(set_type)
            set_resource = entry.get("resource_type")
            if set_resource:
                if set_type != "resource":
                    errors.append(f"{label}: resource_type requires policy_type 'resource'")
                elif not _resource_type_known(str(set_resource)):
                    errors.append(f"{label}: unsupported resource_type '{set_resource}'")

    resource_type = config.get("resource_type")
    if resource_type and not input_paths:
        if not _resource_type_known(str(resource_type)):
            errors.append(
                f"Unsupported resource_type '{resource_type}'. "
                f"Supported: {', '.join(RESOURCE_TYPES)}"
            )
        if "resource" not in types_in_use:
            errors.append("resource_type requires policy_type 'resource'")

    # Custom policy checks
    new_access = bool(config.get("check_no_new_access"))
    not_granted = bool(config.get("check_access_not_granted"))
    public_access = config.get("check_no_public_access")

    if new_access and input_paths:
        if not config.get("reference_input"):
            errors.append("check_no_new_access requires reference_input (--reference-input)")
    elif new_access:
        reference = config.get("reference_path")
        if not reference:
            errors.append("check_no_new_access requires reference_path (--reference-path)")
        elif not Path(str(reference)).is_dir():
            errors.append(f"reference_path is not a directory: {reference}")

    if not_granted and not (_as_list(config.get("deny_actions")) or _as_list(
        config.get("deny_resources")
    )):
        errors.append("check_access_not_granted requires deny_actions and/or deny_resources")

    if (
        (new_access or not_granted or public_access)
        and not input_paths
        and not any(kind in CHECKABLE_POLICY_TYPES for kind in types_in_use)
    ):
        errors.append(
            "Custom policy checks support identity and resource policies only "
            f"(got: {', '.join(sorted(set(types_in_use)))})"
        )
    if public_access and not input_paths and "resource" not in types_in_use:
        errors.append("check_no_public_access requires policy_type 'resource'")

    return errors
