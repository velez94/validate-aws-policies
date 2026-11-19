"""Extract IAM policy documents from infrastructure-as-code inputs.

Supported inputs:

- ``terraform-plan``: ``terraform show -json`` / ``tofu show -json`` (plan or state)
- ``cloudformation``: CloudFormation templates in JSON or YAML, including CDK output
- ``pulumi``: ``pulumi stack export`` and ``pulumi preview --json``

Use :func:`extract` to read inputs. Each extractor returns the policy documents found
and the policies that could not be validated because their value is not known yet.
"""

import json
import logging
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any, Optional, Union

from .base import (
    CLOUDFORMATION,
    PULUMI,
    SOURCES,
    TERRAFORM,
    ExtractionResult,
    ExtractOptions,
    PolicyDocument,
    SkippedPolicy,
    SourceError,
)
from .cloudformation import extract_cloudformation, is_cloudformation, load_template
from .pulumi import extract_pulumi, is_pulumi
from .terraform import extract_terraform, is_terraform

logger = logging.getLogger(__name__)

__all__ = [
    "CLOUDFORMATION",
    "PULUMI",
    "SOURCES",
    "TERRAFORM",
    "ExtractOptions",
    "ExtractionResult",
    "PolicyDocument",
    "SkippedPolicy",
    "SourceError",
    "detect_source",
    "extract",
]

TEMPLATE_SUFFIXES = {".json", ".yaml", ".yml", ".template"}


def detect_source(data: Any) -> str:
    """Identify the IaC format of parsed content.

    Raises:
        SourceError: If the content matches no supported format
    """
    if is_terraform(data):
        return TERRAFORM
    if is_pulumi(data):
        return PULUMI
    if is_cloudformation(data):
        return CLOUDFORMATION
    raise SourceError(
        "Unrecognized input. Expected Terraform plan JSON (terraform show -json), a "
        "CloudFormation template, or Pulumi JSON (stack export or preview --json)."
    )


def _matches(kind: str, data: Any) -> bool:
    if kind == TERRAFORM:
        return is_terraform(data)
    if kind == CLOUDFORMATION:
        return is_cloudformation(data)
    return is_pulumi(data)


def _expand(
    inputs: Sequence[Union[str, Path]], recursive: bool
) -> list[tuple[Path, bool]]:
    """Expand inputs into ``(file, found_in_directory)`` pairs."""
    files: list[tuple[Path, bool]] = []
    for item in inputs:
        path = Path(item)
        if path.is_dir():
            pattern = path.rglob("*") if recursive else path.glob("*")
            found = sorted(
                p
                for p in pattern
                if p.is_file()
                and p.suffix.lower() in TEMPLATE_SUFFIXES
                and not any(part.startswith(".") for part in p.relative_to(path).parts[:-1])
            )
            if not found:
                raise SourceError(f"No template files found in directory {path}")
            files.extend((f, True) for f in found)
        elif path.is_file():
            files.append((path, False))
        else:
            raise FileNotFoundError(f"Input not found: {path}")
    return files


def _parse(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise SourceError(f"{path} is not a UTF-8 text file: {error}") from None
    try:
        return load_template(text)
    except Exception as error:  # yaml.YAMLError, ValueError
        raise SourceError(f"{path} is not valid JSON or YAML: {error}") from None


def extract(
    inputs: Sequence[Union[str, Path]],
    source: Optional[str] = None,
    options: Optional[ExtractOptions] = None,
    recursive: bool = False,
) -> ExtractionResult:
    """Read IaC inputs and return their policy documents.

    Args:
        inputs: Files, or directories of CloudFormation templates
        source: ``terraform-plan``, ``cloudformation``, ``pulumi`` or None/``auto`` to detect
        options: Extraction options (only-changed, CloudFormation parameters, region)
        recursive: Search sub-directories of directory inputs

    Returns:
        Documents and skipped policies of all inputs. With more than one input file,
        policy ids are prefixed with the file name so they stay unique.

    Raises:
        FileNotFoundError: If an input does not exist
        SourceError: If an input is not valid or not in a supported format
    """
    options = options or ExtractOptions()
    if source in (None, "", "auto"):
        source = None
    elif source not in SOURCES:
        raise SourceError(f"Unsupported source '{source}'. Supported: auto, {', '.join(SOURCES)}")

    files = _expand(inputs, recursive)
    if not files:
        raise SourceError("No input given")

    parts: list[tuple[Path, ExtractionResult]] = []
    for path, from_directory in files:
        try:
            data: dict[str, Any] = _parse(path)
            kind = source or detect_source(data)
            if from_directory and not _matches(kind, data):
                raise SourceError(f"{path} is not a {kind} input")
        except SourceError as error:
            if from_directory:
                # Directories such as cdk.out also hold manifests and asset files
                logger.debug(f"Ignoring {path}: {error}")
                continue
            raise
        logger.info(f"Reading {kind} input {path}")

        if kind == TERRAFORM:
            if not is_terraform(data):
                raise SourceError(f"{path} is not Terraform plan JSON (terraform show -json)")
            part = extract_terraform(data, str(path), options)
        elif kind == CLOUDFORMATION:
            if not is_cloudformation(data):
                raise SourceError(f"{path} is not a CloudFormation template")
            part = extract_cloudformation(data, str(path), options)
        else:
            if not is_pulumi(data):
                raise SourceError(f"{path} is not Pulumi stack export or preview JSON")
            part = extract_pulumi(data, str(path), options)

        parts.append((path, part))

    if not parts:
        raise SourceError(
            "No supported input found in "
            + ", ".join(str(i) for i in inputs)
            + " (expected Terraform plan JSON, CloudFormation templates or Pulumi JSON)"
        )

    # With more than one input file, prefix ids with the file name so they stay unique
    combined = ExtractionResult()
    for path, part in parts:
        if len(parts) > 1:
            name = path.name
            part = ExtractionResult(
                [replace(d, id=f"{name}:{d.id}") for d in part.documents],
                [replace(s, id=f"{name}:{s.id}") for s in part.skipped],
            )
        combined.extend(part)

    for skipped in combined.skipped:
        logger.warning(f"Skipping {skipped.id}: {skipped.reason}")
    return combined
