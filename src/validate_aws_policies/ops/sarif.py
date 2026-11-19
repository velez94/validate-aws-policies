"""SARIF 2.1.0 output for code scanning tools (for example GitHub code scanning)."""

import os
from pathlib import Path
from typing import Any, Optional

from ..version import __version__
from .findings import finding_link, finding_message, finding_spans, real_findings

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/velez94/validate-aws-policies"

LEVELS = {
    "ERROR": "error",
    "SECURITY_WARNING": "warning",
    "WARNING": "warning",
    "SUGGESTION": "note",
}


def artifact_uri(file_policy: str, base_dir: Optional[str]) -> str:
    """Build a forward-slash URI for a policy file, relative to the working directory.

    Args:
        file_policy: File name from the report (relative to ``base_dir`` if given)
        base_dir: Directory the policies were read from, or None if ``file_policy``
            already includes it
    """
    path = Path(base_dir) / file_policy if base_dir else Path(file_policy)
    if path.is_absolute():
        try:
            path = Path(os.path.relpath(path, Path.cwd()))
        except ValueError:  # different drive on Windows
            pass
    return path.as_posix()


def build_sarif(results: list[dict[str, Any]], base_dir: Optional[str] = None) -> dict[str, Any]:
    """Convert validation results into a SARIF log.

    Access Analyzer positions use 1-based lines and 0-based columns; SARIF uses
    1-based lines and columns, so columns are shifted by one.
    """
    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []

    seen_artifacts = set()

    for result in results:
        source = result.get("source")
        if source:
            # IaC policy: the artifact is the plan/template, the policy is a logical location
            uri = artifact_uri(str(source.get("file", "")), None)
        else:
            uri = artifact_uri(str(result.get("filePolicy", "")), base_dir)
        if uri not in seen_artifacts:
            seen_artifacts.add(uri)
            artifacts.append({"location": {"uri": uri}})

        for finding in real_findings(result):
            kind = str(finding.get("findingType", "WARNING"))
            rule_id = str(finding.get("issueCode") or "UNKNOWN")
            level = LEVELS.get(kind, "warning")

            rule = rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "shortDescription": {"text": rule_id},
                    "defaultConfiguration": {"level": level},
                },
            )
            link = finding_link(finding)
            if link and "helpUri" not in rule:
                rule["helpUri"] = link

            physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
            # Spans point into the embedded policy JSON, not into the IaC file
            spans = [] if source else finding_spans(finding)
            if spans:
                start_line, start_col, end_line, end_col = spans[0]
                physical["region"] = {
                    "startLine": max(start_line, 1),
                    "startColumn": start_col + 1,
                    "endLine": max(end_line, 1),
                    "endColumn": end_col + 1,
                }

            location: dict[str, Any] = {"physicalLocation": physical}
            message = finding_message(finding)
            if source:
                resource_id = str(result.get("filePolicy", ""))
                location["logicalLocations"] = [
                    {"name": resource_id, "kind": "resource", "fullyQualifiedName": resource_id}
                ]
                message = f"{resource_id}: {message}"

            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": message},
                    "locations": [location],
                    "properties": {"findingType": kind},
                }
            )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "validate-aws-policies",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "artifacts": artifacts,
                "results": sarif_results,
            }
        ],
    }
