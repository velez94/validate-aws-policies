"""SARIF 2.1.0 output for code scanning tools (for example GitHub code scanning)."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

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


def build_sarif(results: List[Dict[str, Any]], base_dir: Optional[str] = None) -> Dict[str, Any]:
    """Convert validation results into a SARIF log.

    Access Analyzer positions use 1-based lines and 0-based columns; SARIF uses
    1-based lines and columns, so columns are shifted by one.
    """
    rules: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []
    artifacts: List[Dict[str, Any]] = []

    for result in results:
        uri = artifact_uri(str(result.get("filePolicy", "")), base_dir)
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

            physical: Dict[str, Any] = {"artifactLocation": {"uri": uri}}
            spans = finding_spans(finding)
            if spans:
                start_line, start_col, end_line, end_col = spans[0]
                physical["region"] = {
                    "startLine": max(start_line, 1),
                    "startColumn": start_col + 1,
                    "endLine": max(end_line, 1),
                    "endColumn": end_col + 1,
                }

            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": finding_message(finding)},
                    "locations": [{"physicalLocation": physical}],
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
