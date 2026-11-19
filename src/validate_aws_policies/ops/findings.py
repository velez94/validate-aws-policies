"""Helpers for reading findings in the report summary format.

A report entry looks like::

    {"filePolicy": "a.json",
     "summary": [{"policyName": "a", "issueCode": "X", "findingType": "WARNING",
                  "details": {...raw Access Analyzer finding...}}],
     "checks": [...]}          # only when custom policy checks ran
"""

from typing import Any, Optional

from ..iam_access_analyzer.constants import FAIL_ON_LEVELS, SEVERITY_ORDER

NO_FINDING = "None"


def finding_message(finding: dict[str, Any]) -> str:
    """Return the human readable message of a summary entry."""
    details = finding.get("details")
    if isinstance(details, dict):
        message = details.get("findingDetails") or details.get("message")
        if message:
            return str(message)
    elif isinstance(details, str) and details:
        return details
    legacy = finding.get("findingDetails")
    return str(legacy) if legacy else "No details available"


def finding_link(finding: dict[str, Any]) -> Optional[str]:
    """Return the learn-more link of a summary entry, if any."""
    details = finding.get("details")
    if isinstance(details, dict):
        link = details.get("learnMoreLink")
        return str(link) if link else None
    return None


def finding_spans(finding: dict[str, Any]) -> list[tuple[int, int, int, int]]:
    """Return ``(start_line, start_col, end_line, end_col)`` for each location.

    Access Analyzer lines start at 1 and columns start at 0.
    """
    details = finding.get("details")
    spans: list[tuple[int, int, int, int]] = []
    if not isinstance(details, dict):
        return spans
    for location in details.get("locations") or []:
        span = location.get("span") if isinstance(location, dict) else None
        if not span:
            continue
        try:
            start, end = span["start"], span["end"]
            spans.append((start["line"], start["column"], end["line"], end["column"]))
        except (KeyError, TypeError):
            continue
    return spans


def is_placeholder(finding: dict[str, Any]) -> bool:
    """True for the "No findings" placeholder entry."""
    return finding.get("findingType") == NO_FINDING


def real_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Summary entries of a result without the "No findings" placeholder."""
    return [f for f in result.get("summary", []) if not is_placeholder(f)]


def count_by_type(results: list[dict[str, Any]]) -> dict[str, int]:
    """Count real findings per finding type across all results."""
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for result in results:
        for finding in real_findings(result):
            kind = finding.get("findingType", "")
            if kind in counts:
                counts[kind] += 1
    return counts


def exceeds_threshold(results: list[dict[str, Any]], fail_on: str) -> bool:
    """True when any finding is at or above the ``--fail-on`` level.

    Args:
        results: Validation results
        fail_on: One of the keys of ``FAIL_ON_LEVELS`` (``none`` never fails)
    """
    level = FAIL_ON_LEVELS.get(fail_on, "ERROR")
    if not level:
        return False
    accepted = SEVERITY_ORDER[: SEVERITY_ORDER.index(level) + 1]
    return any(
        finding.get("findingType") in accepted
        for result in results
        for finding in real_findings(result)
    )
