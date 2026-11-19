"""Core validation orchestrator for AWS policy validation workflow."""

import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import BotoCoreError, ClientError

from ..cli.exit_codes import (
    EXIT_AWS_ERROR,
    EXIT_CONFIG_ERROR,
    EXIT_FILE_ERROR,
    EXIT_SUCCESS,
    EXIT_VALIDATION_ERROR,
)
from ..iam_access_analyzer.checks import checks_requested, run_policy_checks
from ..iam_access_analyzer.features import SdkFeatureError
from ..iam_access_analyzer.iam_access_analyzer import validate_policies, validate_policy_documents
from ..ops.findings import exceeds_threshold, finding_link, finding_spans
from ..ops.ops import upload_file
from ..ops.reports import ReportGenerator
from ..sources import ExtractOptions, PolicyDocument, SkippedPolicy, SourceError, extract
from ..version import __version__

logger = logging.getLogger(__name__)


class UploadError(Exception):
    """Raised when a report could not be uploaded to S3 (exit code 3)."""


class PolicyValidator:
    """Orchestrate policy validation workflow."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize PolicyValidator with configuration.

        Args:
            config: Configuration dictionary containing:
                - policies_path: Path to directory containing policy files
                - format: Output format (json, text, html, md/markdown, xml/junit)
                - output: Optional output file path
                - dry_run: Whether to skip report generation and uploads
                - policy_type: identity (default), resource, scp or rcp
                - resource_type, locale, max_findings, recursive, policy_sets
                - continue_on_error, fail_on: failure handling (see --fail-on)
                - check_no_new_access, reference_path, strict_references,
                  check_access_not_granted, deny_actions, deny_resources,
                  check_no_public_access: custom policy checks
                - upload: Whether to upload reports to S3 (legacy key: upload_report)
                - bucket_name: S3 bucket name for uploads
                - zip: Whether to create ZIP archives
        """
        self.config = config
        self.report_generator = ReportGenerator()
        self._base_dir: Optional[str] = None
        self._targets_info: List[Dict[str, Any]] = []
        self._skipped: List[SkippedPolicy] = []
        self._iac_inputs: List[Dict[str, Any]] = []

    def run(self) -> int:
        """
        Execute validation workflow and return exit code.

        Workflow:
        1. Resolve the policy sets to validate (one directory, or ``policy_sets``)
        2. Get policy files from each directory (optionally recursive)
        3. Validate policies using IAM Access Analyzer
        4. Run custom policy checks if enabled
        5. Output results in requested format (json/text)
        6. Generate reports (HTML/Markdown/JUnit/SARIF/ZIP) unless dry-run
        7. Upload reports to S3 if requested
        8. Return appropriate exit code

        Returns:
            Exit code indicating success or failure type:
            - EXIT_SUCCESS (0): Successful execution
            - EXIT_VALIDATION_ERROR (1): Policy validation or a custom check failed
            - EXIT_CONFIG_ERROR (2): The installed boto3 lacks a requested capability
            - EXIT_AWS_ERROR (3): AWS API error
            - EXIT_FILE_ERROR (4): File operation error
        """
        try:
            if self.config.get("input"):
                return self._run_iac()

            targets = self._targets()
            results: List[Dict[str, Any]] = []

            for target in targets:
                policies_path = Path(target["path"])
                if not policies_path.exists():
                    logger.error(f"Policies directory not found: {policies_path}")
                    return EXIT_FILE_ERROR

                if not policies_path.is_dir():
                    logger.error(f"Policies path is not a directory: {policies_path}")
                    return EXIT_FILE_ERROR

                policy_files = self._get_policy_files(
                    policies_path, recursive=bool(self.config.get("recursive"))
                )
                if not policy_files:
                    logger.warning(f"No policy files found in {policies_path}")
                    continue

                # Validate policies
                logger.info(f"Validating {len(policy_files)} policies in {policies_path}...")
                set_results = validate_policies(
                    policy_files,
                    policies_path,
                    policy_type=target["policy_type"],
                    resource_type=target.get("resource_type"),
                    locale=self.config.get("locale") or "EN",
                    max_findings=self.config.get("max_findings"),
                    fail_fast=not self._continue_on_error(),
                )

                if checks_requested(self.config):
                    run_policy_checks(
                        set_results,
                        policies_path,
                        target["policy_type"],
                        self.config,
                        resource_type=target.get("resource_type"),
                    )

                if len(targets) > 1:
                    for result in set_results:
                        result["filePolicy"] = f"{target['path']}/{result['filePolicy']}"
                results.extend(set_results)

            if not results:
                return EXIT_SUCCESS

            self._base_dir = str(targets[0]["path"]) if len(targets) == 1 else None
            self._targets_info = targets
            return self._finish(results)

        except (SdkFeatureError, SourceError) as e:
            logger.error(str(e))
            return EXIT_CONFIG_ERROR
        except (ClientError, BotoCoreError, UploadError) as e:
            logger.error(f"AWS API error: {e}")
            return EXIT_AWS_ERROR
        except FileNotFoundError as e:
            logger.error(f"File error: {e}")
            return EXIT_FILE_ERROR
        except ValueError as e:
            # ValueError is raised by validate_findings when ERROR-level finding is detected
            logger.error(f"Validation error: {e}")
            return EXIT_VALIDATION_ERROR
        except Exception as e:
            # Catch any other unexpected errors
            logger.exception(f"Unexpected error during validation: {e}")
            return EXIT_VALIDATION_ERROR

    def _finish(self, results: List[Dict[str, Any]]) -> int:
        """Write the output and reports, upload them, and decide the exit code."""
        # Output results
        self._output_results(results)

        # Generate reports (unless dry-run)
        if not self.config.get("dry_run", False):
            report_files = self._generate_reports(results)

            # Upload reports if requested
            if self.config.get("upload_report", False) or self.config.get("upload", False):
                self._upload_reports(report_files)
        else:
            logger.info("Dry-run mode: Skipping report generation and uploads")

        # Custom check failures (and, with --continue-on-error/--fail-on, validation
        # findings) decide the exit code only after everything has been written.
        failed = False
        if exceeds_threshold(results, self.config.get("fail_on") or "error"):
            logger.error("Findings at or above the failure threshold were found")
            failed = True
        if self._unknown_values_fail():
            failed = True
        return EXIT_VALIDATION_ERROR if failed else EXIT_SUCCESS

    def _unknown_values_fail(self) -> bool:
        """True when --unknown-values fail is set and some policies were skipped."""
        if self.config.get("unknown_values") == "fail" and self._skipped:
            logger.error(
                f"{len(self._skipped)} policies could not be validated because their value "
                "is not known before deployment (--unknown-values fail)"
            )
            return True
        return False

    @staticmethod
    def _region() -> str:
        return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"

    def _run_iac(self) -> int:
        """Validate the policies found in Terraform, CloudFormation or Pulumi inputs."""
        options = ExtractOptions(
            only_changed=bool(self.config.get("only_changed")),
            params=dict(self.config.get("params") or {}),
            region=self._region(),
        )
        source = self.config.get("source")
        recursive = bool(self.config.get("recursive"))

        extraction = extract(self.config["input"], source, options, recursive=recursive)
        self._skipped = extraction.skipped

        references: Optional[Dict[str, str]] = None
        if self.config.get("reference_input"):
            baseline = extract(self.config["reference_input"], source, options, recursive=recursive)
            references = {doc.id: doc.text for doc in baseline.documents}

        counts: Dict[str, int] = {}
        kinds: Dict[str, str] = {}
        for doc in extraction.documents:
            counts[doc.file] = counts.get(doc.file, 0) + 1
            kinds[doc.file] = doc.source_type
        self._iac_inputs = [
            {"file": file, "type": kinds[file], "policies": count} for file, count in counts.items()
        ]

        if not extraction.documents:
            logger.warning("No policies found in the input")
            return EXIT_VALIDATION_ERROR if self._unknown_values_fail() else EXIT_SUCCESS

        groups: Dict[Tuple[str, Optional[str]], List[PolicyDocument]] = {}
        for doc in extraction.documents:
            groups.setdefault((doc.policy_type, doc.resource_type), []).append(doc)

        results: List[Dict[str, Any]] = []
        for (policy_type, resource_type), docs in groups.items():
            kind = f"{policy_type}/{resource_type}" if resource_type else policy_type
            logger.info(f"Validating {len(docs)} {kind} policies...")
            group_results = validate_policy_documents(
                [(doc.id, doc.text) for doc in docs],
                policy_type=policy_type,
                resource_type=resource_type,
                locale=self.config.get("locale") or "EN",
                max_findings=self.config.get("max_findings"),
                fail_fast=not self._continue_on_error(),
            )
            by_id = {doc.id: doc for doc in docs}
            for entry in group_results:
                doc = by_id[entry["filePolicy"]]
                entry["source"] = {
                    "type": doc.source_type,
                    "file": doc.file,
                    "resourceType": doc.iac_type,
                }

            if checks_requested(self.config):
                run_policy_checks(
                    group_results,
                    None,
                    policy_type,
                    self.config,
                    resource_type=resource_type,
                    documents={doc.id: doc.text for doc in docs},
                    reference_documents=references,
                    strict_resource_type=True,
                )
            results.extend(group_results)

        self._base_dir = None
        self._targets_info = []
        return self._finish(results)

    def _continue_on_error(self) -> bool:
        """True when ERROR findings must not abort the run (opt-in, legacy default is abort)."""
        return bool(self.config.get("continue_on_error")) or self.config.get("fail_on") is not None

    def _targets(self) -> List[Dict[str, Any]]:
        """Return the policy sets to validate.

        Uses ``policy_sets`` from the configuration when present, otherwise a single
        set built from ``policies_path``, ``policy_type`` and ``resource_type``.
        """
        default_type = self.config.get("policy_type") or "identity"
        sets = self.config.get("policy_sets")
        if not sets:
            return [
                {
                    "path": self.config["policies_path"],
                    "policy_type": default_type,
                    "resource_type": self.config.get("resource_type"),
                }
            ]

        targets = []
        for entry in sets:
            policy_type = entry.get("policy_type") or default_type
            resource_type = entry.get("resource_type")
            if resource_type is None and str(policy_type).lower() == "resource":
                resource_type = self.config.get("resource_type")
            targets.append(
                {"path": entry["path"], "policy_type": policy_type, "resource_type": resource_type}
            )
        return targets

    def _get_policy_files(self, path: Path, recursive: bool = False) -> List[str]:
        """
        Get list of JSON policy files from directory.

        Args:
            path: Directory path to search for policy files
            recursive: Also search sub-directories (hidden directories are skipped)

        Returns:
            Sorted list of policy file names relative to ``path`` (POSIX separators)
        """
        if recursive:
            candidates = [
                f
                for f in path.rglob("*.json")
                if f.is_file()
                and not any(part.startswith(".") for part in f.relative_to(path).parts[:-1])
            ]
        else:
            candidates = [f for f in path.glob("*.json") if f.is_file()]
        policy_files = sorted(f.relative_to(path).as_posix() for f in candidates)
        logger.debug(f"Found {len(policy_files)} policy files: {policy_files}")
        return policy_files

    def _output_results(self, results: List[Dict[str, Any]]) -> None:
        """
        Output validation results based on configured format.

        Supports json and text formats. For json/text, output goes to
        stdout by default or to a file if output path is specified.

        Args:
            results: List of validation results to output
        """
        format_type = self.config.get("format", "json")
        output_path = self.config.get("output")

        if format_type == "json":
            output = json.dumps(results, indent=2)
            if output_path:
                output_file = Path(output_path)
                output_file.write_text(output, encoding="utf-8")
                logger.info(f"JSON results written to {output_path}")
            else:
                print(output)
        elif format_type == "text":
            output = self._format_text_output(results)
            if output_path:
                output_file = Path(output_path)
                output_file.write_text(output, encoding="utf-8")
                logger.info(f"Text results written to {output_path}")
            else:
                print(output)
        # For html/md formats, output is handled by _generate_reports

    def _format_text_output(self, results: List[Dict[str, Any]]) -> str:
        """
        Format validation results as human-readable text.

        Args:
            results: List of validation results

        Returns:
            Formatted text string with policy findings
        """
        lines = ["Policy Validation Results", "=" * 50, ""]

        for result in results:
            policy_name = result.get("filePolicy", "Unknown")
            lines.append(f"Policy: {policy_name}")

            summary = result.get("summary", [])
            if not summary:
                lines.append("  No findings")
            else:
                for finding in summary:
                    finding_type = finding.get("findingType", "Unknown")
                    issue_code = finding.get("issueCode", "N/A")
                    lines.append(f"  - {finding_type}: {issue_code}")
                    if finding_type == "None":
                        continue
                    details = finding.get("details")
                    if isinstance(details, dict) and details.get("findingDetails"):
                        lines.append(f"      {details['findingDetails']}")
                    for start_line, start_col, _end_line, _end_col in finding_spans(finding):
                        lines.append(f"      at line {start_line}, column {start_col + 1}")
                    link = finding_link(finding)
                    if link:
                        lines.append(f"      {link}")

            lines.append("")

        if self._skipped:
            lines.append("Skipped (value not known before deployment):")
            lines.extend(f"  - {item.id}: {item.reason}" for item in self._skipped)
            lines.append("")

        return "\n".join(lines)

    def _generate_reports(self, results: List[Dict[str, Any]]) -> List[Path]:
        """
        Generate report files based on configuration.

        Supports HTML, Markdown, XML/JUnit, and ZIP formats. Respects dry-run mode.

        Args:
            results: List of validation results

        Returns:
            List of generated report file paths
        """
        report_files: List[Path] = []
        format_type = self.config.get("format", "json")
        metadata = self._report_metadata()

        # Generate all formats if 'all' is specified
        if format_type == "all":
            html_file = self.report_generator.create_html_report(results, metadata=metadata)
            report_files.append(html_file)
            md_file = self.report_generator.create_markdown_report(results)
            report_files.append(md_file)
            xml_file = self.report_generator.create_junit_xml_report(results)
            report_files.append(xml_file)
        # Generate HTML report if format is html
        elif format_type == "html":
            html_file = self.report_generator.create_html_report(results, metadata=metadata)
            report_files.append(html_file)
        # Generate Markdown report if format is md or markdown
        elif format_type in ["md", "markdown"]:
            md_file = self.report_generator.create_markdown_report(results)
            report_files.append(md_file)
        # Generate JUnit XML report if format is xml or junit
        elif format_type in ["xml", "junit"]:
            xml_file = self.report_generator.create_junit_xml_report(results)
            report_files.append(xml_file)
        # Generate SARIF report for code scanning tools
        elif format_type == "sarif":
            sarif_file = self.report_generator.create_sarif_report(results, base_dir=self._base_dir)
            report_files.append(sarif_file)

        # Honor --output for single-file report formats
        output_path = self.config.get("output")
        if output_path and len(report_files) == 1 and format_type != "all":
            destination = Path(output_path)
            if destination.parent != Path("."):
                destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(report_files[0]), str(destination))
            logger.info(f"Report written to {destination}")
            report_files = [destination]

        # Create ZIP archive if requested
        if self.config.get("zip") and report_files:
            zip_file = self.report_generator.create_zip(report_files)
            report_files = [zip_file]

        return report_files

    def _report_metadata(self) -> Dict[str, Any]:
        """Describe the run for report headers (policy sets, checks, tool version)."""
        checks = []
        if self.config.get("check_no_new_access"):
            checks.append("CheckNoNewAccess")
        if self.config.get("check_access_not_granted"):
            checks.append("CheckAccessNotGranted")
        if self.config.get("check_no_public_access"):
            checks.append("CheckNoPublicAccess")
        return {
            "inputs": self._iac_inputs,
            "skipped": [{"id": item.id, "reason": item.reason} for item in self._skipped],
            "tool_version": __version__,
            "policy_sets": [
                {"path": str(t["path"]), "policy_type": str(t["policy_type"])}
                for t in self._targets_info
            ],
            "locale": self.config.get("locale") or "EN",
            "checks": checks,
        }

    def _upload_reports(self, files: List[Path]) -> None:
        """
        Upload report files to S3.

        Uses the configured bucket name and creates a date-based key structure.

        Args:
            files: List of file paths to upload

        Raises:
            ValueError: If bucket_name is not configured
        """
        from datetime import datetime

        bucket = self.config.get("bucket_name") or self.config.get("bucket")
        if not bucket:
            logger.error("Cannot upload reports: bucket_name not configured")
            raise ValueError("bucket_name is required for uploads")

        date = datetime.today().strftime("%Y/%m/%d")

        failed = []
        for file_path in files:
            key = f"AccessAnalyzer/{date}/{file_path.name}"
            logger.info(f"Uploading {file_path.name} to s3://{bucket}/{key}")
            if not upload_file(file_path, bucket, key):
                failed.append(file_path.name)

        if failed:
            raise UploadError(f"Failed to upload to s3://{bucket}: {', '.join(failed)}")
