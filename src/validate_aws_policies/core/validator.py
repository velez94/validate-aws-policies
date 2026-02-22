"""Core validation orchestrator for AWS policy validation workflow."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from ..cli.exit_codes import (
    EXIT_FILE_ERROR,
    EXIT_SUCCESS,
    EXIT_VALIDATION_ERROR,
)
from ..iam_access_analyzer.iam_access_analyzer import validate_policies
from ..ops.ops import upload_file
from ..ops.reports import ReportGenerator

logger = logging.getLogger(__name__)


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
                - upload_report: Whether to upload reports to S3
                - bucket_name: S3 bucket name for uploads
                - zip: Whether to create ZIP archives
        """
        self.config = config
        self.report_generator = ReportGenerator()

    def run(self) -> int:
        """
        Execute validation workflow and return exit code.

        Workflow:
        1. Get policy files from directory
        2. Validate policies using IAM Access Analyzer
        3. Output results in requested format (json/text)
        4. Generate reports (HTML/Markdown/ZIP) unless dry-run
        5. Upload reports to S3 if requested
        6. Return appropriate exit code

        Returns:
            Exit code indicating success or failure type:
            - EXIT_SUCCESS (0): Successful execution
            - EXIT_VALIDATION_ERROR (1): Policy validation failed
            - EXIT_AWS_ERROR (3): AWS API error
            - EXIT_FILE_ERROR (4): File operation error
        """
        try:
            # Get policy files
            policies_path = Path(self.config["policies_path"])
            if not policies_path.exists():
                logger.error(f"Policies directory not found: {policies_path}")
                return EXIT_FILE_ERROR

            if not policies_path.is_dir():
                logger.error(f"Policies path is not a directory: {policies_path}")
                return EXIT_FILE_ERROR

            policy_files = self._get_policy_files(policies_path)
            if not policy_files:
                logger.warning(f"No policy files found in {policies_path}")
                return EXIT_SUCCESS

            # Validate policies
            logger.info(f"Validating {len(policy_files)} policies...")
            results = validate_policies(policy_files, policies_path)

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

            return EXIT_SUCCESS

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

    def _get_policy_files(self, path: Path) -> List[str]:
        """
        Get list of JSON policy files from directory.

        Args:
            path: Directory path to search for policy files

        Returns:
            List of policy filenames (not full paths)
        """
        policy_files = [f.name for f in path.glob("*.json")]
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

        # Generate all formats if 'all' is specified
        if format_type == "all":
            html_file = self.report_generator.create_html_report(results)
            report_files.append(html_file)
            md_file = self.report_generator.create_markdown_report(results)
            report_files.append(md_file)
            xml_file = self.report_generator.create_junit_xml_report(results)
            report_files.append(xml_file)
        # Generate HTML report if format is html
        elif format_type == "html":
            html_file = self.report_generator.create_html_report(results)
            report_files.append(html_file)
        # Generate Markdown report if format is md or markdown
        elif format_type in ["md", "markdown"]:
            md_file = self.report_generator.create_markdown_report(results)
            report_files.append(md_file)
        # Generate JUnit XML report if format is xml or junit
        elif format_type in ["xml", "junit"]:
            xml_file = self.report_generator.create_junit_xml_report(results)
            report_files.append(xml_file)

        # Create ZIP archive if requested
        if self.config.get("zip") and report_files:
            zip_file = self.report_generator.create_zip(report_files)
            report_files = [zip_file]

        return report_files

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

        for file_path in files:
            key = f"AccessAnalyzer/{date}/{file_path.name}"
            logger.info(f"Uploading {file_path.name} to s3://{bucket}/{key}")
            upload_file(file_path, bucket, key)
