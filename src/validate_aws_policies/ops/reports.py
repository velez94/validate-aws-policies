"""Report generation module for AWS policy validation results."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from zipfile import ZipFile

from .findings import finding_message, real_findings
from .html_report import render_html
from .sarif import build_sarif

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate validation reports in various formats."""

    def create_html_report(
        self, results: list[dict[str, Any]], metadata: Optional[dict[str, Any]] = None
    ) -> Path:
        """
        Create a self-contained HTML report (light/dark theme, filters, search).

        Args:
            results: List of validation results containing policy findings
            metadata: Optional run description shown in the report header
                (``tool_version``, ``policy_sets``, ``locale``, ``checks``)

        Returns:
            Path to the created HTML report file

        Raises:
            IOError: If unable to write the HTML file
        """
        timestamp = datetime.now()
        file_name = Path(f"AccessAnalyzerReport_{timestamp.strftime('%Y%m%d_%H%M%S')}.html")

        logger.info("Creating HTML report...")
        document = render_html(results, generated_at=timestamp, metadata=metadata)

        try:
            with file_name.open("w", encoding="utf-8") as f:
                f.write(document)

            logger.info(f"Created HTML report: {file_name}")
            return file_name

        except OSError as e:
            logger.error(f"Failed to create HTML report: {e}")
            raise

    def create_sarif_report(
        self, results: list[dict[str, Any]], base_dir: Optional[str] = None
    ) -> Path:
        """
        Create a SARIF 2.1.0 report for code scanning tools.

        Args:
            results: List of validation results containing policy findings
            base_dir: Directory the policy files were read from (used for file URIs)

        Returns:
            Path to the created SARIF file

        Raises:
            IOError: If unable to write the file
        """
        timestamp = datetime.now()
        file_name = Path(f"AccessAnalyzerReport_{timestamp.strftime('%Y%m%d_%H%M%S')}.sarif")

        logger.info("Creating SARIF report...")
        try:
            with file_name.open("w", encoding="utf-8") as f:
                json.dump(build_sarif(results, base_dir), f, indent=2)
                f.write("\n")
            logger.info(f"Created SARIF report: {file_name}")
            return file_name
        except OSError as e:
            logger.error(f"Failed to create SARIF report: {e}")
            raise

    def create_markdown_report(self, results: list[dict[str, Any]]) -> Path:
        """
        Create Markdown report from validation results.

        Args:
            results: List of validation results containing policy findings

        Returns:
            Path to the created Markdown report file

        Raises:
            IOError: If unable to write the Markdown file
        """
        timestamp = datetime.now()
        file_name = Path(f"AccessAnalyzerReport_{timestamp.strftime('%Y%m%d_%H%M%S')}.md")

        logger.info("Creating Markdown report...")

        # Calculate summary statistics
        total_policies = len(results)
        total_findings = sum(len(real_findings(r)) for r in results)
        findings_by_type = {"ERROR": 0, "WARNING": 0, "SUGGESTION": 0, "SECURITY_WARNING": 0}

        for result in results:
            for finding in real_findings(result):
                finding_type = finding.get("findingType", "")
                if finding_type in findings_by_type:
                    findings_by_type[finding_type] += 1

        md_content = f"""# AWS Policy Validation Report

**IAM Access Analyzer Policy Validation Results**

Generated: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}

---

## Summary

| Metric | Count |
|--------|-------|
| Total Policies | {total_policies} |
| Total Findings | {total_findings} |
| Errors | {findings_by_type['ERROR']} |
| Warnings | {findings_by_type['WARNING']} |
| Security Warnings | {findings_by_type['SECURITY_WARNING']} |
| Suggestions | {findings_by_type['SUGGESTION']} |

---

## Table of Contents

"""

        # Generate table of contents
        for idx, result in enumerate(results, 1):
            policy_name = result.get("filePolicy", "Unknown Policy")
            anchor = policy_name.replace(" ", "-").replace(".", "").lower()
            md_content += f"{idx}. [{policy_name}](#{anchor})\n"

        md_content += "\n---\n\n## Policy Validation Details\n\n"

        # Add policy details
        for result in results:
            policy_name = result.get("filePolicy", "Unknown Policy")
            summary = real_findings(result)

            md_content += f"### {policy_name}\n\n"

            if not summary:
                md_content += "✅ **No findings** - Policy is valid\n\n"
            else:
                md_content += f"**Findings:** {len(summary)}\n\n"
                md_content += "| Finding Type | Issue Code | Details |\n"
                md_content += "|--------------|------------|----------|\n"

                for finding in summary:
                    finding_type = finding.get("findingType", "UNKNOWN")
                    issue_code = finding.get("issueCode", "N/A")
                    details = finding_message(finding)

                    # Add emoji indicators
                    emoji = {
                        "ERROR": "🔴",
                        "WARNING": "🟡",
                        "SECURITY_WARNING": "🟠",
                        "SUGGESTION": "🟢"
                    }.get(finding_type, "⚪")

                    # Escape pipe characters in details
                    details = details.replace("|", "\\|")

                    md_content += f"| {emoji} {finding_type} | `{issue_code}` | {details} |\n"

                md_content += "\n"

            md_content += "---\n\n"

        md_content += f"""
## Report Information

- **Generated By:** AWS Policy Validator
- **Validation Engine:** IAM Access Analyzer
- **Timestamp:** {timestamp.strftime('%Y-%m-%d %H:%M:%S')}
- **Total Policies Analyzed:** {total_policies}
- **Total Findings:** {total_findings}

---

*This report was automatically generated by the AWS Policy Validation tool.*
"""

        try:
            with file_name.open("w", encoding="utf-8") as f:
                f.write(md_content)

            logger.info(f"Created Markdown report: {file_name}")
            return file_name

        except OSError as e:
            logger.error(f"Failed to create Markdown report: {e}")
            raise

    def create_zip(self, file_paths: list[Path]) -> Path:
        """
        Create ZIP archive of report files.

        Args:
            file_paths: List of file paths to include in the ZIP archive

        Returns:
            Path to the created ZIP archive

        Raises:
            FileNotFoundError: If any of the files to zip don't exist
            IOError: If unable to create the ZIP archive
        """
        timestamp = datetime.now()
        zip_name = Path(f"reports_{timestamp.strftime('%Y%m%d_%H%M%S')}.zip")

        logger.info("Creating ZIP archive...")

        # Validate all files exist before creating zip
        for file_path in file_paths:
            if not file_path.exists():
                logger.error(f"File not found for zipping: {file_path}")
                raise FileNotFoundError(f"File not found: {file_path}")

        try:
            with ZipFile(zip_name, "w") as zipf:
                for file_path in file_paths:
                    zipf.write(file_path)
                    logger.debug(f"Added {file_path} to ZIP archive")

            logger.info(f"Created ZIP archive: {zip_name}")
            return zip_name

        except Exception as e:
            logger.error(f"Failed to create ZIP archive: {e}")
            raise OSError(f"Failed to create ZIP archive: {e}") from e
    def create_junit_xml_report(self, results: list[dict[str, Any]]) -> Path:
        """
        Create JUnit XML report from validation results for CI/CD integration.

        The XML format follows the JUnit schema compatible with Jenkins, GitLab CI,
        GitHub Actions, CircleCI, AWS CodeBuild, and other CI/CD tools.

        Args:
            results: List of validation results containing policy findings

        Returns:
            Path to the created XML report file

        Raises:
            IOError: If unable to write the XML file
        """
        import socket
        import xml.etree.ElementTree as ET

        timestamp = datetime.now()
        file_name = Path(f"AccessAnalyzerReport_{timestamp.strftime('%Y%m%d_%H%M%S')}.xml")

        logger.info("Creating JUnit XML report...")

        # Calculate summary statistics
        total_tests = 0
        total_failures = 0
        total_errors = 0
        total_time = 0.0

        # Create root element
        testsuites = ET.Element("testsuites")
        testsuites.set("name", "AWS Policy Validation")
        testsuites.set("timestamp", timestamp.strftime('%Y-%m-%dT%H:%M:%S'))
        testsuites.set("hostname", socket.gethostname())

        # Process each policy as a test suite
        for result in results:
            policy_name = result.get("filePolicy", "Unknown Policy")
            summary = result.get("summary", [])

            # Count findings by type for this policy
            suite_tests = 0
            suite_failures = 0
            suite_errors = 0
            suite_time = 0.1  # Estimated time per policy

            # Each policy gets at least one test case (the validation itself)
            # If there are findings, each finding becomes a test case
            if not summary:
                suite_tests = 1  # One passing test for valid policy
            else:
                suite_tests = len(summary)
                for finding in summary:
                    finding_type = finding.get("findingType", "")
                    if finding_type == "ERROR":
                        suite_errors += 1
                    elif finding_type in ["WARNING", "SECURITY_WARNING"]:
                        suite_failures += 1
                    # SUGGESTION findings are passing tests (no error/failure)

            # Create testsuite element
            testsuite = ET.SubElement(testsuites, "testsuite")
            testsuite.set("name", policy_name)
            testsuite.set("tests", str(suite_tests))
            testsuite.set("failures", str(suite_failures))
            testsuite.set("errors", str(suite_errors))
            testsuite.set("skipped", "0")  # Required by AWS CodeBuild
            testsuite.set("time", f"{suite_time:.3f}")
            testsuite.set("timestamp", timestamp.strftime('%Y-%m-%dT%H:%M:%S'))

            # Add properties section with metadata
            properties = ET.SubElement(testsuite, "properties")

            prop_validator = ET.SubElement(properties, "property")
            prop_validator.set("name", "validator")
            prop_validator.set("value", "AWS IAM Access Analyzer")

            prop_policy = ET.SubElement(properties, "property")
            prop_policy.set("name", "policy_file")
            prop_policy.set("value", policy_name)

            prop_findings = ET.SubElement(properties, "property")
            prop_findings.set("name", "total_findings")
            prop_findings.set("value", str(len(summary)))

            # Create test cases
            if not summary:
                # Policy is valid - create a passing test case
                testcase = ET.SubElement(testsuite, "testcase")
                testcase.set("classname", policy_name.replace(".json", ""))
                testcase.set("name", "ValidatePolicy")
                testcase.set("time", f"{suite_time:.3f}")
            else:
                # Create a test case for each finding
                for idx, finding in enumerate(summary, 1):
                    finding_type = finding.get("findingType", "UNKNOWN")
                    issue_code = finding.get("issueCode", "N/A")
                    details = finding.get("findingDetails", "No details available")
                    learn_more = finding.get("learnMoreLink", "")

                    testcase = ET.SubElement(testsuite, "testcase")
                    testcase.set("classname", policy_name.replace(".json", ""))
                    testcase.set("name", f"{issue_code}_{idx}")
                    testcase.set("time", f"{suite_time / len(summary):.3f}")

                    # Build detailed message
                    message = f"{finding_type}: {issue_code}"
                    details_text = f"Finding Type: {finding_type}\n"
                    details_text += f"Issue Code: {issue_code}\n"
                    details_text += f"Details: {details}\n"
                    if learn_more:
                        details_text += f"Learn More: {learn_more}\n"

                    # Add error or failure element based on finding type
                    if finding_type == "ERROR":
                        error = ET.SubElement(testcase, "error")
                        error.set("type", finding_type)
                        error.set("message", message)
                        error.text = details_text
                    elif finding_type in ["WARNING", "SECURITY_WARNING"]:
                        failure = ET.SubElement(testcase, "failure")
                        failure.set("type", finding_type)
                        failure.set("message", message)
                        failure.text = details_text
                    # SUGGESTION findings don't get error/failure elements (passing tests)

            # Add system-out and system-err elements (required by AWS CodeBuild)
            ET.SubElement(testsuite, "system-out")
            ET.SubElement(testsuite, "system-err")

            # Update totals
            total_tests += suite_tests
            total_failures += suite_failures
            total_errors += suite_errors
            total_time += suite_time

        # Set summary attributes on root element
        testsuites.set("tests", str(total_tests))
        testsuites.set("failures", str(total_failures))
        testsuites.set("errors", str(total_errors))
        testsuites.set("skipped", "0")  # Required by AWS CodeBuild
        testsuites.set("time", f"{total_time:.3f}")

        # Generate clean XML without minidom's extra blank lines
        # Use ElementTree's indent method (Python 3.9+) or manual formatting
        try:
            # Python 3.9+ has indent method
            ET.indent(testsuites, space="  ", level=0)
            xml_str = ET.tostring(testsuites, encoding="unicode", xml_declaration=False)
            # Add clean XML declaration
            pretty_xml = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str
        except AttributeError:
            # Fallback for Python < 3.9: use minidom but clean up output
            xml_str = ET.tostring(testsuites, encoding="unicode")
            from xml.dom import minidom
            dom = minidom.parseString(xml_str)
            pretty_xml_bytes = dom.toprettyxml(indent="  ", encoding="UTF-8")
            # Remove extra blank lines that minidom adds
            lines = pretty_xml_bytes.decode("UTF-8").split('\n')
            # Filter out empty lines between elements
            cleaned_lines = []
            for i, line in enumerate(lines):
                if line.strip() or (i > 0 and lines[i-1].strip().endswith('>')):
                    cleaned_lines.append(line)
            pretty_xml = '\n'.join(cleaned_lines)
            # Ensure clean XML declaration
            if pretty_xml.startswith('<?xml'):
                pretty_xml = pretty_xml.split('\n', 1)[1]
            pretty_xml = '<?xml version="1.0" encoding="UTF-8"?>\n' + pretty_xml

        try:
            with file_name.open("w", encoding="utf-8") as f:
                f.write(pretty_xml)

            logger.info(f"Created JUnit XML report: {file_name}")
            return file_name

        except OSError as e:
            logger.error(f"Failed to create JUnit XML report: {e}")
            raise


