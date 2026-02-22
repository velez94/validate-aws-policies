"""Report generation module for AWS policy validation results."""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from zipfile import ZipFile

from json2html import json2html

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate validation reports in various formats."""

    def create_html_report(self, results: List[Dict[str, Any]]) -> Path:
        """
        Create modern, responsive HTML report from validation results.

        Args:
            results: List of validation results containing policy findings

        Returns:
            Path to the created HTML report file

        Raises:
            IOError: If unable to write the HTML file
        """
        timestamp = datetime.now()
        file_name = Path(f"AccessAnalyzerReport_{timestamp.strftime('%Y%m%d_%H%M%S')}.html")

        logger.info("Creating HTML report...")

        # Calculate summary statistics
        total_policies = len(results)
        total_findings = sum(len(r.get("summary", [])) for r in results)
        findings_by_type = {"ERROR": 0, "WARNING": 0, "SUGGESTION": 0, "SECURITY_WARNING": 0}
        
        for result in results:
            for finding in result.get("summary", []):
                finding_type = finding.get("findingType", "")
                if finding_type in findings_by_type:
                    findings_by_type[finding_type] += 1

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="generator" content="AWS Policy Validator">
    <title>AWS Policy Validation Report</title>
    <style>

        :root {{
            --primary-color: #232f3e;
            --secondary-color: #ff9900;
            --error-color: #d13212;
            --warning-color: #ff9900;
            --suggestion-color: #1e8900;
            --security-warning-color: #ec7211;
            --bg-color: #f8f9fa;
            --card-bg: #ffffff;
            --text-primary: #16191f;
            --text-secondary: #545b64;
            --border-color: #d5dbdb;
            --shadow: 0 2px 4px rgba(0,0,0,0.1);
            --shadow-hover: 0 4px 8px rgba(0,0,0,0.15);
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
                'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        header {{
            background: linear-gradient(135deg, var(--primary-color) 0%, #37475a 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: var(--shadow);
        }}

        h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 10px;
        }}

        .subtitle {{
            font-size: 1.1rem;
            opacity: 0.9;
            font-weight: 300;
        }}

        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: var(--card-bg);
            padding: 25px;
            border-radius: 8px;
            box-shadow: var(--shadow);
            transition: transform 0.2s, box-shadow 0.2s;
        }}

        .summary-card:hover {{
            transform: translateY(-2px);
            box-shadow: var(--shadow-hover);
        }}

        .summary-card .number {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 5px;
        }}

        .summary-card .label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .summary-card.error .number {{ color: var(--error-color); }}
        .summary-card.warning .number {{ color: var(--warning-color); }}
        .summary-card.suggestion .number {{ color: var(--suggestion-color); }}
        .summary-card.security .number {{ color: var(--security-warning-color); }}

        .report-section {{
            background: var(--card-bg);
            padding: 30px;
            border-radius: 8px;
            box-shadow: var(--shadow);
            margin-bottom: 20px;
        }}

        h2 {{
            font-size: 1.8rem;
            margin-bottom: 20px;
            color: var(--primary-color);
            border-bottom: 3px solid var(--secondary-color);
            padding-bottom: 10px;
        }}

        .policy-item {{
            margin-bottom: 30px;
            padding: 20px;
            background: var(--bg-color);
            border-radius: 6px;
            border-left: 4px solid var(--primary-color);
        }}

        .policy-name {{
            font-size: 1.3rem;
            font-weight: 600;
            color: var(--primary-color);
            margin-bottom: 15px;
        }}

        .findings-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            overflow-x: auto;
            display: block;
        }}

        .findings-table thead {{
            background: var(--primary-color);
            color: white;
        }}

        .findings-table th,
        .findings-table td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        .findings-table th {{
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 0.5px;
        }}

        .findings-table tbody tr:hover {{
            background-color: rgba(255, 153, 0, 0.05);
        }}

        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .badge.error {{
            background-color: rgba(209, 50, 18, 0.1);
            color: var(--error-color);
        }}

        .badge.warning {{
            background-color: rgba(255, 153, 0, 0.1);
            color: var(--warning-color);
        }}

        .badge.suggestion {{
            background-color: rgba(30, 137, 0, 0.1);
            color: var(--suggestion-color);
        }}

        .badge.security {{
            background-color: rgba(236, 114, 17, 0.1);
            color: var(--security-warning-color);
        }}

        .no-findings {{
            color: var(--suggestion-color);
            font-weight: 500;
            padding: 15px;
            background: rgba(30, 137, 0, 0.05);
            border-radius: 4px;
            text-align: center;
        }}

        footer {{
            margin-top: 40px;
            padding: 20px;
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.9rem;
            border-top: 1px solid var(--border-color);
        }}

        .timestamp {{
            font-weight: 600;
            color: var(--text-primary);
        }}

        @media (max-width: 768px) {{
            h1 {{
                font-size: 1.8rem;
            }}

            .summary-cards {{
                grid-template-columns: repeat(2, 1fr);
            }}

            .findings-table {{
                font-size: 0.85rem;
            }}

            .findings-table th,
            .findings-table td {{
                padding: 8px 10px;
            }}
        }}

        @media (max-width: 480px) {{
            body {{
                padding: 10px;
            }}

            header {{
                padding: 20px;
            }}

            .summary-cards {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>AWS Policy Validation Report</h1>
            <p class="subtitle">IAM Access Analyzer Policy Validation Results</p>
        </header>

        <div class="summary-cards">
            <div class="summary-card">
                <div class="number">{total_policies}</div>
                <div class="label">Total Policies</div>
            </div>
            <div class="summary-card">
                <div class="number">{total_findings}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="summary-card error">
                <div class="number">{findings_by_type['ERROR']}</div>
                <div class="label">Errors</div>
            </div>
            <div class="summary-card warning">
                <div class="number">{findings_by_type['WARNING']}</div>
                <div class="label">Warnings</div>
            </div>
            <div class="summary-card security">
                <div class="number">{findings_by_type['SECURITY_WARNING']}</div>
                <div class="label">Security Warnings</div>
            </div>
            <div class="summary-card suggestion">
                <div class="number">{findings_by_type['SUGGESTION']}</div>
                <div class="label">Suggestions</div>
            </div>
        </div>

        <div class="report-section">
            <h2>Policy Validation Details</h2>
"""

        # Add policy details
        for result in results:
            policy_name = result.get("filePolicy", "Unknown Policy")
            summary = result.get("summary", [])
            
            html_content += f"""
            <div class="policy-item">
                <div class="policy-name">📄 {policy_name}</div>
"""
            
            if not summary:
                html_content += """
                <div class="no-findings">✓ No findings - Policy is valid</div>
"""
            else:
                html_content += """
                <table class="findings-table">
                    <thead>
                        <tr>
                            <th>Finding Type</th>
                            <th>Issue Code</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
"""
                for finding in summary:
                    finding_type = finding.get("findingType", "UNKNOWN")
                    issue_code = finding.get("issueCode", "N/A")
                    details = finding.get("findingDetails", "No details available")
                    
                    badge_class = finding_type.lower().replace("_", "-")
                    if badge_class not in ["error", "warning", "suggestion", "security-warning"]:
                        badge_class = "warning"
                    
                    html_content += f"""
                        <tr>
                            <td><span class="badge {badge_class}">{finding_type}</span></td>
                            <td>{issue_code}</td>
                            <td>{details}</td>
                        </tr>
"""
                
                html_content += """
                    </tbody>
                </table>
"""
            
            html_content += """
            </div>
"""

        html_content += f"""
        </div>

        <footer>
            <p>Generated on <span class="timestamp">{timestamp.strftime('%Y-%m-%d %H:%M:%S')}</span></p>
            <p>AWS Policy Validator | IAM Access Analyzer</p>
        </footer>
    </div>
</body>
</html>
"""

        try:
            with file_name.open("w", encoding="utf-8") as f:
                f.write(html_content)

            logger.info(f"Created HTML report: {file_name}")
            return file_name

        except OSError as e:
            logger.error(f"Failed to create HTML report: {e}")
            raise


    def create_markdown_report(self, results: List[Dict[str, Any]]) -> Path:
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
        total_findings = sum(len(r.get("summary", [])) for r in results)
        findings_by_type = {"ERROR": 0, "WARNING": 0, "SUGGESTION": 0, "SECURITY_WARNING": 0}
        
        for result in results:
            for finding in result.get("summary", []):
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
            md_content += f"{idx}. [{policy_name}](#{policy_name.replace(' ', '-').replace('.', '').lower()})\n"

        md_content += "\n---\n\n## Policy Validation Details\n\n"

        # Add policy details
        for result in results:
            policy_name = result.get("filePolicy", "Unknown Policy")
            summary = result.get("summary", [])
            
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
                    details = finding.get("findingDetails", "No details available")
                    
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

    def create_zip(self, file_paths: List[Path]) -> Path:
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
    def create_junit_xml_report(self, results: List[Dict[str, Any]]) -> Path:
        """
        Create JUnit XML report from validation results for CI/CD integration.

        The XML format follows the JUnit schema compatible with Jenkins, GitLab CI,
        GitHub Actions, CircleCI, and other CI/CD tools.

        Args:
            results: List of validation results containing policy findings

        Returns:
            Path to the created XML report file

        Raises:
            IOError: If unable to write the XML file
        """
        import socket
        import xml.etree.ElementTree as ET
        from xml.dom import minidom

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
        testsuites.set("timestamp", timestamp.isoformat())
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
            testsuite.set("time", f"{suite_time:.3f}")
            testsuite.set("timestamp", timestamp.isoformat())

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

            # Update totals
            total_tests += suite_tests
            total_failures += suite_failures
            total_errors += suite_errors
            total_time += suite_time

        # Set summary attributes on root element
        testsuites.set("tests", str(total_tests))
        testsuites.set("failures", str(total_failures))
        testsuites.set("errors", str(total_errors))
        testsuites.set("time", f"{total_time:.3f}")

        # Convert to pretty-printed XML string
        xml_str = ET.tostring(testsuites, encoding="unicode")
        dom = minidom.parseString(xml_str)
        pretty_xml = dom.toprettyxml(indent="  ", encoding="UTF-8")

        try:
            with file_name.open("wb") as f:
                f.write(pretty_xml)

            logger.info(f"Created JUnit XML report: {file_name}")
            return file_name

        except OSError as e:
            logger.error(f"Failed to create JUnit XML report: {e}")
            raise


