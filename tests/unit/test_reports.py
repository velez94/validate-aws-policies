"""Unit tests for JUnit XML report generation."""

import os
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

import pytest

from validate_aws_policies.ops.reports import ReportGenerator


class TestJUnitXMLReport:
    """Test suite for JUnit XML report generation."""

    @pytest.fixture
    def report_generator(self):
        """Create ReportGenerator instance."""
        return ReportGenerator()

    @pytest.fixture
    def sample_results_no_findings(self):
        """Sample results with no findings (valid policy)."""
        return [
            {
                "filePolicy": "valid-policy.json",
                "summary": []
            }
        ]

    @pytest.fixture
    def sample_results_with_errors(self):
        """Sample results with ERROR findings."""
        return [
            {
                "filePolicy": "error-policy.json",
                "summary": [
                    {
                        "findingType": "ERROR",
                        "issueCode": "INVALID_ACTION",
                        "findingDetails": "Action 's3:InvalidAction' does not exist",
                        "learnMoreLink": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html"
                    }
                ]
            }
        ]

    @pytest.fixture
    def sample_results_with_warnings(self):
        """Sample results with WARNING findings."""
        return [
            {
                "filePolicy": "warning-policy.json",
                "summary": [
                    {
                        "findingType": "WARNING",
                        "issueCode": "MISSING_VERSION",
                        "findingDetails": "Policy should include a Version element",
                        "learnMoreLink": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html"
                    }
                ]
            }
        ]

    @pytest.fixture
    def sample_results_with_security_warnings(self):
        """Sample results with SECURITY_WARNING findings."""
        return [
            {
                "filePolicy": "security-policy.json",
                "summary": [
                    {
                        "findingType": "SECURITY_WARNING",
                        "issueCode": "WILDCARD_RESOURCE",
                        "findingDetails": "Using wildcard in Resource can be overly permissive",
                        "learnMoreLink": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
                    }
                ]
            }
        ]

    @pytest.fixture
    def sample_results_with_suggestions(self):
        """Sample results with SUGGESTION findings."""
        return [
            {
                "filePolicy": "suggestion-policy.json",
                "summary": [
                    {
                        "findingType": "SUGGESTION",
                        "issueCode": "SIMPLIFY_POLICY",
                        "findingDetails": "Policy can be simplified by combining statements",
                        "learnMoreLink": ""
                    }
                ]
            }
        ]

    @pytest.fixture
    def sample_results_mixed(self):
        """Sample results with multiple policies and mixed finding types."""
        return [
            {
                "filePolicy": "policy1.json",
                "summary": [
                    {
                        "findingType": "ERROR",
                        "issueCode": "INVALID_ACTION",
                        "findingDetails": "Invalid action specified",
                        "learnMoreLink": "https://example.com"
                    },
                    {
                        "findingType": "WARNING",
                        "issueCode": "MISSING_VERSION",
                        "findingDetails": "Missing version",
                        "learnMoreLink": ""
                    }
                ]
            },
            {
                "filePolicy": "policy2.json",
                "summary": []
            },
            {
                "filePolicy": "policy3.json",
                "summary": [
                    {
                        "findingType": "SUGGESTION",
                        "issueCode": "OPTIMIZE",
                        "findingDetails": "Can be optimized",
                        "learnMoreLink": ""
                    }
                ]
            }
        ]

    @pytest.fixture
    def sample_results_special_chars(self):
        """Sample results with special characters in policy names and messages."""
        return [
            {
                "filePolicy": "policy-with-<special>&chars.json",
                "summary": [
                    {
                        "findingType": "ERROR",
                        "issueCode": "SPECIAL_CHARS",
                        "findingDetails": "Message with <tags> & \"quotes\" and 'apostrophes'",
                        "learnMoreLink": "https://example.com?param=value&other=test"
                    }
                ]
            }
        ]

    @pytest.fixture
    def sample_results_empty(self):
        """Empty results list."""
        return []

    def test_xml_structure_has_required_attributes(self, report_generator, sample_results_no_findings):
        """Test that XML has all required attributes for CodeBuild."""
        # Create the XML file
        xml_file = report_generator.create_junit_xml_report(sample_results_no_findings)

        try:
            # Read the created file
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            # Parse and test
            root = ET.fromstring(xml_content)

            # Check testsuites attributes
            assert root.tag == "testsuites"
            assert "name" in root.attrib
            assert "tests" in root.attrib
            assert "failures" in root.attrib
            assert "errors" in root.attrib
            assert "skipped" in root.attrib
            assert "time" in root.attrib
            assert "timestamp" in root.attrib
            assert "hostname" in root.attrib

            # Check testsuite attributes
            testsuite = root.find("testsuite")
            assert testsuite is not None
            assert "name" in testsuite.attrib
            assert "tests" in testsuite.attrib
            assert "failures" in testsuite.attrib
            assert "errors" in testsuite.attrib
            assert "skipped" in testsuite.attrib
            assert "time" in testsuite.attrib
            assert "timestamp" in testsuite.attrib

            # Check testcase attributes
            testcase = testsuite.find("testcase")
            assert testcase is not None
            assert "classname" in testcase.attrib
            assert "name" in testcase.attrib
            assert "time" in testcase.attrib
        finally:
            # Cleanup
            if xml_file.exists():
                xml_file.unlink()

    def test_codebuild_skipped_attribute(self, report_generator, sample_results_no_findings):
        """Test that skipped attribute is present (CodeBuild requirement)."""
        xml_file = report_generator.create_junit_xml_report(sample_results_no_findings)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            # Check testsuites has skipped="0"
            assert root.attrib["skipped"] == "0"

            # Check each testsuite has skipped="0"
            for testsuite in root.findall("testsuite"):
                assert testsuite.attrib["skipped"] == "0"
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_codebuild_system_elements(self, report_generator, sample_results_no_findings):
        """Test that system-out and system-err elements exist (CodeBuild requirement)."""
        xml_file = report_generator.create_junit_xml_report(sample_results_no_findings)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            # Check each testsuite has system-out and system-err
            for testsuite in root.findall("testsuite"):
                system_out = testsuite.find("system-out")
                system_err = testsuite.find("system-err")
                assert system_out is not None, "system-out element is required by CodeBuild"
                assert system_err is not None, "system-err element is required by CodeBuild"
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_timestamp_format(self, report_generator, sample_results_no_findings):
        """Test that timestamp format is ISO 8601 without microseconds."""
        xml_file = report_generator.create_junit_xml_report(sample_results_no_findings)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            # Check testsuites timestamp format
            timestamp_str = root.attrib["timestamp"]
            # Should be in format: YYYY-MM-DDTHH:MM:SS (no microseconds)
            try:
                parsed = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S')
                assert parsed is not None
            except ValueError:
                pytest.fail(f"Timestamp format is incorrect: {timestamp_str}")

            # Check testsuite timestamp format
            testsuite = root.find("testsuite")
            timestamp_str = testsuite.attrib["timestamp"]
            try:
                parsed = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S')
                assert parsed is not None
            except ValueError:
                pytest.fail(f"Testsuite timestamp format is incorrect: {timestamp_str}")
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_error_findings_create_error_elements(self, report_generator, sample_results_with_errors):
        """Test that ERROR findings create <error> elements."""
        xml_file = report_generator.create_junit_xml_report(sample_results_with_errors)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            # Check that errors count is correct
            assert root.attrib["errors"] == "1"

            # Find the testcase with error
            testsuite = root.find("testsuite")
            testcase = testsuite.find("testcase")
            error = testcase.find("error")

            assert error is not None, "ERROR finding should create <error> element"
            assert error.attrib["type"] == "ERROR"
            assert "INVALID_ACTION" in error.attrib["message"]
            assert "Action 's3:InvalidAction' does not exist" in error.text
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_warning_findings_create_failure_elements(self, report_generator, sample_results_with_warnings):
        """Test that WARNING findings create <failure> elements."""
        xml_file = report_generator.create_junit_xml_report(sample_results_with_warnings)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            # Check that failures count is correct
            assert root.attrib["failures"] == "1"

            # Find the testcase with failure
            testsuite = root.find("testsuite")
            testcase = testsuite.find("testcase")
            failure = testcase.find("failure")

            assert failure is not None, "WARNING finding should create <failure> element"
            assert failure.attrib["type"] == "WARNING"
            assert "MISSING_VERSION" in failure.attrib["message"]
            assert "Policy should include a Version element" in failure.text
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_security_warning_findings_create_failure_elements(self, report_generator, sample_results_with_security_warnings):
        """Test that SECURITY_WARNING findings create <failure> elements."""
        xml_file = report_generator.create_junit_xml_report(sample_results_with_security_warnings)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            # Check that failures count is correct
            assert root.attrib["failures"] == "1"

            # Find the testcase with failure
            testsuite = root.find("testsuite")
            testcase = testsuite.find("testcase")
            failure = testcase.find("failure")

            assert failure is not None, "SECURITY_WARNING finding should create <failure> element"
            assert failure.attrib["type"] == "SECURITY_WARNING"
            assert "WILDCARD_RESOURCE" in failure.attrib["message"]
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_suggestion_findings_create_passing_tests(self, report_generator, sample_results_with_suggestions):
        """Test that SUGGESTION findings create passing tests (no error/failure)."""
        xml_file = report_generator.create_junit_xml_report(sample_results_with_suggestions)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            # Check that no failures or errors
            assert root.attrib["failures"] == "0"
            assert root.attrib["errors"] == "0"
            assert root.attrib["tests"] == "1"

            # Find the testcase - should have no error or failure child
            testsuite = root.find("testsuite")
            testcase = testsuite.find("testcase")
            error = testcase.find("error")
            failure = testcase.find("failure")

            assert error is None, "SUGGESTION finding should not create <error> element"
            assert failure is None, "SUGGESTION finding should not create <failure> element"
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_no_findings_create_passing_test(self, report_generator, sample_results_no_findings):
        """Test that policies with no findings create passing tests."""
        xml_file = report_generator.create_junit_xml_report(sample_results_no_findings)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            # Check that no failures or errors
            assert root.attrib["failures"] == "0"
            assert root.attrib["errors"] == "0"
            assert root.attrib["tests"] == "1"

            # Find the testcase
            testsuite = root.find("testsuite")
            testcase = testsuite.find("testcase")

            assert testcase.attrib["name"] == "ValidatePolicy"
            assert testcase.find("error") is None
            assert testcase.find("failure") is None
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_xml_is_well_formed(self, report_generator, sample_results_mixed):
        """Test that generated XML is well-formed and parseable."""
        xml_file = report_generator.create_junit_xml_report(sample_results_mixed)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            # Should be parseable without errors
            try:
                root = ET.fromstring(xml_content)
                assert root is not None
            except ET.ParseError as e:
                pytest.fail(f"Generated XML is not well-formed: {e}")
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_xml_declaration(self, report_generator, sample_results_no_findings):
        """Test that XML declaration is correct."""
        xml_file = report_generator.create_junit_xml_report(sample_results_no_findings)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            # Check XML declaration
            assert xml_content.startswith('<?xml version="1.0" encoding="UTF-8"?>')
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_special_characters_are_escaped(self, report_generator, sample_results_special_chars):
        """Test that special characters are properly escaped."""
        xml_file = report_generator.create_junit_xml_report(sample_results_special_chars)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            # Should be parseable even with special characters
            try:
                root = ET.fromstring(xml_content)
                testsuite = root.find("testsuite")
                testcase = testsuite.find("testcase")
                error = testcase.find("error")

                # Special characters should be in the parsed content
                assert "<tags>" in error.text
                assert "&" in error.text
                assert '"quotes"' in error.text
            except ET.ParseError as e:
                pytest.fail(f"XML with special characters is not well-formed: {e}")
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_empty_results_list(self, report_generator, sample_results_empty):
        """Test with empty results list."""
        xml_file = report_generator.create_junit_xml_report(sample_results_empty)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            # Should have zero tests
            assert root.attrib["tests"] == "0"
            assert root.attrib["failures"] == "0"
            assert root.attrib["errors"] == "0"

            # Should have no testsuite elements
            testsuites = root.findall("testsuite")
            assert len(testsuites) == 0
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_multiple_policies(self, report_generator, sample_results_mixed):
        """Test with multiple policies."""
        xml_file = report_generator.create_junit_xml_report(sample_results_mixed)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            # Should have 3 testsuites (one per policy)
            testsuites = root.findall("testsuite")
            assert len(testsuites) == 3

            # Check total counts
            # policy1: 2 tests (1 error, 1 warning)
            # policy2: 1 test (no findings)
            # policy3: 1 test (1 suggestion)
            assert root.attrib["tests"] == "4"
            assert root.attrib["errors"] == "1"
            assert root.attrib["failures"] == "1"
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_mixed_finding_types(self, report_generator, sample_results_mixed):
        """Test with mixed finding types."""
        xml_file = report_generator.create_junit_xml_report(sample_results_mixed)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            # Find policy1 testsuite (has error and warning)
            testsuites = root.findall("testsuite")
            policy1_suite = testsuites[0]

            assert policy1_suite.attrib["tests"] == "2"
            assert policy1_suite.attrib["errors"] == "1"
            assert policy1_suite.attrib["failures"] == "1"

            # Check testcases
            testcases = policy1_suite.findall("testcase")
            assert len(testcases) == 2

            # First testcase should have error
            assert testcases[0].find("error") is not None

            # Second testcase should have failure
            assert testcases[1].find("failure") is not None
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_testcase_naming(self, report_generator, sample_results_with_errors):
        """Test that testcase names are properly formatted."""
        xml_file = report_generator.create_junit_xml_report(sample_results_with_errors)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            testsuite = root.find("testsuite")
            testcase = testsuite.find("testcase")

            # Testcase name should be issueCode_index
            assert testcase.attrib["name"] == "INVALID_ACTION_1"
            # Classname should be policy name without .json
            assert testcase.attrib["classname"] == "error-policy"
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_time_attributes_are_numeric(self, report_generator, sample_results_mixed):
        """Test that time attributes are numeric and properly formatted."""
        xml_file = report_generator.create_junit_xml_report(sample_results_mixed)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            # Check testsuites time
            time_value = float(root.attrib["time"])
            assert time_value >= 0

            # Check each testsuite time
            for testsuite in root.findall("testsuite"):
                time_value = float(testsuite.attrib["time"])
                assert time_value >= 0

                # Check each testcase time
                for testcase in testsuite.findall("testcase"):
                    time_value = float(testcase.attrib["time"])
                    assert time_value >= 0
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_properties_section(self, report_generator, sample_results_no_findings):
        """Test that properties section is included with metadata."""
        xml_file = report_generator.create_junit_xml_report(sample_results_no_findings)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            testsuite = root.find("testsuite")
            properties = testsuite.find("properties")

            assert properties is not None, "Properties section should be present"

            # Check for expected properties
            property_names = [prop.attrib["name"] for prop in properties.findall("property")]
            assert "validator" in property_names
            assert "policy_file" in property_names
            assert "total_findings" in property_names
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_learn_more_link_included(self, report_generator, sample_results_with_errors):
        """Test that learnMoreLink is included in error details."""
        xml_file = report_generator.create_junit_xml_report(sample_results_with_errors)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            testsuite = root.find("testsuite")
            testcase = testsuite.find("testcase")
            error = testcase.find("error")

            # Check that learn more link is in the error text
            assert "Learn More:" in error.text
            assert "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html" in error.text
        finally:
            if xml_file.exists():
                xml_file.unlink()

    def test_file_creation_returns_path(self, report_generator, sample_results_no_findings):
        """Test that create_junit_xml_report returns a Path object."""
        result = report_generator.create_junit_xml_report(sample_results_no_findings)

        try:
            assert isinstance(result, Path)
            assert result.suffix == ".xml"
            assert "AccessAnalyzerReport_" in result.name
        finally:
            if result.exists():
                result.unlink()

    def test_hostname_attribute(self, report_generator, sample_results_no_findings):
        """Test that hostname attribute is present in testsuites."""
        xml_file = report_generator.create_junit_xml_report(sample_results_no_findings)

        try:
            with xml_file.open('r', encoding='utf-8') as f:
                xml_content = f.read()

            root = ET.fromstring(xml_content)

            assert "hostname" in root.attrib
            assert len(root.attrib["hostname"]) > 0
        finally:
            if xml_file.exists():
                xml_file.unlink()
