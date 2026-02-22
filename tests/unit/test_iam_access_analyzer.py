"""Unit tests for IAM Access Analyzer module."""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from validate_aws_policies.iam_access_analyzer.iam_access_analyzer import validate_policies


class TestValidatePolicies:
    """Test suite for validate_policies function."""

    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.boto3")
    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.read_policies")
    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.validate_findings")
    def test_validate_policies_success_with_string_path(
        self, mock_validate_findings, mock_read_policies, mock_boto3, tmp_path
    ):
        """Test successful validation with string path."""
        # Setup
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        policy_file = policy_dir / "test-policy.json"
        policy_file.write_text('{"Version": "2012-10-17"}')

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.get_paginator.return_value = mock_paginator

        mock_page = {"findings": [{"findingType": "WARNING", "issueCode": "TEST"}]}
        mock_paginator.paginate.return_value = [mock_page]

        mock_read_policies.return_value = '{"Version": "2012-10-17"}'
        mock_validate_findings.return_value = {"filePolicy": "test-policy.json", "summary": []}

        # Execute
        result = validate_policies(["test-policy.json"], str(policy_dir))

        # Assert
        assert len(result) == 1
        mock_boto3.client.assert_called_once_with("accessanalyzer")
        mock_read_policies.assert_called_once()
        mock_validate_findings.assert_called_once()

    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.boto3")
    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.read_policies")
    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.validate_findings")
    def test_validate_policies_success_with_path_object(
        self, mock_validate_findings, mock_read_policies, mock_boto3, tmp_path
    ):
        """Test successful validation with Path object."""
        # Setup
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        policy_file = policy_dir / "test-policy.json"
        policy_file.write_text('{"Version": "2012-10-17"}')

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.get_paginator.return_value = mock_paginator

        mock_page = {"findings": []}
        mock_paginator.paginate.return_value = [mock_page]

        mock_read_policies.return_value = '{"Version": "2012-10-17"}'
        mock_validate_findings.return_value = {"filePolicy": "test-policy.json", "summary": []}

        # Execute
        result = validate_policies(["test-policy.json"], policy_dir)

        # Assert
        assert len(result) == 1
        assert isinstance(result, list)

    def test_validate_policies_directory_not_found(self):
        """Test error handling when policies directory doesn't exist."""
        # Execute & Assert
        with pytest.raises(FileNotFoundError) as exc_info:
            validate_policies(["test.json"], "/nonexistent/path")

        assert "Policies directory not found" in str(exc_info.value)

    def test_validate_policies_path_not_directory(self, tmp_path):
        """Test error handling when policies path is a file, not a directory."""
        # Setup
        policy_file = tmp_path / "not-a-dir.txt"
        policy_file.write_text("test")

        # Execute & Assert
        with pytest.raises(NotADirectoryError) as exc_info:
            validate_policies(["test.json"], policy_file)

        assert "not a directory" in str(exc_info.value)

    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.boto3")
    def test_validate_policies_aws_client_error(self, mock_boto3, tmp_path):
        """Test error handling when AWS client initialization fails."""
        # Setup
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()

        error_response = {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}
        mock_boto3.client.side_effect = ClientError(error_response, "CreateClient")

        # Execute & Assert
        with pytest.raises(ClientError):
            validate_policies(["test.json"], policy_dir)

    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.boto3")
    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.read_policies")
    def test_validate_policies_file_not_found(self, mock_read_policies, mock_boto3, tmp_path):
        """Test error handling when policy file doesn't exist."""
        # Setup
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()

        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.get_paginator.return_value = MagicMock()

        mock_read_policies.side_effect = FileNotFoundError("Policy file not found")

        # Execute & Assert
        with pytest.raises(FileNotFoundError):
            validate_policies(["missing.json"], policy_dir)

    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.boto3")
    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.read_policies")
    def test_validate_policies_api_error_during_validation(
        self, mock_read_policies, mock_boto3, tmp_path
    ):
        """Test error handling when AWS API call fails during validation."""
        # Setup
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        policy_file = policy_dir / "test-policy.json"
        policy_file.write_text('{"Version": "2012-10-17"}')

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.get_paginator.return_value = mock_paginator

        error_response = {"Error": {"Code": "InvalidPolicyDocument", "Message": "Invalid policy"}}
        mock_paginator.paginate.side_effect = ClientError(error_response, "ValidatePolicy")

        mock_read_policies.return_value = '{"Version": "2012-10-17"}'

        # Execute & Assert
        with pytest.raises(ClientError) as exc_info:
            validate_policies(["test-policy.json"], policy_dir)

        assert exc_info.value.response["Error"]["Code"] == "InvalidPolicyDocument"

    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.boto3")
    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.read_policies")
    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.validate_findings")
    def test_validate_policies_multiple_files(
        self, mock_validate_findings, mock_read_policies, mock_boto3, tmp_path
    ):
        """Test validation of multiple policy files."""
        # Setup
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()

        for i in range(3):
            policy_file = policy_dir / f"policy-{i}.json"
            policy_file.write_text('{"Version": "2012-10-17"}')

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.get_paginator.return_value = mock_paginator

        mock_page = {"findings": []}
        mock_paginator.paginate.return_value = [mock_page]

        mock_read_policies.return_value = '{"Version": "2012-10-17"}'
        mock_validate_findings.return_value = {"filePolicy": "test", "summary": []}

        # Execute
        result = validate_policies(["policy-0.json", "policy-1.json", "policy-2.json"], policy_dir)

        # Assert
        assert len(result) == 3
        assert mock_read_policies.call_count == 3
        assert mock_validate_findings.call_count == 3

    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.boto3")
    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.read_policies")
    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.validate_findings")
    def test_validate_policies_skips_unreadable_file(
        self, mock_validate_findings, mock_read_policies, mock_boto3, tmp_path
    ):
        """Test that validation continues when a file cannot be read."""
        # Setup
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.get_paginator.return_value = mock_paginator

        mock_page = {"findings": []}
        mock_paginator.paginate.return_value = [mock_page]

        # First file returns None (unreadable), second file succeeds
        mock_read_policies.side_effect = [None, '{"Version": "2012-10-17"}']
        mock_validate_findings.return_value = {"filePolicy": "test", "summary": []}

        # Execute
        result = validate_policies(["bad.json", "good.json"], policy_dir)

        # Assert - only one policy should be validated
        assert len(result) == 1
        assert mock_validate_findings.call_count == 1

    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.boto3")
    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.read_policies")
    @patch("validate_aws_policies.iam_access_analyzer.iam_access_analyzer.validate_findings")
    def test_validate_policies_pagination(
        self, mock_validate_findings, mock_read_policies, mock_boto3, tmp_path
    ):
        """Test that pagination correctly aggregates findings across multiple pages."""
        # Setup
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        policy_file = policy_dir / "test-policy.json"
        policy_file.write_text('{"Version": "2012-10-17"}')

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_client.get_paginator.return_value = mock_paginator

        # Multiple pages with findings
        mock_pages = [
            {"findings": [{"findingType": "WARNING", "issueCode": "TEST1"}]},
            {"findings": [{"findingType": "SUGGESTION", "issueCode": "TEST2"}]},
            {"findings": [{"findingType": "WARNING", "issueCode": "TEST3"}]},
        ]
        mock_paginator.paginate.return_value = mock_pages

        mock_read_policies.return_value = '{"Version": "2012-10-17"}'
        mock_validate_findings.return_value = {"filePolicy": "test-policy.json", "summary": []}

        # Execute
        result = validate_policies(["test-policy.json"], policy_dir)

        # Assert - validate_findings should be called with all 3 findings
        assert len(result) == 1
        call_args = mock_validate_findings.call_args
        findings_arg = call_args[0][1]
        assert len(findings_arg) == 3
