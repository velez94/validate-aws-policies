"""Tests for the main entry point."""

import sys
from unittest.mock import MagicMock, patch

import pytest

# Add src to path for imports
sys.path.insert(0, "src")

from validate_aws_policies.cli.exit_codes import (
    EXIT_SUCCESS,
)
from validate_aws_policies.validate_policies import main, merge_config, setup_logging


class TestSetupLogging:
    """Test setup_logging function."""

    def test_setup_logging_default(self):
        """Test default logging setup."""
        setup_logging()
        # Should not raise any exceptions

    def test_setup_logging_verbose(self):
        """Test verbose logging setup."""
        setup_logging(verbose=True)
        # Should not raise any exceptions

    def test_setup_logging_quiet(self):
        """Test quiet logging setup."""
        setup_logging(quiet=True)
        # Should not raise any exceptions

    def test_setup_logging_json_format(self):
        """Test JSON format logging setup."""
        setup_logging(log_format="json")
        # Should not raise any exceptions


class TestMergeConfig:
    """Test merge_config function."""

    def test_merge_config_basic(self):
        """Test basic config merging."""
        # Create mock args
        args = MagicMock()
        args.config = None
        args.policies_path = "/test/path"
        args.profile = "test-profile"
        args.bucket = "test-bucket"
        args.upload = True
        args.zip = False
        args.ci = False
        args.dry_run = False
        args.format = "json"
        args.output = None
        args.verbose = False
        args.quiet = False
        args.log_format = "text"

        config = merge_config(args)

        assert config["policies_path"] == "/test/path"
        assert config["profile"] == "test-profile"
        assert config["bucket_name"] == "test-bucket"
        assert config["upload"] is True
        assert config["zip"] is False


class TestMain:
    """Test main function."""

    def test_main_version(self, capsys):
        """Test --version flag."""
        with patch.object(sys, "argv", ["validate-aws-policies", "--version"]):
            exit_code = main()

        assert exit_code == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "validate-aws-policies version" in captured.out

    def test_main_no_args(self):
        """Test main with no arguments (should fail validation)."""
        with patch.object(sys, "argv", ["validate-aws-policies"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        # Should exit with status 2 (argparse error)
        assert exc_info.value.code == 2

    def test_main_missing_bucket_with_upload(self):
        """Test main with --upload but no --bucket."""
        with patch.object(
            sys, "argv", ["validate-aws-policies", "--policies-path", "./policies", "--upload"]
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()

        # Should exit with status 2 (argparse error)
        assert exc_info.value.code == 2
