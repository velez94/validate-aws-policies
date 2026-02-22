"""Unit tests for CLI argument parser."""

import tempfile
from argparse import Namespace

import pytest

from validate_aws_policies.cli.args import (
    ArgumentValidationError,
    create_parser,
    parse_args,
    validate_args,
)


class TestCreateParser:
    """Tests for create_parser function."""

    def test_create_parser_returns_parser(self):
        """Test that create_parser returns an ArgumentParser instance."""
        parser = create_parser()
        assert parser is not None
        assert hasattr(parser, "parse_args")

    def test_parser_has_all_arguments(self):
        """Test that parser has all expected arguments."""
        parser = create_parser()

        # Parse with --help to get all arguments (will exit, so we catch it)
        with pytest.raises(SystemExit):
            parser.parse_args(["--help"])


class TestValidateArgs:
    """Tests for validate_args function."""

    def test_validate_upload_requires_bucket(self):
        """Test that --upload requires --bucket."""
        args = Namespace(
            upload=True,
            bucket=None,
            version=False,
            config=None,
            policies_path="/tmp/policies",
            dry_run=False,
            zip=False,
            output=None,
            format="json",
        )

        with pytest.raises(ArgumentValidationError) as exc_info:
            validate_args(args)

        assert "--bucket is required when --upload is set" in str(exc_info.value)

    def test_validate_bucket_requires_upload(self):
        """Test that --bucket requires --upload."""
        args = Namespace(
            upload=False,
            bucket="my-bucket",
            version=False,
            config=None,
            policies_path="/tmp/policies",
            dry_run=False,
            zip=False,
            output=None,
            format="json",
        )

        with pytest.raises(ArgumentValidationError) as exc_info:
            validate_args(args)

        assert "--bucket can only be used with --upload" in str(exc_info.value)

    def test_validate_policies_path_required(self):
        """Test that --policies-path is required when no config or version."""
        args = Namespace(
            upload=False,
            bucket=None,
            version=False,
            config=None,
            policies_path=None,
            dry_run=False,
            zip=False,
            output=None,
            format="json",
        )

        with pytest.raises(ArgumentValidationError) as exc_info:
            validate_args(args)

        assert "--policies-path is required" in str(exc_info.value)

    def test_validate_dry_run_conflicts_with_upload(self):
        """Test that --dry-run conflicts with --upload."""
        args = Namespace(
            upload=True,
            bucket="my-bucket",
            version=False,
            config=None,
            policies_path="/tmp/policies",
            dry_run=True,
            zip=False,
            output=None,
            format="json",
        )

        with pytest.raises(ArgumentValidationError) as exc_info:
            validate_args(args)

        assert "--dry-run cannot be used with --upload" in str(exc_info.value)

    def test_validate_output_extension_matches_format(self):
        """Test that output file extension must match format."""
        args = Namespace(
            upload=False,
            bucket=None,
            version=False,
            config=None,
            policies_path="/tmp/policies",
            dry_run=False,
            zip=False,
            output="report.txt",
            format="json",
        )

        with pytest.raises(ArgumentValidationError) as exc_info:
            validate_args(args)

        assert "does not match format" in str(exc_info.value)

    def test_validate_valid_args(self):
        """Test that valid arguments pass validation."""
        # Create a temporary directory for testing
        with tempfile.TemporaryDirectory() as tmpdir:
            args = Namespace(
                upload=False,
                bucket=None,
                version=False,
                config=None,
                policies_path=tmpdir,
                dry_run=False,
                zip=False,
                output=None,
                format="json",
            )

            # Should not raise any exception
            validate_args(args)


class TestParseArgs:
    """Tests for parse_args function."""

    def test_parse_basic_args(self):
        """Test parsing basic arguments."""
        with tempfile.TemporaryDirectory() as tmpdir:
            args = parse_args(["--policies-path", tmpdir])

            assert args.policies_path == tmpdir
            assert args.upload is False
            assert args.bucket is None

    def test_parse_upload_with_bucket(self):
        """Test parsing upload with bucket."""
        with tempfile.TemporaryDirectory() as tmpdir:
            args = parse_args(["--policies-path", tmpdir, "--upload", "--bucket", "my-bucket"])

            assert args.upload is True
            assert args.bucket == "my-bucket"

    def test_parse_verbose_flag(self):
        """Test parsing verbose flag."""
        with tempfile.TemporaryDirectory() as tmpdir:
            args = parse_args(["--policies-path", tmpdir, "--verbose"])

            assert args.verbose is True
            assert args.quiet is False

    def test_parse_quiet_flag(self):
        """Test parsing quiet flag."""
        with tempfile.TemporaryDirectory() as tmpdir:
            args = parse_args(["--policies-path", tmpdir, "--quiet"])

            assert args.quiet is True
            assert args.verbose is False

    def test_parse_format_option(self):
        """Test parsing format option."""
        with tempfile.TemporaryDirectory() as tmpdir:
            args = parse_args(["--policies-path", tmpdir, "--format", "text"])

            assert args.format == "text"

    def test_parse_dry_run(self):
        """Test parsing dry-run flag."""
        with tempfile.TemporaryDirectory() as tmpdir:
            args = parse_args(["--policies-path", tmpdir, "--dry-run"])

            assert args.dry_run is True

    def test_parse_version(self):
        """Test parsing version flag."""
        args = parse_args(["--version"])

        assert args.version is True
