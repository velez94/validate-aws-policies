"""Integration tests for CLI argument parser with config loader."""

import tempfile
from pathlib import Path

import pytest

from validate_aws_policies.cli.args import parse_args
from validate_aws_policies.cli.config import ConfigLoader


class TestArgsConfigIntegration:
    """Tests for integration between args parser and config loader."""

    def test_args_override_config_file(self):
        """Test that CLI arguments override config file values."""
        # Create a temporary config file
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text("""
profile: config-profile
bucket_name: config-bucket
directory_policies_path: /config/path
""")

            policies_dir = Path(tmpdir) / "policies"
            policies_dir.mkdir()

            # Parse args with config file
            args = parse_args(
                [
                    "--config",
                    str(config_file),
                    "--policies-path",
                    str(policies_dir),
                    "--profile",
                    "cli-profile",
                ]
            )

            # Load config
            config_loader = ConfigLoader(config_file)
            config = config_loader.load_config()

            # CLI args should take precedence
            assert args.profile == "cli-profile"
            assert args.policies_path == str(policies_dir)

            # Config file values are loaded
            assert config["profile"] == "config-profile"
            assert config["bucket_name"] == "config-bucket"

    def test_config_provides_defaults_for_missing_args(self):
        """Test that config file provides defaults for missing CLI args."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text("""
profile: my-profile
bucket_name: my-bucket
upload_report: true
""")

            policies_dir = Path(tmpdir) / "policies"
            policies_dir.mkdir()

            # Parse args without profile or bucket
            _ = parse_args(["--config", str(config_file), "--policies-path", str(policies_dir)])

            # Load config
            config_loader = ConfigLoader(config_file)
            config = config_loader.load_config()

            # Config provides the missing values
            assert config["profile"] == "my-profile"
            assert config["bucket_name"] == "my-bucket"
            assert config["upload_report"] is True

    def test_standardized_flag_names(self):
        """Test that new standardized flag names work correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policies_dir = Path(tmpdir) / "policies"
            policies_dir.mkdir()

            # Test new flag names (hyphens instead of underscores)
            args = parse_args(
                [
                    "--policies-path",
                    str(policies_dir),
                    "--upload",
                    "--bucket",
                    "my-bucket",
                    "--zip",
                ]
            )

            assert args.policies_path == str(policies_dir)
            assert args.upload is True
            assert args.bucket == "my-bucket"
            assert args.zip is True

    def test_mutually_exclusive_verbose_quiet(self):
        """Test that --verbose and --quiet are mutually exclusive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policies_dir = Path(tmpdir) / "policies"
            policies_dir.mkdir()

            # This should fail because --verbose and --quiet are mutually exclusive
            with pytest.raises(SystemExit):
                parse_args(["--policies-path", str(policies_dir), "--verbose", "--quiet"])
