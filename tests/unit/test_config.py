"""Unit tests for cli.config module."""

import os
from unittest.mock import patch

import pytest

from validate_aws_policies.cli.config import ConfigError, ConfigLoader


class TestConfigLoader:
    """Test suite for ConfigLoader class."""

    def test_load_defaults(self):
        """Test loading default configuration values."""
        loader = ConfigLoader()
        config = loader.load_config()

        assert config["profile"] is None
        assert config["bucket_name"] is None
        assert config["directory_policies_path"] == "./policies"
        assert config["upload_report"] is False
        assert config["zip_reports"] is False
        assert config["ci"] is False
        assert config["log_level"] == "INFO"

    def test_load_env_vars(self):
        """Test loading configuration from environment variables."""
        env_vars = {
            "AWS_PROFILE": "test-profile",
            "REPORTS_BUCKET": "test-bucket",
            "POLICIES_PATH": "/test/policies",
            "LOG_LEVEL": "DEBUG",
        }

        with patch.dict(os.environ, env_vars, clear=False):
            loader = ConfigLoader()
            config = loader.load_config()

            assert config["profile"] == "test-profile"
            assert config["bucket_name"] == "test-bucket"
            assert config["directory_policies_path"] == "/test/policies"
            assert config["log_level"] == "DEBUG"

    def test_env_vars_override_defaults(self):
        """Test that environment variables override default values."""
        with patch.dict(os.environ, {"AWS_PROFILE": "env-profile"}, clear=False):
            loader = ConfigLoader()
            config = loader.load_config()

            # Env var should override default
            assert config["profile"] == "env-profile"
            # Other defaults should remain
            assert config["directory_policies_path"] == "./policies"

    def test_config_file_not_found(self):
        """Test error handling when config file doesn't exist."""
        loader = ConfigLoader(config_file="/nonexistent/config.yaml")

        with pytest.raises(ConfigError, match="Configuration file not found"):
            loader.load_config()

    def test_unsupported_config_format(self, tmp_path):
        """Test error handling for unsupported config file formats."""
        config_file = tmp_path / "config.json"
        config_file.write_text('{"profile": "test"}')

        loader = ConfigLoader(config_file=config_file)

        with pytest.raises(ConfigError, match="Unsupported config file format"):
            loader.load_config()

    def test_load_yaml_config(self, tmp_path):
        """Test loading configuration from YAML file."""
        config_file = tmp_path / "config.yaml"
        config_content = """
profile: yaml-profile
bucket_name: yaml-bucket
directory_policies_path: /yaml/policies
upload_report: true
"""
        config_file.write_text(config_content)

        loader = ConfigLoader(config_file=config_file)
        config = loader.load_config()

        assert config["profile"] == "yaml-profile"
        assert config["bucket_name"] == "yaml-bucket"
        assert config["directory_policies_path"] == "/yaml/policies"
        assert config["upload_report"] is True

    def test_load_toml_config(self, tmp_path):
        """Test loading configuration from TOML file."""
        config_file = tmp_path / "config.toml"
        config_content = """
profile = "toml-profile"
bucket_name = "toml-bucket"
directory_policies_path = "/toml/policies"
upload_report = true
"""
        config_file.write_text(config_content)

        loader = ConfigLoader(config_file=config_file)
        config = loader.load_config()

        assert config["profile"] == "toml-profile"
        assert config["bucket_name"] == "toml-bucket"
        assert config["directory_policies_path"] == "/toml/policies"
        assert config["upload_report"] is True

    def test_precedence_order(self, tmp_path):
        """Test configuration precedence: defaults < file < env vars."""
        # Create config file
        config_file = tmp_path / "config.yaml"
        config_content = """
profile: file-profile
bucket_name: file-bucket
directory_policies_path: /file/policies
"""
        config_file.write_text(config_content)

        # Set environment variable (should override file)
        with patch.dict(os.environ, {"AWS_PROFILE": "env-profile"}, clear=False):
            loader = ConfigLoader(config_file=config_file)
            config = loader.load_config()

            # Env var should override file
            assert config["profile"] == "env-profile"
            # File should override default
            assert config["bucket_name"] == "file-bucket"
            assert config["directory_policies_path"] == "/file/policies"
            # Default should be used when not in file or env
            assert config["upload_report"] is False

    def test_invalid_yaml(self, tmp_path):
        """Test error handling for invalid YAML."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("invalid: yaml: content:")

        loader = ConfigLoader(config_file=config_file)

        with pytest.raises(ConfigError, match="Invalid YAML"):
            loader.load_config()

    def test_invalid_toml(self, tmp_path):
        """Test error handling for invalid TOML."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("invalid toml content [[[")

        loader = ConfigLoader(config_file=config_file)

        with pytest.raises(ConfigError, match="Invalid TOML"):
            loader.load_config()

    def test_get_method(self):
        """Test get method for retrieving config values."""
        loader = ConfigLoader()
        loader.load_config()

        assert loader.get("profile") is None
        assert loader.get("nonexistent", "default") == "default"
        assert loader.get("log_level") == "INFO"

    def test_dict_access(self):
        """Test dictionary-like access to config values."""
        loader = ConfigLoader()
        loader.load_config()

        assert loader["log_level"] == "INFO"
        assert "profile" in loader
        assert "nonexistent" not in loader

        with pytest.raises(KeyError):
            _ = loader["nonexistent"]

    def test_empty_yaml_file(self, tmp_path):
        """Test handling of empty YAML file."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("")

        loader = ConfigLoader(config_file=config_file)
        config = loader.load_config()

        # Should fall back to defaults
        assert config["directory_policies_path"] == "./policies"

    def test_partial_env_vars(self):
        """Test that only set environment variables are loaded."""
        with patch.dict(os.environ, {"AWS_PROFILE": "test-profile"}, clear=True):
            loader = ConfigLoader()
            config = loader.load_config()

            # Only AWS_PROFILE should be set from env
            assert config["profile"] == "test-profile"
            # Others should be defaults
            assert config["bucket_name"] is None
            assert config["directory_policies_path"] == "./policies"
