"""Configuration management module for validate-aws-policies CLI.

This module provides configuration loading from multiple sources with precedence:
1. Default values (lowest priority)
2. Config file (YAML/TOML)
3. Environment variables
4. CLI arguments (highest priority - handled by argparse)
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Union

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised when configuration loading fails."""

    pass


class ConfigLoader:
    """Load and manage configuration from multiple sources.

    Supports loading configuration from:
    - Default values
    - YAML/TOML configuration files
    - Environment variables
    - CLI arguments (via argparse)

    Environment variables supported:
    - AWS_PROFILE: AWS profile name
    - REPORTS_BUCKET: S3 bucket for report uploads
    - POLICIES_PATH: Directory containing policy files
    - LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR)
    """

    # Environment variable mappings
    ENV_VAR_MAP = {
        "AWS_PROFILE": "profile",
        "REPORTS_BUCKET": "bucket_name",
        "POLICIES_PATH": "directory_policies_path",
        "LOG_LEVEL": "log_level",
    }

    def __init__(self, config_file: Optional[Union[str, Path]] = None):
        """Initialize ConfigLoader.

        Args:
            config_file: Optional path to configuration file (YAML or TOML)
        """
        self.config_file = Path(config_file) if config_file else None
        self._config: Dict[str, Any] = {}

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from all sources with proper precedence.

        Precedence order (lowest to highest):
        1. Default values
        2. Config file
        3. Environment variables

        Returns:
            Dictionary containing merged configuration

        Raises:
            ConfigError: If config file is specified but cannot be loaded
        """
        # Start with defaults
        self._config = self._load_defaults()

        # Override with config file if provided
        if self.config_file:
            file_config = self._load_file()
            self._config.update(file_config)

        # Override with environment variables
        env_config = self._load_env_vars()
        self._config.update(env_config)

        logger.debug(f"Loaded configuration: {self._config}")
        return self._config

    def _load_defaults(self) -> Dict[str, Any]:
        """Load default configuration values.

        Returns:
            Dictionary containing default configuration values
        """
        return {
            "profile": None,
            "bucket_name": None,
            "directory_policies_path": "./policies",
            "upload_report": False,
            "zip_reports": False,
            "ci": False,
            "log_level": "INFO",
        }

    def _load_file(self) -> Dict[str, Any]:
        """Load configuration from YAML or TOML file.

        Returns:
            Dictionary containing file configuration

        Raises:
            ConfigError: If file cannot be read or parsed
        """
        if not self.config_file or not self.config_file.exists():
            raise ConfigError(f"Configuration file not found: {self.config_file}")

        file_ext = self.config_file.suffix.lower()

        try:
            if file_ext in [".yaml", ".yml"]:
                return self._load_yaml()
            elif file_ext == ".toml":
                return self._load_toml()
            else:
                raise ConfigError(
                    f"Unsupported config file format: {file_ext}. "
                    "Supported formats: .yaml, .yml, .toml"
                )
        except Exception as e:
            raise ConfigError(f"Failed to load config file {self.config_file}: {e}") from e

    def _load_yaml(self) -> Dict[str, Any]:
        """Load configuration from YAML file.

        Returns:
            Dictionary containing YAML configuration

        Raises:
            ConfigError: If YAML parsing fails or pyyaml is not installed
        """
        try:
            import yaml
        except ImportError:
            raise ConfigError(
                "PyYAML is required to load YAML config files. Install it with: pip install pyyaml"
            ) from None

        if self.config_file is None:
            raise ConfigError("No config file specified")

        try:
            with self.config_file.open("r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
                return config if config else {}
        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML in config file: {e}") from e

    def _load_toml(self) -> Dict[str, Any]:
        """Load configuration from TOML file.

        Returns:
            Dictionary containing TOML configuration

        Raises:
            ConfigError: If TOML parsing fails or tomli is not installed
        """
        try:
            # Python 3.11+ has tomllib in stdlib
            try:
                import tomllib
            except ImportError:
                import tomli as tomllib
        except ImportError:
            raise ConfigError(
                "tomli is required to load TOML config files on Python < 3.11. "
                "Install it with: pip install tomli"
            ) from None

        if self.config_file is None:
            raise ConfigError("No config file specified")

        try:
            with self.config_file.open("rb") as f:
                config = tomllib.load(f)
                return config  # type: ignore[no-any-return]
        except Exception as e:
            raise ConfigError(f"Invalid TOML in config file: {e}") from e

    def _load_env_vars(self) -> Dict[str, Any]:
        """Load configuration from environment variables.

        Supported environment variables:
        - AWS_PROFILE: AWS profile name
        - REPORTS_BUCKET: S3 bucket for report uploads
        - POLICIES_PATH: Directory containing policy files
        - LOG_LEVEL: Logging level

        Returns:
            Dictionary containing environment variable configuration
        """
        env_config = {}

        for env_var, config_key in self.ENV_VAR_MAP.items():
            value = os.getenv(env_var)
            if value is not None:
                env_config[config_key] = value
                logger.debug(f"Loaded {config_key} from environment variable {env_var}")

        return env_config

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key.

        Args:
            key: Configuration key
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        return self._config.get(key, default)

    def __getitem__(self, key: str) -> Any:
        """Get configuration value by key using dict-like access.

        Args:
            key: Configuration key

        Returns:
            Configuration value

        Raises:
            KeyError: If key not found
        """
        return self._config[key]

    def __contains__(self, key: str) -> bool:
        """Check if configuration key exists.

        Args:
            key: Configuration key

        Returns:
            True if key exists, False otherwise
        """
        return key in self._config
