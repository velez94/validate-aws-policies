"""CLI module for AWS policy validation.

This module provides command-line interface components including:
- Argument parsing with validation
- Configuration management
- Exit codes for error handling
"""

from .args import ArgumentValidationError, create_parser, parse_args, validate_args
from .config import ConfigError, ConfigLoader
from .exit_codes import (
    EXIT_AWS_ERROR,
    EXIT_CONFIG_ERROR,
    EXIT_FILE_ERROR,
    EXIT_SUCCESS,
    EXIT_VALIDATION_ERROR,
)

__all__ = [
    # Argument parsing
    "create_parser",
    "validate_args",
    "parse_args",
    "ArgumentValidationError",
    # Configuration
    "ConfigLoader",
    "ConfigError",
    # Exit codes
    "EXIT_SUCCESS",
    "EXIT_VALIDATION_ERROR",
    "EXIT_CONFIG_ERROR",
    "EXIT_AWS_ERROR",
    "EXIT_FILE_ERROR",
]
