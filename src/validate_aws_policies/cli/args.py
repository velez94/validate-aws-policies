"""Argument parser for the AWS policy validation CLI.

This module provides argument parsing with:
- Standardized flag names (using hyphens, not underscores)
- Argument validation for required combinations
- Mutually exclusive groups (--verbose/--quiet)
- Support for config files, dry-run mode, and output formats
- Integration with argcomplete for tab completion
"""

import argparse
from pathlib import Path
from typing import Optional

try:
    import argcomplete

    ARGCOMPLETE_AVAILABLE = True
except ImportError:
    ARGCOMPLETE_AVAILABLE = False


class ArgumentValidationError(Exception):
    """Raised when argument validation fails."""

    pass


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser.

    Returns:
        Configured ArgumentParser instance with all CLI arguments
    """
    parser = argparse.ArgumentParser(
        prog="validate-aws-policies",
        description="Validate AWS IAM policies using IAM Access Analyzer API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic validation
  validate-aws-policies --policies-path ./policies

  # Validate and create reports
  validate-aws-policies --policies-path ./policies --format html --zip

  # Upload reports to S3
  validate-aws-policies --policies-path ./policies --upload --bucket my-bucket

  # Use config file
  validate-aws-policies --config config.yaml

  # Dry run mode (validate without creating reports)
  validate-aws-policies --policies-path ./policies --dry-run

  # Verbose output
  validate-aws-policies --policies-path ./policies --verbose
        """,
    )

    # Version argument
    parser.add_argument(
        "-v", "--version", action="store_true", help="Print the package version and exit"
    )

    # Configuration file
    parser.add_argument(
        "--config",
        type=str,
        metavar="FILE",
        help="Path to configuration file (YAML or TOML format)",
    )

    # Policy input
    parser.add_argument(
        "-d",
        "--policies-path",
        type=str,
        metavar="PATH",
        help="Directory path containing policy files in JSON format",
    )

    # AWS configuration
    parser.add_argument(
        "-p",
        "--profile",
        type=str,
        metavar="NAME",
        help="AWS CLI profile name for Access Analyzer API (default: uses default profile)",
    )

    # Output format and location
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "text", "html", "md", "markdown"],
        default="json",
        help="Output format for validation results (default: json)",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        metavar="FILE",
        help="Output file path (default: stdout for json/text, file for html/md)",
    )

    # Report generation flags

    parser.add_argument(
        "-z", "--zip", action="store_true", help="Create ZIP archive of generated reports"
    )

    # S3 upload configuration
    parser.add_argument(
        "-u", "--upload", action="store_true", help="Upload generated reports to S3 bucket"
    )

    parser.add_argument(
        "-b",
        "--bucket",
        type=str,
        metavar="NAME",
        help="S3 bucket name for report uploads (required when --upload is set)",
    )

    # Execution modes
    parser.add_argument(
        "-c",
        "--ci",
        action="store_true",
        help="Run in CI/CD pipeline mode (non-interactive, strict validation)",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate policies without creating reports or uploading to S3",
    )

    # Logging configuration - mutually exclusive group
    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument(
        "--verbose", action="store_true", help="Enable verbose output (DEBUG level logging)"
    )

    log_group.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-essential output (ERROR level logging only)",
    )

    parser.add_argument(
        "--log-format",
        choices=["text", "json"],
        default="text",
        help="Log output format (default: text)",
    )

    # Enable argcomplete if available
    if ARGCOMPLETE_AVAILABLE:
        argcomplete.autocomplete(parser)

    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Validate argument combinations and requirements.

    Args:
        args: Parsed arguments from ArgumentParser

    Raises:
        ArgumentValidationError: If argument validation fails
    """
    errors = []

    # Validate --upload requires --bucket
    if args.upload and not args.bucket:
        errors.append("--bucket is required when --upload is set")

    # Validate --bucket only makes sense with --upload
    if args.bucket and not args.upload:
        errors.append("--bucket can only be used with --upload")

    # Validate policies-path is required unless --version or --config is provided
    if not args.version and not args.config and not args.policies_path:
        errors.append("--policies-path is required (or use --config to specify it)")

    # Validate policies-path exists if provided
    if args.policies_path:
        policies_path = Path(args.policies_path)
        if not policies_path.exists():
            errors.append(f"Policies path does not exist: {args.policies_path}")
        elif not policies_path.is_dir():
            errors.append(f"Policies path is not a directory: {args.policies_path}")

    # Validate config file exists if provided
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            errors.append(f"Config file does not exist: {args.config}")
        elif not config_path.is_file():
            errors.append(f"Config path is not a file: {args.config}")

        # Validate config file extension
        if config_path.suffix.lower() not in [".yaml", ".yml", ".toml"]:
            errors.append(
                f"Unsupported config file format: {config_path.suffix}. "
                "Supported formats: .yaml, .yml, .toml"
            )

    # Validate --dry-run conflicts
    if args.dry_run:
        if args.upload:
            errors.append("--dry-run cannot be used with --upload")
        if args.zip:
            errors.append("--dry-run cannot be used with --zip")

    # Validate output file extension matches format
    if args.output and args.format:
        output_path = Path(args.output)
        expected_ext = f".{args.format}"
        if output_path.suffix.lower() != expected_ext:
            errors.append(
                f"Output file extension {output_path.suffix} does not match "
                f"format {args.format} (expected {expected_ext})"
            )

    # If there are validation errors, raise exception
    if errors:
        error_msg = "Argument validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
        raise ArgumentValidationError(error_msg)


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    """Parse and validate command-line arguments.

    Args:
        argv: Optional list of arguments to parse (default: sys.argv[1:])

    Returns:
        Validated Namespace object containing parsed arguments

    Raises:
        SystemExit: If argument parsing or validation fails
    """
    parser = create_parser()
    args = parser.parse_args(argv)

    try:
        validate_args(args)
    except ArgumentValidationError as e:
        parser.error(str(e))

    return args
