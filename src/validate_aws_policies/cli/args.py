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

from ..iam_access_analyzer.constants import FAIL_ON_LEVELS, LOCALES, RESOURCE_TYPES

try:
    import argcomplete

    ARGCOMPLETE_AVAILABLE = True
except ImportError:
    ARGCOMPLETE_AVAILABLE = False


def _csv(value: str) -> list[str]:
    """Split a comma separated argument into a list of non-empty items."""
    return [item.strip() for item in value.split(",") if item.strip()]


def _key_value(value: str) -> tuple[str, str]:
    """Parse ``KEY=VALUE`` for ``--param``."""
    if "=" not in value or value.startswith("="):
        raise argparse.ArgumentTypeError(f"expected KEY=VALUE, got '{value}'")
    key, _, text = value.partition("=")
    return key.strip(), text


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
  # Generate JUnit XML report for CI/CD
  validate-aws-policies --policies-path ./policies --format xml

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

    parser.add_argument(
        "-t",
        "--policy-type",
        choices=["identity", "resource", "scp", "rcp"],
        default=None,
        help="Type of policies in the directory (default: identity). "
        "scp = service control policy, rcp = resource control policy",
    )

    parser.add_argument(
        "--resource-type",
        type=str,
        default=None,
        metavar="TYPE",
        help="Resource type for resource policies (only with --policy-type resource): "
        + ", ".join(RESOURCE_TYPES)
        + " or an AWS::Service::Type value",
    )

    parser.add_argument(
        "--locale",
        type=str.upper,
        choices=list(LOCALES),
        default=None,
        help="Language of the finding messages (default: EN)",
    )

    parser.add_argument(
        "--max-findings",
        type=int,
        default=None,
        metavar="N",
        help="Collect at most N findings per policy (default: all)",
    )

    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Also validate *.json files in sub-directories",
    )

    # Failure handling
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Do not stop at the first ERROR finding: validate everything, write the "
        "reports, then exit with code 1 if any ERROR was found",
    )

    parser.add_argument(
        "--fail-on",
        choices=list(FAIL_ON_LEVELS),
        default=None,
        help="Exit with code 1 when a finding of this severity or higher exists "
        "(error, security-warning, warning, suggestion) or never (none). "
        "Implies --continue-on-error",
    )

    # Custom policy checks
    checks = parser.add_argument_group(
        "custom policy checks",
        "Extra IAM Access Analyzer checks for identity and resource policies. "
        "A failed check is reported as an ERROR finding and exits with code 1. "
        "AWS bills these checks per API call (about one call per policy and check, "
        "even with --dry-run); policy validation itself is free.",
    )
    checks.add_argument(
        "--check-no-new-access",
        action="store_true",
        help="Fail if a policy grants access not granted by the policy with the same file "
        "name in --reference-path",
    )
    checks.add_argument(
        "--reference-path",
        type=str,
        default=None,
        metavar="DIR",
        help="Directory with the reference (baseline) policies for --check-no-new-access",
    )
    checks.add_argument(
        "--strict-references",
        action="store_true",
        help="Treat a policy without a reference file as a failed check (default: skip it)",
    )
    checks.add_argument(
        "--check-access-not-granted",
        action="store_true",
        help="Fail if a policy grants any of --deny-actions on any of --deny-resources",
    )
    checks.add_argument(
        "--deny-actions",
        type=_csv,
        default=None,
        metavar="A,B",
        help="Comma separated actions that must not be granted (for example iam:*,s3:Delete*)",
    )
    checks.add_argument(
        "--deny-resources",
        type=_csv,
        default=None,
        metavar="ARN,ARN",
        help="Comma separated resource ARNs that must not be accessible",
    )
    checks.add_argument(
        "--check-no-public-access",
        type=str,
        default=None,
        metavar="RESOURCE_TYPE",
        help="Fail if a resource policy can grant public access to this resource type "
        "(for example s3-bucket, kms-key, sqs-queue or AWS::S3::Bucket). "
        "Use with --policy-type resource",
    )

    # Infrastructure as code inputs
    iac = parser.add_argument_group(
        "infrastructure as code inputs",
        "Validate the policies of a Terraform/OpenTofu plan, CloudFormation or CDK template, "
        "or Pulumi preview/export instead of policy files. The policy types are decided by "
        "the resource types, so --policy-type and --resource-type are not used.",
    )
    iac.add_argument(
        "-i",
        "--input",
        nargs="+",
        default=None,
        metavar="PATH",
        help="Plan JSON (terraform show -json), template, Pulumi JSON, or a directory of "
        "templates. Replaces --policies-path",
    )
    iac.add_argument(
        "--source",
        choices=["auto", "terraform-plan", "cloudformation", "pulumi"],
        default=None,
        help="Format of --input (default: auto, detected from the content)",
    )
    iac.add_argument(
        "--reference-input",
        nargs="+",
        default=None,
        metavar="PATH",
        help="Baseline plan/template (for example from the main branch) for "
        "--check-no-new-access. Policies are matched by id",
    )
    iac.add_argument(
        "--param",
        action="append",
        type=_key_value,
        default=None,
        metavar="KEY=VALUE",
        help="CloudFormation parameter value (repeatable)",
    )
    iac.add_argument(
        "--unknown-values",
        choices=["skip", "fail"],
        default=None,
        help="Policies whose value is not known before deployment: skip them with a "
        "warning (default) or exit with code 1 after validating the rest",
    )
    iac.add_argument(
        "--only-changed",
        action="store_true",
        help="Terraform and Pulumi: only policies of resources that are created or updated",
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
        choices=["json", "text", "html", "md", "markdown", "xml", "junit", "sarif", "all"],
        default=None,
        help="Output format for validation results (default: json). "
        "Use xml/junit for CI/CD and sarif for code scanning tools. "
        "'all' writes html, md and xml",
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
        help="Reserved for CI/CD pipelines. Currently has no effect on behavior; use "
        "--fail-on, --format xml/sarif and --log-format json for pipelines",
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
        default=None,
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

    input_paths = getattr(args, "input", None)
    if input_paths and args.policies_path:
        errors.append("--input cannot be combined with --policies-path")

    # Validate policies-path is required unless --version, --config or --input is provided
    if not args.version and not args.config and not args.policies_path and not input_paths:
        errors.append("--policies-path is required (or use --input or --config)")

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

    # Validate custom check inputs that can be verified without the config file
    reference_path = getattr(args, "reference_path", None)
    if reference_path and not Path(reference_path).is_dir():
        errors.append(f"Reference path is not a directory: {reference_path}")

    max_findings = getattr(args, "max_findings", None)
    if max_findings is not None and max_findings < 1:
        errors.append("--max-findings must be a positive integer")

    # Validate --dry-run conflicts
    if args.dry_run:
        if args.upload:
            errors.append("--dry-run cannot be used with --upload")
        if args.zip:
            errors.append("--dry-run cannot be used with --zip")

    # Validate output file extension matches format
    if args.output and (args.format or "json") == "all":
        errors.append("--output cannot be used with --format all (it writes several files)")
    elif args.output:
        output_format = args.format or "json"
        output_path = Path(args.output)
        # Map format to expected extension (junit -> xml)
        format_to_ext = {
            "json": ".json",
            "text": ".text",
            "html": ".html",
            "md": ".md",
            "markdown": ".md",
            "xml": ".xml",
            "junit": ".xml",
            "sarif": ".sarif",
        }
        expected_ext = format_to_ext.get(output_format, f".{output_format}")
        allowed_ext = {expected_ext}
        if output_format == "text":
            allowed_ext.add(".txt")
        if output_format == "sarif":
            allowed_ext.add(".json")
        if output_path.suffix.lower() not in allowed_ext:
            errors.append(
                f"Output file extension {output_path.suffix} does not match "
                f"format {output_format} (expected {' or '.join(sorted(allowed_ext))})"
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
