"""Main entry point for AWS policy validation CLI."""

import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from colorama import Fore

from .cli.args import ArgumentValidationError, parse_args
from .cli.config import ConfigError, ConfigLoader
from .cli.exit_codes import (
    EXIT_AWS_ERROR,
    EXIT_CONFIG_ERROR,
    EXIT_FILE_ERROR,
    EXIT_SUCCESS,
    EXIT_VALIDATION_ERROR,
)
from .cli.validation import apply_checks_section, validate_merged_config
from .core.validator import PolicyValidator
from .iam_access_analyzer.features import SdkFeatureError
from .version import __version__


def setup_logging(verbose: bool = False, quiet: bool = False, log_format: str = "text") -> None:
    """Configure logging based on verbosity flags.

    Args:
        verbose: Enable DEBUG level logging
        quiet: Enable ERROR level logging only
        log_format: Log format ('text' or 'json')
    """
    # Determine log level
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.ERROR
    else:
        level = logging.INFO

    # Configure format
    if log_format == "json":
        import json as json_module

        class JSONFormatter(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                log_data = {
                    "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                    "level": record.levelname,
                    "message": record.getMessage(),
                    "module": record.module,
                    "function": record.funcName,
                }
                if record.exc_info:
                    log_data["exception"] = self.formatException(record.exc_info)
                return json_module.dumps(log_data)

        formatter = JSONFormatter()  # type: logging.Formatter
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)


def merge_config(args: Any) -> Dict[str, Any]:
    """Merge configuration from multiple sources with proper precedence.

    Precedence order (lowest to highest):
    1. Default values (in ConfigLoader)
    2. Config file (if --config provided)
    3. Environment variables
    4. CLI arguments (highest priority)

    Args:
        args: Parsed command-line arguments

    Returns:
        Merged configuration dictionary

    Raises:
        ConfigError: If config file loading fails
    """
    # Load config from file and environment variables
    config_loader = ConfigLoader(config_file=args.config)
    config = config_loader.load_config()
    apply_checks_section(config)

    # Override with CLI arguments, only when they were explicitly provided.
    # Boolean flags are store_true, so False means "not given" and must not
    # replace a value from the config file or environment.
    if args.policies_path:
        config["policies_path"] = args.policies_path
        config["directory_policies_path"] = args.policies_path

    if args.profile:
        config["profile"] = args.profile

    config["policy_type"] = args.policy_type or config.get("policy_type") or "identity"

    # Options added in 3.2: value options only override when given; flags only when set.
    for key in (
        "resource_type",
        "locale",
        "max_findings",
        "fail_on",
        "reference_path",
        "check_no_public_access",
        "deny_actions",
        "deny_resources",
    ):
        value = getattr(args, key, None)
        if value is not None:
            config[key] = value
    for key in (
        "recursive",
        "continue_on_error",
        "check_no_new_access",
        "strict_references",
        "check_access_not_granted",
    ):
        if getattr(args, key, False) is True:
            config[key] = True
        else:
            config.setdefault(key, False)

    if args.bucket:
        config["bucket_name"] = args.bucket

    for key in ("upload", "zip", "ci", "dry_run"):
        if getattr(args, key):
            config[key] = True
        else:
            config.setdefault(key, False)
    config["upload_report"] = config["upload"]
    config["zip_reports"] = config["zip"]

    # Output configuration
    config["format"] = args.format or config.get("format") or "json"
    if args.output:
        config["output"] = args.output

    # Logging configuration
    config["verbose"] = args.verbose
    config["quiet"] = args.quiet
    config["log_format"] = args.log_format or config.get("log_format") or "text"

    return config


def main() -> int:
    """Main entry point for AWS policy validation CLI.

    Returns:
        Exit code:
            0 - Success
            1 - Validation error
            2 - Configuration error
            3 - AWS API error
            4 - File I/O error
    """
    try:
        # Parse command-line arguments
        args = parse_args()

        # Handle --version flag
        if args.version:
            print(f"validate-aws-policies version {__version__}")
            return EXIT_SUCCESS

        # Setup logging before anything else
        setup_logging(
            verbose=args.verbose,
            quiet=args.quiet,
            log_format=args.log_format,
        )

        logger = logging.getLogger(__name__)
        logger.debug(f"Starting validate-aws-policies v{__version__}")

        # Merge configuration from all sources
        try:
            config = merge_config(args)
            logger.debug(f"Merged configuration: {config}")
        except ConfigError as e:
            logger.error(f"Configuration error: {e}")
            return EXIT_CONFIG_ERROR

        # Validate required configuration
        if not config.get("policies_path"):
            logger.error("Policies path is required")
            return EXIT_CONFIG_ERROR

        config_errors = validate_merged_config(config)
        if config_errors:
            for message in config_errors:
                logger.error(f"Configuration error: {message}")
            return EXIT_CONFIG_ERROR

        if config.get("upload") and not config.get("bucket_name"):
            logger.error("An S3 bucket is required to upload reports (--bucket or bucket_name)")
            return EXIT_CONFIG_ERROR

        if config.get("upload") and config.get("dry_run"):
            logger.error("dry_run cannot be combined with upload")
            return EXIT_CONFIG_ERROR

        # Setup AWS session with profile if provided
        if config.get("profile"):
            try:
                boto3.setup_default_session(profile_name=config["profile"])
                logger.info(f"Using AWS profile: {config['profile']}")
            except Exception as e:
                logger.error(f"Failed to setup AWS profile '{config['profile']}': {e}")
                return EXIT_CONFIG_ERROR

        # Run validation workflow
        validator = PolicyValidator(config)
        exit_code = validator.run()

        if exit_code == EXIT_SUCCESS:
            logger.info("Validation completed successfully")
        else:
            logger.error(f"Validation failed with exit code {exit_code}")

        return exit_code

    except ArgumentValidationError as e:
        # This should be caught by parse_args, but handle it just in case
        print(f"{Fore.RED}Error: {e}{Fore.RESET}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    except (ConfigError, SdkFeatureError) as e:
        print(f"{Fore.RED}Configuration error: {e}{Fore.RESET}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    except (ClientError, BotoCoreError) as e:
        print(f"{Fore.RED}AWS API error: {e}{Fore.RESET}", file=sys.stderr)
        return EXIT_AWS_ERROR

    except FileNotFoundError as e:
        print(f"{Fore.RED}File not found: {e}{Fore.RESET}", file=sys.stderr)
        return EXIT_FILE_ERROR

    except PermissionError as e:
        print(f"{Fore.RED}Permission denied: {e}{Fore.RESET}", file=sys.stderr)
        return EXIT_FILE_ERROR

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted by user{Fore.RESET}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {e}{Fore.RESET}", file=sys.stderr)
        logging.exception("Unexpected error occurred")
        return EXIT_VALIDATION_ERROR


if __name__ == "__main__":
    sys.exit(main())
