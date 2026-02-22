# Implementation Plan: CLI & Developer Improvements

## Overview

This implementation refactors the AWS policy validation CLI tool to improve error handling, logging, configuration management, code quality, and testing. The work is organized into phases: infrastructure setup, core refactoring, testing, and cleanup.

## Tasks

- [x] 1. Set up new module structure and core infrastructure
  - Create new directory structure: `cli/`, `core/`, refactor `ops/`
  - Create `__init__.py` files for all new modules
  - _Requirements: All (foundational)_

- [x] 2. Implement exit codes module
  - [x] 2.1 Create `cli/exit_codes.py` with exit code constants
    - Define EXIT_SUCCESS, EXIT_VALIDATION_ERROR, EXIT_CONFIG_ERROR, EXIT_AWS_ERROR, EXIT_FILE_ERROR
    - _Requirements: 1.1-1.6_

- [x] 3. Implement configuration management
  - [x] 3.1 Create `cli/config.py` with ConfigLoader class
    - Implement `load_config()` method with precedence handling
    - Implement `_load_defaults()` for default values
    - Implement `_load_file()` for YAML/TOML parsing
    - Implement `_load_env_vars()` for environment variable support
    - _Requirements: 4.1-4.5, 7.1-7.4_
  
  - [x]* 3.2 Write unit tests for configuration loader
    - Test YAML config loading
    - Test TOML config loading
    - Test environment variable precedence
    - Test CLI argument precedence
    - Test invalid config file handling
    - _Requirements: 4.1-4.5, 7.1-7.4_

- [x] 4. Implement argument parser with validation
  - [x] 4.1 Create `cli/args.py` with argument parser
    - Implement `create_parser()` with all CLI arguments
    - Implement `validate_args()` for argument validation
    - Add mutually exclusive groups for --verbose/--quiet
    - Standardize flag names (--pdf, --zip, --upload, --bucket, --policies-path)
    - _Requirements: 2.1-2.5, 3.1-3.6, 5.1-5.4, 6.1-6.4, 8.1-8.5_
  
  - [ ]* 4.2 Write unit tests for argument parser
    - Test required argument validation
    - Test mutually exclusive flags
    - Test upload/bucket validation
    - Test invalid argument combinations
    - _Requirements: 6.1-6.4_

- [x] 5. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Refactor file operations module
  - [x] 6.1 Refactor `ops/ops.py` to use pathlib and context managers
    - Update `read_policies()` to use Path and context managers
    - Update `validate_findings()` with type hints and structured logging
    - Remove suspicious `from psutil.tests.test_process_all import proc_info` import
    - Replace print statements with logging calls
    - _Requirements: 9.1-9.3, 10.1-10.3_
  
  - [x] 6.2 Add retry logic to `upload_file()` function
    - Implement exponential backoff retry mechanism
    - Add boto3 Config with adaptive retry mode
    - Update function signature with type hints
    - _Requirements: 11.1-11.3_
  
  - [ ]* 6.3 Write unit tests for file operations
    - Test read_policies with valid and invalid paths
    - Test validate_findings with various finding types
    - Test upload_file retry logic with mocked S3
    - _Requirements: 9.1-9.3, 11.1-11.3_

- [x] 7. Extract report generation into dedicated module
  - [x] 7.1 Create `ops/reports.py` with ReportGenerator class
    - Implement `create_html_report()` method
    - Implement `create_pdf_report()` method
    - Implement `create_zip()` method
    - Use pathlib throughout
    - Add structured logging
    - _Requirements: 3.1-3.6_
  
  - [ ]* 7.2 Write unit tests for report generation
    - Test HTML report creation
    - Test PDF report creation
    - Test ZIP archive creation
    - _Requirements: 3.1-3.6_

- [x] 8. Refactor IAM Access Analyzer module
  - [x] 8.1 Update `iam_access_analyzer/iam_access_analyzer.py`
    - Add comprehensive type hints to `validate_policies()`
    - Add structured error handling for ClientError and FileNotFoundError
    - Replace print statements with logging
    - Update to use pathlib Path objects
    - _Requirements: 1.1-1.6, 10.1-10.3_
  
  - [ ]* 8.2 Write unit tests for IAM analyzer
    - Test validate_policies with mocked AWS API (using moto)
    - Test error handling for AWS API failures
    - Test error handling for missing policy files
    - _Requirements: 1.1-1.6_

- [x] 9. Implement core validator orchestrator
  - [x] 9.1 Create `core/validator.py` with PolicyValidator class
    - Implement `run()` method with workflow orchestration
    - Implement `_get_policy_files()` helper
    - Implement `_output_results()` with format handling (json, text)
    - Implement `_format_text_output()` for human-readable output
    - Implement `_generate_reports()` with dry-run support
    - Implement `_upload_reports()` with S3 integration
    - Add proper exit code returns for all error types
    - _Requirements: 1.1-1.6, 3.1-3.6, 5.1-5.4_
  
  - [ ]* 9.2 Write unit tests for validator orchestrator
    - Test successful validation workflow
    - Test dry-run mode (no files created, no uploads)
    - Test different output formats (json, text)
    - Test error handling and exit codes
    - _Requirements: 1.1-1.6, 5.1-5.4_

- [x] 10. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 11. Refactor main entry point
  - [x] 11.1 Update `validate_policies.py` main function
    - Implement `setup_logging()` function with verbosity control
    - Refactor `main()` to use new modules (ConfigLoader, PolicyValidator)
    - Implement configuration merging (config file → env vars → CLI args)
    - Add proper exception handling with specific exit codes
    - Handle --version flag
    - _Requirements: All requirements integrated_
  
  - [ ]* 11.2 Write integration tests for CLI
    - Test end-to-end validation workflow
    - Test configuration precedence (file < env < CLI)
    - Test all exit codes with different error scenarios
    - Test --dry-run flag behavior
    - Test --verbose and --quiet flags
    - _Requirements: All_

- [x] 12. Update project dependencies
  - [x] 12.1 Update `pyproject.toml` with new dependencies
    - Add pyyaml>=6.0.0,<7.0.0
    - Add tomli>=2.0.0,<3.0.0 (for Python <3.11)
    - Add dev dependencies: pytest, pytest-cov, pytest-mock, moto, ruff, mypy, types-pyyaml
    - Add version constraints to existing dependencies
    - _Requirements: 4.1-4.5_

- [x] 13. Add code quality tooling
  - [x] 13.1 Update `.pre-commit-config.yaml` with enhanced hooks
    - Add ruff for linting and formatting
    - Add mypy for type checking
    - Add standard pre-commit hooks (trailing-whitespace, end-of-file-fixer, etc.)
    - _Requirements: 10.1-10.3_
  
  - [x] 13.2 Create `ruff.toml` or add ruff config to `pyproject.toml`
    - Configure line length, target version
    - Enable relevant lint rules (E, W, F, I, B, C4, UP)
    - _Requirements: 10.1-10.3_
  
  - [x] 13.3 Add mypy configuration to `pyproject.toml`
    - Set strict mode or appropriate strictness level
    - Configure exclude patterns
    - _Requirements: 10.1-10.3_

- [x] 14. Create test infrastructure
  - [x] 14.1 Create test directory structure
    - Create `tests/` directory with `unit/`, `integration/`, `fixtures/` subdirectories
    - Create `conftest.py` with pytest fixtures
    - Create sample policy files in `fixtures/sample_policies/`
    - Create sample config files in `fixtures/config_files/`
    - _Requirements: 12.1-12.3_
  
  - [x] 14.2 Add pytest configuration to `pyproject.toml`
    - Configure test paths, coverage settings
    - Set coverage target to >80%
    - _Requirements: 12.1-12.3_

- [x] 15. Final checkpoint and validation
  - [x] 15.1 Run all tests and verify coverage
    - Execute pytest with coverage report
    - Verify >80% code coverage
    - _Requirements: All_
  
  - [ ] 15.2 Run code quality checks
    - Execute ruff check and format
    - Execute mypy type checking
    - Fix any issues found
    - _Requirements: 10.1-10.3_
  
  - [x] 15.3 Manual testing of CLI
    - Test basic validation workflow
    - Test all CLI flags and combinations
    - Test configuration file loading
    - Test environment variable support
    - Verify exit codes for different scenarios
    - _Requirements: All_

## Notes

- Tasks marked with `*` are optional testing tasks and can be skipped for faster MVP
- Each implementation task references specific requirements for traceability
- Checkpoints ensure incremental validation throughout the implementation
- The refactoring maintains backward compatibility where possible, with clear migration notes for breaking changes
- All new code includes type hints and uses modern Python best practices (pathlib, context managers, structured logging)
