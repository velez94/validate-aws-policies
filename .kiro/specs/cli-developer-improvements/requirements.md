# Requirements Document

## Introduction

This document specifies requirements for improving the AWS policy validation CLI tool to meet production-ready standards. The improvements focus on error handling, logging, configuration management, testing infrastructure, code quality tooling, and developer experience enhancements.

## Glossary

- **CLI_Tool**: The AWS policy validation command-line interface application
- **Exit_Code**: Integer value returned by the CLI_Tool to indicate execution status
- **Logger**: The logging subsystem that outputs diagnostic messages
- **Config_File**: YAML or TOML file containing CLI_Tool configuration settings
- **Test_Suite**: Collection of automated tests validating CLI_Tool behavior
- **Type_Checker**: Static analysis tool (mypy) that validates type annotations
- **Linter**: Code quality tool (ruff) that enforces style and detects issues
- **Pre_Commit_Hook**: Automated check that runs before git commits
- **Output_Formatter**: Component that transforms validation results into specified formats
- **Argument_Parser**: Component that processes and validates command-line arguments
- **Path_Handler**: Component using pathlib for file system operations
- **Context_Manager**: Python construct ensuring proper resource cleanup
- **Environment_Variable**: System-level configuration value
- **Retry_Handler**: Component that implements retry logic for transient failures

## Requirements

### Requirement 1: Exit Code Standardization

**User Story:** As a CI/CD pipeline developer, I want specific exit codes for different failure types, so that I can handle errors appropriately in automation scripts.

#### Acceptance Criteria

1. THE CLI_Tool SHALL define exit code constants for success (0), validation errors (1), configuration errors (2), AWS API errors (3), and file errors (4)
2. WHEN a file is not found, THE CLI_Tool SHALL return exit code 4
3. WHEN an AWS API call fails, THE CLI_Tool SHALL return exit code 3
4. WHEN policy validation fails, THE CLI_Tool SHALL return exit code 1
5. WHEN configuration is invalid, THE CLI_Tool SHALL return exit code 2
6. WHEN execution completes successfully, THE CLI_Tool SHALL return exit code 0

### Requirement 2: Structured Logging System

**User Story:** As a developer, I want proper logging with configurable verbosity levels, so that I can control diagnostic output during development and production use.

#### Acceptance Criteria

1. THE CLI_Tool SHALL replace all print statements with Logger calls
2. THE CLI_Tool SHALL support a --verbose flag that enables DEBUG level logging
3. THE CLI_Tool SHALL support a --quiet flag that suppresses all output except ERROR level
4. WHEN neither --verbose nor --quiet is specified, THE CLI_Tool SHALL use INFO level logging
5. THE CLI_Tool SHALL reserve print() only for primary output data (JSON results)
6. THE CLI_Tool SHALL support a --log-format flag with choices of 'text' and 'json'
7. WHEN --log-format is 'json', THE Logger SHALL output structured JSON log entries with timestamp, level, message, and module fields

### Requirement 3: Output Format Flexibility

**User Story:** As a user, I want to specify output format and destination, so that I can integrate validation results into different workflows.

#### Acceptance Criteria

1. THE CLI_Tool SHALL support a --format flag with choices: json, text, html, pdf
2. THE CLI_Tool SHALL support an --output flag specifying the output file path
3. WHEN --output is not specified and format is json or text, THE Output_Formatter SHALL write to stdout
4. WHEN --output is specified, THE Output_Formatter SHALL write results to the specified file path
5. WHEN format is json, THE Output_Formatter SHALL produce valid JSON output
6. WHEN format is text, THE Output_Formatter SHALL produce human-readable text output

### Requirement 4: Configuration File Support

**User Story:** As a user, I want to store CLI options in a configuration file, so that I can avoid repeating common arguments.

#### Acceptance Criteria

1. THE CLI_Tool SHALL support a --config flag accepting a file path
2. WHEN --config is provided with a .yaml file, THE CLI_Tool SHALL parse YAML configuration
3. WHEN --config is provided with a .toml file, THE CLI_Tool SHALL parse TOML configuration
4. WHEN both Config_File and command-line arguments are provided, THE CLI_Tool SHALL prioritize command-line arguments
5. THE Config_File SHALL support keys: profile, policies_path, upload_report, bucket_name, create_pdf
6. WHEN Config_File parsing fails, THE CLI_Tool SHALL return exit code 2 with a descriptive error message

### Requirement 5: Dry Run Mode

**User Story:** As a user, I want to validate policies without side effects, so that I can test configurations safely.

#### Acceptance Criteria

1. THE CLI_Tool SHALL support a --dry-run flag
2. WHEN --dry-run is enabled, THE CLI_Tool SHALL validate policies without creating reports
3. WHEN --dry-run is enabled, THE CLI_Tool SHALL validate policies without uploading to S3
4. WHEN --dry-run is enabled, THE CLI_Tool SHALL log all actions that would be performed

### Requirement 6: Argument Validation Enhancement

**User Story:** As a user, I want clear error messages for invalid argument combinations, so that I can correct my usage quickly.

#### Acceptance Criteria

1. WHEN --upload is specified without --bucket-name, THE Argument_Parser SHALL return an error message stating bucket-name is required
2. WHEN --upload is specified without --bucket-name, THE CLI_Tool SHALL return exit code 2
3. THE Argument_Parser SHALL validate all required argument dependencies before execution begins
4. WHEN argument validation fails, THE Argument_Parser SHALL display a clear error message indicating the missing or invalid arguments

### Requirement 7: Comprehensive Test Suite

**User Story:** As a developer, I want automated tests for all CLI functionality, so that I can refactor confidently and prevent regressions.

#### Acceptance Criteria

1. THE Test_Suite SHALL include unit tests for policy validation logic
2. THE Test_Suite SHALL include unit tests for IAM analyzer integration
3. THE Test_Suite SHALL include unit tests for file operations
4. THE Test_Suite SHALL include integration tests for CLI argument parsing
5. THE Test_Suite SHALL use pytest as the test framework
6. THE Test_Suite SHALL use moto for mocking AWS services
7. THE Test_Suite SHALL achieve a minimum of 80% code coverage
8. THE Test_Suite SHALL include fixtures for sample policies and expected outputs

### Requirement 8: Code Quality Tooling

**User Story:** As a developer, I want automated code quality checks, so that the codebase maintains consistent style and catches common errors.

#### Acceptance Criteria

1. THE Pre_Commit_Hook SHALL run the Linter with auto-fix enabled
2. THE Pre_Commit_Hook SHALL run the Type_Checker on all Python files
3. THE Pre_Commit_Hook SHALL check for trailing whitespace
4. THE Pre_Commit_Hook SHALL check for proper file endings
5. THE Pre_Commit_Hook SHALL validate YAML and JSON files
6. THE Linter SHALL enforce a maximum line length of 100 characters
7. THE Linter SHALL check for pycodestyle errors, pyflakes issues, import sorting, bugbear patterns, and comprehension improvements

### Requirement 9: Type Annotation Coverage

**User Story:** As a developer, I want comprehensive type hints throughout the codebase, so that I can catch type errors during development.

#### Acceptance Criteria

1. THE CLI_Tool SHALL include type annotations for all function parameters
2. THE CLI_Tool SHALL include type annotations for all function return values
3. THE CLI_Tool SHALL use typing module types: List, Dict, Optional, Any, Path
4. WHEN the Type_Checker runs, THE CLI_Tool SHALL produce zero type errors
5. THE CLI_Tool SHALL include docstrings with Args, Returns, and Raises sections for all public functions

### Requirement 10: Path Handling Modernization

**User Story:** As a developer, I want consistent path handling using pathlib, so that file operations are more reliable and cross-platform.

#### Acceptance Criteria

1. THE Path_Handler SHALL use pathlib.Path for all file system operations
2. THE Path_Handler SHALL replace all os.path operations with pathlib equivalents
3. THE Path_Handler SHALL use Path.glob() for directory listing operations
4. THE Path_Handler SHALL use Path division operator (/) for path joining
5. THE Path_Handler SHALL use Path.open() with context managers for file operations

### Requirement 11: Resource Management with Context Managers

**User Story:** As a developer, I want automatic resource cleanup, so that file handles and connections are properly closed.

#### Acceptance Criteria

1. WHEN reading policy files, THE CLI_Tool SHALL use context managers (with statements)
2. WHEN writing report files, THE CLI_Tool SHALL use context managers (with statements)
3. THE CLI_Tool SHALL specify UTF-8 encoding explicitly in all file operations
4. WHEN a file operation fails, THE Context_Manager SHALL ensure resources are released before raising the exception

### Requirement 12: Environment Variable Configuration

**User Story:** As a user, I want to configure common settings via environment variables, so that I can set defaults without command-line arguments.

#### Acceptance Criteria

1. THE CLI_Tool SHALL read AWS_PROFILE environment variable as default for --profile
2. THE CLI_Tool SHALL read REPORTS_BUCKET environment variable as default for --bucket-name
3. THE CLI_Tool SHALL read POLICIES_PATH environment variable as default for --directory-policies-path
4. WHEN both Environment_Variable and command-line argument are provided, THE CLI_Tool SHALL use the command-line argument value
5. WHEN both Environment_Variable and Config_File value are provided, THE CLI_Tool SHALL use the Config_File value

### Requirement 13: AWS API Retry Logic

**User Story:** As a user, I want automatic retries for transient AWS API failures, so that temporary network issues don't cause validation failures.

#### Acceptance Criteria

1. THE Retry_Handler SHALL configure boto3 with a maximum of 3 retry attempts
2. THE Retry_Handler SHALL use adaptive retry mode for AWS API calls
3. WHEN an S3 upload fails, THE Retry_Handler SHALL retry with exponential backoff
4. WHEN maximum retries are exhausted, THE Retry_Handler SHALL raise the original exception
5. WHEN a retry occurs, THE Logger SHALL log a warning with the attempt number and wait time

### Requirement 14: Progress Indication

**User Story:** As a user, I want visual progress feedback during batch operations, so that I know the tool is working on long-running tasks.

#### Acceptance Criteria

1. WHEN validating multiple policies, THE CLI_Tool SHALL display a progress bar with policy count
2. WHEN --quiet flag is enabled, THE CLI_Tool SHALL suppress progress indicators
3. THE CLI_Tool SHALL use tqdm library for progress bar implementation
4. THE progress bar SHALL show the current policy being processed and percentage complete

### Requirement 15: Dependency Management

**User Story:** As a developer, I want clearly defined dependency groups with version constraints, so that installations are reproducible and conflicts are avoided.

#### Acceptance Criteria

1. THE CLI_Tool SHALL define production dependencies with minimum and maximum version constraints
2. THE CLI_Tool SHALL define a 'dev' optional dependency group including pytest, pytest-cov, pytest-mock, moto, ruff, mypy, and pre-commit
3. THE CLI_Tool SHALL define a 'docs' optional dependency group including mkdocs and mkdocs-material
4. THE CLI_Tool SHALL specify Python version compatibility in project metadata
5. WHEN installing with dev dependencies, THE CLI_Tool SHALL install all testing and quality tools

### Requirement 16: CI/CD Pipeline

**User Story:** As a developer, I want automated testing on multiple Python versions, so that compatibility is verified before merging changes.

#### Acceptance Criteria

1. THE CLI_Tool SHALL include a GitHub Actions workflow that runs on push and pull request events
2. THE workflow SHALL test against Python versions 3.8, 3.9, 3.10, 3.11, and 3.12
3. THE workflow SHALL run the Linter and fail if issues are found
4. THE workflow SHALL run the Type_Checker and fail if type errors are found
5. THE workflow SHALL run the Test_Suite and fail if tests fail or coverage is below 80%
6. THE workflow SHALL upload coverage reports to codecov

### Requirement 17: Flag Naming Consistency

**User Story:** As a user, I want consistent and intuitive flag names, so that the CLI is easy to learn and use.

#### Acceptance Criteria

1. THE CLI_Tool SHALL use hyphens (not underscores) in multi-word flag names
2. THE CLI_Tool SHALL provide short flags (-f, -o, -v, -q) for commonly used options
3. THE CLI_Tool SHALL rename --create_pdf_reports to --pdf
4. THE CLI_Tool SHALL rename upload_report flag to --upload
5. THE CLI_Tool SHALL use descriptive long-form names for all flags

### Requirement 18: Code Cleanup

**User Story:** As a developer, I want to remove unused and suspicious imports, so that the codebase is clean and maintainable.

#### Acceptance Criteria

1. THE CLI_Tool SHALL remove the unused psutil.tests.test_process_all import from ops.py
2. THE Linter SHALL detect and report unused imports
3. THE Pre_Commit_Hook SHALL prevent commits with unused imports
