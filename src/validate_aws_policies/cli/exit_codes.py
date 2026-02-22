"""Exit codes for the AWS policy validation CLI.

This module defines standard exit codes for different error scenarios,
improving error handling and making it easier for scripts and CI/CD
pipelines to determine the specific type of failure.

Exit codes follow Unix conventions where 0 indicates success and
non-zero values indicate different types of failures.
"""

# Success exit code
EXIT_SUCCESS = 0
"""Successful execution with no errors.

Use this when:
- All policies validated successfully with no findings
- All operations completed as expected
"""

# Error exit codes
EXIT_VALIDATION_ERROR = 1
"""Policy validation failed.

Use this when:
- One or more policies have ERROR-level findings from IAM Access Analyzer
- Policy syntax is invalid
- Policy violates AWS best practices (ERROR severity)
"""

EXIT_CONFIG_ERROR = 2
"""Configuration error.

Use this when:
- Required configuration parameters are missing or invalid
- Invalid argument combinations (e.g., --upload without --bucket-name)
- Configuration file is malformed or cannot be read
- AWS profile is invalid or not found
"""

EXIT_AWS_ERROR = 3
"""AWS API error.

Use this when:
- AWS API calls fail (ClientError, BotoCoreError)
- Authentication or authorization failures
- Service unavailable or throttling errors
- S3 upload failures
- IAM Access Analyzer API errors
"""

EXIT_FILE_ERROR = 4
"""File I/O error.

Use this when:
- Policy file not found
- Cannot read policy file (permissions, encoding issues)
- Cannot write report files
- Directory does not exist or is not accessible
"""
