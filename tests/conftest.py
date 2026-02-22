"""Pytest configuration and shared fixtures."""

import json
from pathlib import Path
from typing import Any, Dict

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    """Return the path to the fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_policies_dir(fixtures_dir: Path) -> Path:
    """Return the path to sample policies directory."""
    return fixtures_dir / "sample_policies"


@pytest.fixture
def config_files_dir(fixtures_dir: Path) -> Path:
    """Return the path to config files directory."""
    return fixtures_dir / "config_files"


@pytest.fixture
def valid_identity_policy() -> Dict[str, Any]:
    """Return a valid identity-based policy."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::example-bucket/*",
            }
        ],
    }


@pytest.fixture
def valid_resource_policy() -> Dict[str, Any]:
    """Return a valid resource-based policy."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-bucket/*",
            }
        ],
    }


@pytest.fixture
def invalid_policy_missing_version() -> Dict[str, Any]:
    """Return an invalid policy missing Version field."""
    return {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}


@pytest.fixture
def invalid_policy_wildcard_resource() -> Dict[str, Any]:
    """Return a policy with overly permissive wildcard resource."""
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}],
    }


@pytest.fixture
def sample_config_yaml() -> Dict[str, Any]:
    """Return sample YAML configuration."""
    return {
        "profile": "test-profile",
        "policies_path": "./test-policies",
        "upload_report": True,
        "bucket_name": "test-reports-bucket",
        "create_zip": False,
        "verbose": False,
    }


@pytest.fixture
def sample_config_toml() -> Dict[str, Any]:
    """Return sample TOML configuration."""
    return {
        "profile": "test-profile",
        "policies_path": "./test-policies",
        "upload_report": False,
        "verbose": True,
    }


@pytest.fixture
def temp_policy_file(tmp_path: Path, valid_identity_policy: Dict[str, Any]) -> Path:
    """Create a temporary policy file and return its path."""
    policy_file = tmp_path / "test-policy.json"
    policy_file.write_text(json.dumps(valid_identity_policy, indent=2))
    return policy_file


@pytest.fixture
def temp_policies_dir(
    tmp_path: Path, valid_identity_policy: Dict[str, Any], valid_resource_policy: Dict[str, Any]
) -> Path:
    """Create a temporary directory with multiple policy files."""
    policies_dir = tmp_path / "policies"
    policies_dir.mkdir()

    # Create identity policy
    identity_policy = policies_dir / "identity-policy.json"
    identity_policy.write_text(json.dumps(valid_identity_policy, indent=2))

    # Create resource policy
    resource_policy = policies_dir / "resource-policy.json"
    resource_policy.write_text(json.dumps(valid_resource_policy, indent=2))

    return policies_dir


@pytest.fixture
def mock_aws_credentials(monkeypatch):
    """Mock AWS credentials for testing."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
