"""Tests for config key aliases, CLI/file/env precedence and policy type handling."""

from unittest.mock import MagicMock, patch

import pytest

from validate_aws_policies.cli.args import parse_args
from validate_aws_policies.cli.config import ConfigLoader
from validate_aws_policies.cli.exit_codes import EXIT_CONFIG_ERROR
from validate_aws_policies.iam_access_analyzer.iam_access_analyzer import validate_policies
from validate_aws_policies.validate_policies import main, merge_config


def make_args(**overrides):
    """Build a namespace-like object with every option unset."""
    args = MagicMock()
    defaults = {
        "config": None,
        "policies_path": None,
        "profile": None,
        "bucket": None,
        "policy_type": None,
        "upload": False,
        "zip": False,
        "ci": False,
        "dry_run": False,
        "format": None,
        "output": None,
        "verbose": False,
        "quiet": False,
        "log_format": None,
    }
    defaults.update(overrides)
    for key, value in defaults.items():
        setattr(args, key, value)
    return args


class TestKeyAliases:
    def test_legacy_file_keys_populate_canonical_keys(self, tmp_path):
        cfg = tmp_path / "c.yaml"
        cfg.write_text(
            "directory_policies_path: /p\nupload_report: true\nzip_reports: true\n"
        )
        config = ConfigLoader(cfg).load_config()
        assert config["policies_path"] == "/p"
        assert config["upload"] is True
        assert config["zip"] is True
        # legacy keys are still present
        assert config["directory_policies_path"] == "/p"
        assert config["upload_report"] is True

    def test_canonical_file_keys_populate_legacy_keys(self, tmp_path):
        cfg = tmp_path / "c.toml"
        cfg.write_text('policies_path = "/p"\nupload = true\nzip = true\n')
        config = ConfigLoader(cfg).load_config()
        assert config["directory_policies_path"] == "/p"
        assert config["upload_report"] is True
        assert config["zip_reports"] is True

    def test_env_beats_file_regardless_of_spelling(self, tmp_path, monkeypatch):
        cfg = tmp_path / "c.yaml"
        cfg.write_text("policies_path: /file\n")
        monkeypatch.setenv("POLICIES_PATH", "/env")
        config = ConfigLoader(cfg).load_config()
        assert config["policies_path"] == "/env"
        assert config["directory_policies_path"] == "/env"


class TestMergeConfig:
    def test_file_values_survive_when_cli_flags_not_given(self, tmp_path, monkeypatch):
        monkeypatch.delenv("POLICIES_PATH", raising=False)
        cfg = tmp_path / "c.yaml"
        cfg.write_text(
            "policies_path: /p\nupload: true\nzip_reports: true\nci: true\n"
            "dry_run: false\nformat: html\nlog_format: json\nbucket_name: b\n"
        )
        config = merge_config(make_args(config=str(cfg)))
        assert config["upload"] is True
        assert config["zip"] is True
        assert config["ci"] is True
        assert config["format"] == "html"
        assert config["log_format"] == "json"
        assert config["bucket_name"] == "b"

    def test_cli_values_override_file(self, tmp_path):
        cfg = tmp_path / "c.yaml"
        cfg.write_text("policies_path: /file\nformat: html\npolicy_type: scp\n")
        config = merge_config(
            make_args(
                config=str(cfg), policies_path="/cli", format="text", policy_type="resource"
            )
        )
        assert config["policies_path"] == "/cli"
        assert config["format"] == "text"
        assert config["policy_type"] == "resource"

    def test_defaults(self, monkeypatch):
        monkeypatch.delenv("POLICIES_PATH", raising=False)
        config = merge_config(make_args())
        assert config["format"] == "json"
        assert config["log_format"] == "text"
        assert config["policy_type"] == "identity"
        assert config["upload"] is False
        assert config["zip"] is False


class TestMainConfigChecks:
    def test_upload_from_file_without_bucket_is_config_error(self, tmp_path, monkeypatch):
        monkeypatch.delenv("REPORTS_BUCKET", raising=False)
        cfg = tmp_path / "c.yaml"
        cfg.write_text(f"policies_path: {tmp_path}\nupload: true\n")
        with patch("sys.argv", ["validate-aws-policies", "--config", str(cfg)]):
            assert main() == EXIT_CONFIG_ERROR


class TestArgs:
    def test_text_format_accepts_txt_extension(self, tmp_path):
        args = parse_args(
            ["-d", str(tmp_path), "--format", "text", "--output", str(tmp_path / "out.txt")]
        )
        assert args.format == "text"

    def test_text_format_still_accepts_text_extension(self, tmp_path):
        parse_args(["-d", str(tmp_path), "-f", "text", "-o", str(tmp_path / "out.text")])

    def test_output_extension_checked_against_default_format(self, tmp_path):
        with pytest.raises(SystemExit):
            parse_args(["-d", str(tmp_path), "-o", str(tmp_path / "out.html")])

    @pytest.mark.parametrize("value", ["identity", "resource", "scp", "rcp"])
    def test_policy_type_choices(self, tmp_path, value):
        assert parse_args(["-d", str(tmp_path), "--policy-type", value]).policy_type == value

    def test_policy_type_invalid(self, tmp_path):
        with pytest.raises(SystemExit):
            parse_args(["-d", str(tmp_path), "--policy-type", "bogus"])


class TestPolicyType:
    @pytest.mark.parametrize(
        "given,expected",
        [
            (None, "IDENTITY_POLICY"),
            ("identity", "IDENTITY_POLICY"),
            ("scp", "SERVICE_CONTROL_POLICY"),
            ("resource", "RESOURCE_POLICY"),
            ("rcp", "RESOURCE_CONTROL_POLICY"),
            ("SERVICE_CONTROL_POLICY", "SERVICE_CONTROL_POLICY"),
        ],
    )
    def test_policy_type_sent_to_api(self, tmp_path, given, expected):
        (tmp_path / "p.json").write_text('{"Version": "2012-10-17", "Statement": []}')
        with patch(
            "validate_aws_policies.iam_access_analyzer.iam_access_analyzer.boto3"
        ) as boto:
            paginator = boto.client.return_value.get_paginator.return_value
            paginator.paginate.return_value = [{"findings": []}]
            kwargs = {} if given is None else {"policy_type": given}
            validate_policies(["p.json"], tmp_path, **kwargs)
            assert paginator.paginate.call_args.kwargs["policyType"] == expected

    def test_unknown_policy_type_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            validate_policies([], tmp_path, policy_type="nope")


class TestBucketAliasAndAllFormat:
    def test_bucket_key_in_config_file_is_bucket_name(self, tmp_path):
        cfg = tmp_path / "c.yaml"
        cfg.write_text("bucket: my-bucket\n")
        config = ConfigLoader(cfg).load_config()
        assert config["bucket_name"] == "my-bucket"
        assert config["bucket"] == "my-bucket"

    def test_upload_with_legacy_bucket_key_passes_config_checks(self, tmp_path, monkeypatch):
        monkeypatch.delenv("REPORTS_BUCKET", raising=False)
        cfg = tmp_path / "c.yaml"
        cfg.write_text(f"policies_path: {tmp_path}\nupload: true\nbucket: b\n")
        with patch("sys.argv", ["validate-aws-policies", "--config", str(cfg)]):
            with patch("validate_aws_policies.validate_policies.PolicyValidator") as validator:
                validator.return_value.run.return_value = 0
                assert main() == 0

    def test_format_all_is_accepted_but_not_with_output(self, tmp_path):
        assert parse_args(["-d", str(tmp_path), "-f", "all"]).format == "all"
        with pytest.raises(SystemExit):
            parse_args(["-d", str(tmp_path), "-f", "all", "-o", str(tmp_path / "x.html")])
