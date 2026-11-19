"""Tests for the main() workflow and error-to-exit-code mapping, plus report smoke tests."""

import json
import logging
import sys
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

from validate_aws_policies.cli.config import ConfigError
from validate_aws_policies.cli.exit_codes import (
    EXIT_AWS_ERROR,
    EXIT_CONFIG_ERROR,
    EXIT_FILE_ERROR,
    EXIT_SUCCESS,
    EXIT_VALIDATION_ERROR,
)
from validate_aws_policies.ops.reports import ReportGenerator
from validate_aws_policies.validate_policies import main, setup_logging

MOD = "validate_aws_policies.validate_policies"


@pytest.fixture
def argv(tmp_path, monkeypatch):
    for var in ("POLICIES_PATH", "REPORTS_BUCKET", "AWS_PROFILE", "LOG_LEVEL"):
        monkeypatch.delenv(var, raising=False)
    return ["validate-aws-policies", "--policies-path", str(tmp_path)]


def run_main(argv):
    with patch.object(sys, "argv", argv):
        return main()


class TestMainFlow:
    def test_success(self, argv):
        with patch(f"{MOD}.PolicyValidator") as validator:
            validator.return_value.run.return_value = EXIT_SUCCESS
            assert run_main(argv) == EXIT_SUCCESS
        assert validator.call_args.args[0]["policy_type"] == "identity"

    def test_validator_failure_code_is_returned(self, argv):
        with patch(f"{MOD}.PolicyValidator") as validator:
            validator.return_value.run.return_value = EXIT_VALIDATION_ERROR
            assert run_main(argv) == EXIT_VALIDATION_ERROR

    def test_profile_sets_boto3_session(self, argv):
        with patch(f"{MOD}.PolicyValidator") as validator, patch(f"{MOD}.boto3") as boto:
            validator.return_value.run.return_value = EXIT_SUCCESS
            run_main(argv + ["--profile", "dev"])
        boto.setup_default_session.assert_called_once_with(profile_name="dev")

    def test_profile_failure_is_config_error(self, argv):
        with patch(f"{MOD}.boto3") as boto:
            boto.setup_default_session.side_effect = RuntimeError("no profile")
            assert run_main(argv + ["--profile", "dev"]) == EXIT_CONFIG_ERROR

    def test_config_error(self, argv):
        with patch(f"{MOD}.merge_config", side_effect=ConfigError("bad")):
            assert run_main(argv) == EXIT_CONFIG_ERROR

    def test_dry_run_with_upload_from_file_is_config_error(self, argv, tmp_path):
        cfg = tmp_path / "c.yaml"
        cfg.write_text("upload: true\ndry_run: true\nbucket_name: b\n")
        assert run_main(argv + ["--config", str(cfg)]) == EXIT_CONFIG_ERROR

    @pytest.mark.parametrize(
        "exc,code",
        [
            (ClientError({"Error": {"Code": "X", "Message": "m"}}, "op"), EXIT_AWS_ERROR),
            (FileNotFoundError("f"), EXIT_FILE_ERROR),
            (PermissionError("p"), EXIT_FILE_ERROR),
            (KeyboardInterrupt(), EXIT_CONFIG_ERROR),
            (RuntimeError("boom"), EXIT_VALIDATION_ERROR),
        ],
    )
    def test_exception_mapping(self, argv, exc, code):
        with patch(f"{MOD}.PolicyValidator") as validator:
            validator.return_value.run.side_effect = exc
            assert run_main(argv) == code


class TestJsonLogging:
    def test_json_formatter_emits_valid_json(self, capsys):
        setup_logging(log_format="json")
        try:
            logging.getLogger("t").error("hello")
        finally:
            setup_logging()
        record = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert record["message"] == "hello"
        assert record["level"] == "ERROR"
        assert "T" in record["timestamp"]


FINDINGS = [
    {
        "filePolicy": "a.json",
        "summary": [
            {
                "policyName": "a",
                "issueCode": "UNSUPPORTED_ACTION",
                "findingType": "ERROR",
                "details": {
                    "findingDetails": "bad <action>",
                    "learnMoreLink": "https://docs.aws.amazon.com",
                    "locations": [],
                },
            },
            {
                "policyName": "a",
                "issueCode": "X",
                "findingType": "SECURITY_WARNING",
                "details": {"findingDetails": "d"},
            },
        ],
    },
    {
        "filePolicy": "b.json",
        "summary": [
            {
                "policyName": "b",
                "issueCode": "None",
                "findingType": "None",
                "details": "No findings",
            }
        ],
    },
]


class TestReportSmoke:
    def test_html_report_is_written(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = ReportGenerator().create_html_report(FINDINGS)
        content = path.read_text(encoding="utf-8")
        assert path.suffix == ".html"
        assert "a.json" in content and "UNSUPPORTED_ACTION" in content

    def test_markdown_report_is_written(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = ReportGenerator().create_markdown_report(FINDINGS)
        content = path.read_text(encoding="utf-8")
        assert path.suffix == ".md"
        assert "a.json" in content and "UNSUPPORTED_ACTION" in content

    def test_ops_create_zip_still_works(self, tmp_path, monkeypatch):
        from validate_aws_policies.ops.ops import create_zip

        monkeypatch.chdir(tmp_path)
        report = tmp_path / "r.txt"
        report.write_text("x")
        zip_path = create_zip([report.relative_to(tmp_path)])
        assert zip_path.exists() and zip_path.suffix == ".zip"


class TestLoggingFromConfig:
    """verbose, quiet, log_format and LOG_LEVEL set outside the command line are honored."""

    def run_with_config(self, tmp_path, monkeypatch, content, env=None):
        for var in ("LOG_LEVEL", "POLICIES_PATH", "REPORTS_BUCKET", "AWS_PROFILE"):
            monkeypatch.delenv(var, raising=False)
        for key, value in (env or {}).items():
            monkeypatch.setenv(key, value)
        cfg = tmp_path / "c.yaml"
        cfg.write_text(f"policies_path: {tmp_path}\n{content}")
        with patch(f"{MOD}.PolicyValidator") as validator:
            validator.return_value.run.return_value = EXIT_SUCCESS
            code = run_main(["validate-aws-policies", "--config", str(cfg)])
        return code, logging.getLogger().level

    def teardown_method(self):
        setup_logging()

    def test_verbose_from_file(self, tmp_path, monkeypatch):
        code, level = self.run_with_config(tmp_path, monkeypatch, "verbose: true\n")
        assert code == EXIT_SUCCESS and level == logging.DEBUG

    def test_quiet_from_file(self, tmp_path, monkeypatch):
        _, level = self.run_with_config(tmp_path, monkeypatch, "quiet: true\n")
        assert level == logging.ERROR

    def test_log_level_env(self, tmp_path, monkeypatch):
        _, level = self.run_with_config(tmp_path, monkeypatch, "", env={"LOG_LEVEL": "WARNING"})
        assert level == logging.WARNING

    def test_invalid_log_level_falls_back_to_info(self):
        setup_logging(log_level="loud")
        assert logging.getLogger().level == logging.INFO

    def test_json_log_format_from_file(self, tmp_path, monkeypatch):
        self.run_with_config(tmp_path, monkeypatch, "log_format: json\n")
        handler = logging.getLogger().handlers[0]
        assert type(handler.formatter).__name__ == "JSONFormatter"

    def test_verbose_and_quiet_in_file_is_a_config_error(self, tmp_path, monkeypatch):
        code, _ = self.run_with_config(tmp_path, monkeypatch, "verbose: true\nquiet: true\n")
        assert code == EXIT_CONFIG_ERROR

    def test_command_line_flag_beats_file(self, tmp_path, monkeypatch):
        cfg = tmp_path / "c.yaml"
        cfg.write_text(f"policies_path: {tmp_path}\nquiet: true\n")
        with patch(f"{MOD}.PolicyValidator") as validator:
            validator.return_value.run.return_value = EXIT_SUCCESS
            run_main(["validate-aws-policies", "--config", str(cfg), "--verbose"])
        assert logging.getLogger().level == logging.DEBUG
