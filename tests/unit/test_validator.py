"""Unit tests for PolicyValidator."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from validate_aws_policies.cli.exit_codes import (
    EXIT_AWS_ERROR,
    EXIT_FILE_ERROR,
    EXIT_SUCCESS,
    EXIT_VALIDATION_ERROR,
)
from validate_aws_policies.core.validator import PolicyValidator

MODULE = "validate_aws_policies.core.validator"
RESULTS = [
    {
        "filePolicy": "a.json",
        "summary": [
            {
                "policyName": "a",
                "issueCode": "X",
                "findingType": "WARNING",
                "details": {"findingType": "WARNING"},
            }
        ],
    },
    {"filePolicy": "b.json", "summary": []},
]


@pytest.fixture
def policies_dir(tmp_path):
    d = tmp_path / "policies"
    d.mkdir()
    (d / "a.json").write_text("{}")
    (d / "b.json").write_text("{}")
    (d / "ignore.txt").write_text("x")
    return d


def make(policies_dir, **extra):
    return PolicyValidator({"policies_path": str(policies_dir), "format": "json", **extra})


class TestRun:
    def test_missing_directory(self, tmp_path):
        v = PolicyValidator({"policies_path": str(tmp_path / "nope")})
        assert v.run() == EXIT_FILE_ERROR

    def test_path_is_a_file(self, tmp_path):
        f = tmp_path / "f.json"
        f.write_text("{}")
        assert PolicyValidator({"policies_path": str(f)}).run() == EXIT_FILE_ERROR

    def test_no_policy_files_is_success(self, tmp_path):
        assert PolicyValidator({"policies_path": str(tmp_path)}).run() == EXIT_SUCCESS

    def test_json_output_to_stdout(self, policies_dir, capsys):
        with patch(f"{MODULE}.validate_policies", return_value=RESULTS) as vp:
            code = make(policies_dir, dry_run=True, policy_type="scp").run()
        assert code == EXIT_SUCCESS
        assert json.loads(capsys.readouterr().out) == RESULTS
        assert sorted(vp.call_args.args[0]) == ["a.json", "b.json"]
        assert vp.call_args.kwargs["policy_type"] == "scp"

    def test_default_policy_type_is_identity(self, policies_dir):
        with patch(f"{MODULE}.validate_policies", return_value=RESULTS) as vp:
            make(policies_dir, dry_run=True).run()
        assert vp.call_args.kwargs["policy_type"] == "identity"

    def test_text_output_to_file(self, policies_dir, tmp_path):
        out = tmp_path / "out.txt"
        with patch(f"{MODULE}.validate_policies", return_value=RESULTS):
            code = make(policies_dir, format="text", output=str(out), dry_run=True).run()
        assert code == EXIT_SUCCESS
        text = out.read_text()
        assert "Policy: a.json" in text and "WARNING: X" in text and "No findings" in text

    def test_json_output_to_file(self, policies_dir, tmp_path):
        out = tmp_path / "out.json"
        with patch(f"{MODULE}.validate_policies", return_value=RESULTS):
            make(policies_dir, output=str(out), dry_run=True).run()
        assert json.loads(out.read_text()) == RESULTS

    def test_error_finding_maps_to_validation_error(self, policies_dir):
        with patch(f"{MODULE}.validate_policies", side_effect=ValueError("ERROR - bad")):
            assert make(policies_dir).run() == EXIT_VALIDATION_ERROR

    def test_file_not_found_maps_to_file_error(self, policies_dir):
        with patch(f"{MODULE}.validate_policies", side_effect=FileNotFoundError("x")):
            assert make(policies_dir).run() == EXIT_FILE_ERROR

    def test_unexpected_error_maps_to_validation_error(self, policies_dir):
        with patch(f"{MODULE}.validate_policies", side_effect=RuntimeError("boom")):
            assert make(policies_dir).run() == EXIT_VALIDATION_ERROR


class TestReportsAndUpload:
    @pytest.mark.parametrize(
        "fmt,method,count",
        [
            ("html", "create_html_report", 1),
            ("md", "create_markdown_report", 1),
            ("markdown", "create_markdown_report", 1),
            ("xml", "create_junit_xml_report", 1),
            ("junit", "create_junit_xml_report", 1),
        ],
    )
    def test_single_format(self, policies_dir, fmt, method, count):
        v = make(policies_dir, format=fmt)
        with patch.object(v.report_generator, method, return_value=Path("r")) as m:
            files = v._generate_reports(RESULTS)
        assert m.call_count == count
        assert files == [Path("r")]

    def test_all_formats(self, policies_dir):
        v = make(policies_dir, format="all")
        rg = v.report_generator
        with patch.object(rg, "create_html_report", return_value=Path("a.html")), patch.object(
            rg, "create_markdown_report", return_value=Path("a.md")
        ), patch.object(rg, "create_junit_xml_report", return_value=Path("a.xml")):
            assert len(v._generate_reports(RESULTS)) == 3

    def test_zip_replaces_files(self, policies_dir):
        v = make(policies_dir, format="html", zip=True)
        rg = v.report_generator
        with patch.object(rg, "create_html_report", return_value=Path("a.html")):
            with patch.object(rg, "create_zip", return_value=Path("r.zip")) as z:
                assert v._generate_reports(RESULTS) == [Path("r.zip")]
        z.assert_called_once_with([Path("a.html")])

    def test_json_format_creates_no_report_files(self, policies_dir):
        assert make(policies_dir)._generate_reports(RESULTS) == []

    def test_upload_uses_date_key(self, policies_dir):
        v = make(policies_dir, bucket_name="bkt")
        with patch(f"{MODULE}.upload_file") as up:
            v._upload_reports([Path("x/report.html")])
        bucket, key = up.call_args.args[1], up.call_args.args[2]
        assert bucket == "bkt"
        assert key.startswith("AccessAnalyzer/") and key.endswith("/report.html")

    def test_upload_requires_bucket(self, policies_dir):
        with pytest.raises(ValueError):
            make(policies_dir)._upload_reports([Path("r.html")])

    @pytest.mark.parametrize("flag", ["upload", "upload_report"])
    def test_run_uploads_with_either_key(self, policies_dir, flag):
        v = make(policies_dir, format="html", bucket_name="b", **{flag: True})
        with patch(f"{MODULE}.validate_policies", return_value=RESULTS), patch.object(
            v.report_generator, "create_html_report", return_value=Path("r.html")
        ), patch(f"{MODULE}.upload_file") as up:
            assert v.run() == EXIT_SUCCESS
        assert up.call_count == 1

    def test_dry_run_skips_reports_and_upload(self, policies_dir):
        v = make(policies_dir, format="html", upload=True, bucket_name="b", dry_run=True)
        with patch(f"{MODULE}.validate_policies", return_value=RESULTS), patch.object(
            v.report_generator, "create_html_report"
        ) as html, patch(f"{MODULE}.upload_file") as up:
            assert v.run() == EXIT_SUCCESS
        html.assert_not_called()
        up.assert_not_called()


class TestUploadFailure:
    def test_failed_upload_exits_with_aws_error(self, policies_dir):
        v = make(policies_dir, format="html", upload=True, bucket_name="b")
        with patch(f"{MODULE}.validate_policies", return_value=RESULTS), patch.object(
            v.report_generator, "create_html_report", return_value=Path("r.html")
        ), patch(f"{MODULE}.upload_file", return_value=False):
            assert v.run() == EXIT_AWS_ERROR
