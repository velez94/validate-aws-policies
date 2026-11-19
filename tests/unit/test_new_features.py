"""Tests for 3.2 features: failure thresholds, recursion, policy sets, checks wiring,
merged-config validation, new CLI options, SARIF and the HTML report."""

import json
import sys
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

from validate_aws_policies.cli.args import parse_args
from validate_aws_policies.cli.exit_codes import (
    EXIT_AWS_ERROR,
    EXIT_CONFIG_ERROR,
    EXIT_SUCCESS,
    EXIT_VALIDATION_ERROR,
)
from validate_aws_policies.cli.validation import apply_checks_section, validate_merged_config
from validate_aws_policies.core.validator import PolicyValidator
from validate_aws_policies.iam_access_analyzer.features import SdkFeatureError
from validate_aws_policies.ops.findings import exceeds_threshold, finding_message
from validate_aws_policies.ops.html_report import render_html
from validate_aws_policies.ops.reports import ReportGenerator
from validate_aws_policies.ops.sarif import build_sarif
from validate_aws_policies.validate_policies import main, merge_config

MODULE = "validate_aws_policies.core.validator"


def finding(kind, code="X", message="msg", spans=True, link="https://docs.aws.amazon.com/x"):
    details = {"findingDetails": message, "learnMoreLink": link}
    if spans:
        details["locations"] = [
            {
                "path": [],
                "span": {
                    "start": {"line": 3, "column": 4, "offset": 10},
                    "end": {"line": 3, "column": 9, "offset": 15},
                },
            }
        ]
    return {"policyName": "p", "issueCode": code, "findingType": kind, "details": details}


def result(name, *findings):
    summary = list(findings) or [
        {"policyName": "p", "issueCode": "None", "findingType": "None", "details": "No findings"}
    ]
    return {"filePolicy": name, "summary": summary}


class TestThreshold:
    @pytest.mark.parametrize(
        "fail_on,kind,expected",
        [
            ("error", "ERROR", True),
            ("error", "SECURITY_WARNING", False),
            ("security-warning", "SECURITY_WARNING", True),
            ("security-warning", "WARNING", False),
            ("warning", "WARNING", True),
            ("warning", "SUGGESTION", False),
            ("suggestion", "SUGGESTION", True),
            ("none", "ERROR", False),
        ],
    )
    def test_levels(self, fail_on, kind, expected):
        assert exceeds_threshold([result("a.json", finding(kind))], fail_on) is expected

    def test_clean_results_never_fail(self):
        assert exceeds_threshold([result("a.json")], "suggestion") is False

    def test_message_helper_reads_nested_details(self):
        assert finding_message(finding("ERROR", message="boom")) == "boom"
        assert finding_message({"details": "No findings"}) == "No findings"
        assert finding_message({}) == "No details available"


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "top.json").write_text("{}")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "deep.json").write_text("{}")
    (tmp_path / ".hidden").mkdir()
    (tmp_path / ".hidden" / "skip.json").write_text("{}")
    return tmp_path


class TestDiscovery:
    def test_non_recursive_by_default(self, tree):
        v = PolicyValidator({"policies_path": str(tree)})
        assert v._get_policy_files(tree) == ["top.json"]

    def test_recursive_uses_relative_posix_names_and_skips_hidden(self, tree):
        v = PolicyValidator({"policies_path": str(tree)})
        assert v._get_policy_files(tree, recursive=True) == ["sub/deep.json", "top.json"]


class TestRunBehavior:
    def run(self, config, results, tmp_path):
        with patch(f"{MODULE}.validate_policies", return_value=results) as vp:
            code = PolicyValidator(
                {"policies_path": str(tmp_path), "dry_run": True, "format": "json", **config}
            ).run()
        return code, vp

    @pytest.fixture(autouse=True)
    def _files(self, tmp_path):
        (tmp_path / "a.json").write_text("{}")

    def test_default_keeps_legacy_fail_fast(self, tmp_path):
        code, vp = self.run({}, [result("a.json")], tmp_path)
        assert code == EXIT_SUCCESS
        assert vp.call_args.kwargs["fail_fast"] is True

    def test_error_findings_returned_in_default_mode_still_fail_the_run(self, tmp_path):
        # validate_policies would have raised; if it returns ERROR entries the run is
        # still judged by the threshold (error), which is stricter and consistent.
        code, _ = self.run({}, [result("a.json", finding("ERROR"))], tmp_path)
        assert code == EXIT_VALIDATION_ERROR

    def test_continue_on_error_collects_then_fails(self, tmp_path, capsys):
        code, vp = self.run(
            {"continue_on_error": True},
            [result("a.json", finding("ERROR")), result("b.json")],
            tmp_path,
        )
        assert vp.call_args.kwargs["fail_fast"] is False
        assert code == EXIT_VALIDATION_ERROR
        assert len(json.loads(capsys.readouterr().out)) == 2  # output written before failing

    def test_fail_on_implies_continue_and_sets_threshold(self, tmp_path):
        warn = [result("a.json", finding("WARNING"))]
        code, vp = self.run({"fail_on": "warning"}, warn, tmp_path)
        assert vp.call_args.kwargs["fail_fast"] is False
        assert code == EXIT_VALIDATION_ERROR
        code, _ = self.run({"fail_on": "error"}, warn, tmp_path)
        assert code == EXIT_SUCCESS

    def test_fail_on_none_never_fails(self, tmp_path):
        code, _ = self.run({"fail_on": "none"}, [result("a.json", finding("ERROR"))], tmp_path)
        assert code == EXIT_SUCCESS

    def test_options_are_forwarded(self, tmp_path):
        _, vp = self.run(
            {
                "policy_type": "resource",
                "resource_type": "s3-bucket",
                "locale": "ES",
                "max_findings": 7,
            },
            [result("a.json")],
            tmp_path,
        )
        kwargs = vp.call_args.kwargs
        assert kwargs["policy_type"] == "resource"
        assert kwargs["resource_type"] == "s3-bucket"
        assert kwargs["locale"] == "ES"
        assert kwargs["max_findings"] == 7

    def test_check_failure_fails_the_run_after_reporting(self, tmp_path, capsys):
        failing = result("a.json", finding("ERROR", code="CHECK_NO_NEW_ACCESS"))

        def fake_checks(results, *_args, **_kwargs):
            results[:] = [failing]

        with patch(f"{MODULE}.run_policy_checks", side_effect=fake_checks) as checks:
            code, _ = self.run(
                {"check_access_not_granted": True, "deny_actions": ["iam:*"]},
                [result("a.json")],
                tmp_path,
            )
        checks.assert_called_once()
        assert code == EXIT_VALIDATION_ERROR
        assert json.loads(capsys.readouterr().out)[0]["summary"][0]["issueCode"].startswith(
            "CHECK_"
        )

    def test_checks_not_run_unless_requested(self, tmp_path):
        with patch(f"{MODULE}.run_policy_checks") as checks:
            self.run({}, [result("a.json")], tmp_path)
        checks.assert_not_called()

    @pytest.mark.parametrize(
        "exc,code",
        [
            (SdkFeatureError("old boto3"), EXIT_CONFIG_ERROR),
            (ClientError({"Error": {"Code": "Throttling", "Message": "m"}}, "op"), EXIT_AWS_ERROR),
        ],
    )
    def test_aws_and_sdk_errors_map_to_their_exit_codes(self, tmp_path, exc, code):
        with patch(f"{MODULE}.validate_policies", side_effect=exc):
            assert (
                PolicyValidator({"policies_path": str(tmp_path), "dry_run": True}).run() == code
            )

    def test_policy_sets_validate_each_directory_with_its_type(self, tmp_path):
        scp, trust = tmp_path / "scps", tmp_path / "trust"
        scp.mkdir()
        trust.mkdir()
        (scp / "s.json").write_text("{}")
        (trust / "t.json").write_text("{}")

        def fake(files, path, **kwargs):
            return [result(files[0])]

        with patch(f"{MODULE}.validate_policies", side_effect=fake) as vp:
            validator = PolicyValidator(
                {
                    "policies_path": str(tmp_path),
                    "dry_run": True,
                    "policy_sets": [
                        {"path": str(scp), "policy_type": "scp"},
                        {
                            "path": str(trust),
                            "policy_type": "resource",
                            "resource_type": "trust-policy",
                        },
                    ],
                }
            )
            assert validator.run() == EXIT_SUCCESS
        types = [(c.kwargs["policy_type"], c.kwargs["resource_type"]) for c in vp.call_args_list]
        assert types == [("scp", None), ("resource", "trust-policy")]

    def test_output_option_moves_single_report(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        out = tmp_path / "out" / "report.html"
        validator = PolicyValidator(
            {"policies_path": str(tmp_path), "format": "html", "output": str(out)}
        )
        files = validator._generate_reports([result("a.json")])
        assert files == [out] and out.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")

    def test_sarif_format(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        validator = PolicyValidator({"policies_path": str(tmp_path), "format": "sarif"})
        files = validator._generate_reports([result("a.json", finding("WARNING"))])
        assert files[0].suffix == ".sarif"
        assert json.loads(files[0].read_text())["version"] == "2.1.0"


class TestMergedConfigValidation:
    def test_defaults_are_valid(self):
        assert validate_merged_config({}) == []

    @pytest.mark.parametrize(
        "config,fragment",
        [
            ({"policy_type": "bogus"}, "policy_type"),
            ({"locale": "xx"}, "locale"),
            ({"fail_on": "bad"}, "fail_on"),
            ({"max_findings": 0}, "max_findings"),
            ({"resource_type": "s3-bucket"}, "requires policy_type 'resource'"),
            ({"policy_type": "resource", "resource_type": "nope"}, "Unsupported resource_type"),
            ({"check_no_new_access": True}, "reference_path"),
            ({"check_access_not_granted": True}, "deny_actions"),
            (
                {"policy_type": "scp", "check_access_not_granted": True, "deny_actions": ["a:b"]},
                "identity and resource",
            ),
            ({"check_no_public_access": "s3-bucket"}, "requires policy_type 'resource'"),
            ({"policy_sets": [{"policy_type": "scp"}]}, "'path' is required"),
            ({"policy_sets": "oops"}, "policy_sets must be a list"),
        ],
    )
    def test_errors(self, config, fragment):
        assert any(fragment in e for e in validate_merged_config(config))

    def test_valid_checks_configuration(self, tmp_path):
        config = {
            "policy_type": "resource",
            "resource_type": "AWS::S3::Bucket",
            "check_no_new_access": True,
            "reference_path": str(tmp_path),
            "check_access_not_granted": True,
            "deny_resources": "arn:aws:s3:::b",
            "check_no_public_access": "s3-bucket",
        }
        assert validate_merged_config(config) == []

    def test_policy_set_with_resource_type_on_wrong_type(self, tmp_path):
        errors = validate_merged_config(
            {
                "policy_sets": [
                    {"path": str(tmp_path), "policy_type": "scp", "resource_type": "s3-bucket"}
                ]
            }
        )
        assert any("requires policy_type 'resource'" in e for e in errors)

    def test_checks_section_is_flattened_without_overriding_flat_keys(self):
        config = {
            "check_access_not_granted": False,
            "checks": {
                "no_new_access": {"reference_path": "./base", "strict": True},
                "access_not_granted": {"actions": ["iam:*"]},
                "no_public_access": {"resource_type": "s3-bucket"},
            },
        }
        apply_checks_section(config)
        assert config["check_no_new_access"] is True
        assert config["reference_path"] == "./base"
        assert config["strict_references"] is True
        assert config["check_access_not_granted"] is False  # flat key wins
        assert config["check_no_public_access"] == "s3-bucket"


class TestCliOptions:
    def test_new_options_parse(self, tmp_path):
        args = parse_args(
            [
                "-d", str(tmp_path),
                "-t", "resource",
                "--resource-type", "s3-bucket",
                "--locale", "es",
                "--max-findings", "10",
                "-r",
                "--fail-on", "warning",
                "--check-access-not-granted",
                "--deny-actions", "iam:*, s3:Delete*",
                "--deny-resources", "arn:aws:s3:::a,arn:aws:s3:::b",
                "--check-no-public-access", "s3-bucket",
                "--check-no-new-access",
                "--reference-path", str(tmp_path),
                "--strict-references",
                "--continue-on-error",
                "-f", "sarif",
                "-o", str(tmp_path / "r.sarif"),
            ]
        )
        assert args.locale == "ES"
        assert args.max_findings == 10
        assert args.recursive and args.continue_on_error and args.strict_references
        assert args.deny_actions == ["iam:*", "s3:Delete*"]
        assert args.deny_resources == ["arn:aws:s3:::a", "arn:aws:s3:::b"]
        assert args.check_no_public_access == "s3-bucket"

    def test_defaults_are_unset_so_config_can_supply_them(self, tmp_path):
        args = parse_args(["-d", str(tmp_path)])
        for name in ("resource_type", "locale", "max_findings", "fail_on", "reference_path"):
            assert getattr(args, name) is None
        assert not args.recursive and not args.continue_on_error

    def test_bad_reference_path_and_max_findings(self, tmp_path):
        with pytest.raises(SystemExit):
            parse_args(["-d", str(tmp_path), "--reference-path", str(tmp_path / "missing")])
        with pytest.raises(SystemExit):
            parse_args(["-d", str(tmp_path), "--max-findings", "0"])

    def test_sarif_output_extension(self, tmp_path):
        parse_args(["-d", str(tmp_path), "-f", "sarif", "-o", str(tmp_path / "a.json")])
        with pytest.raises(SystemExit):
            parse_args(["-d", str(tmp_path), "-f", "sarif", "-o", str(tmp_path / "a.html")])


class TestMergeAndMain:
    def test_file_values_for_new_options(self, tmp_path):
        cfg = tmp_path / "c.yaml"
        cfg.write_text(
            "policies_path: .\nrecursive: true\nfail_on: warning\nlocale: DE\n"
            "checks:\n  access_not_granted:\n    actions: ['iam:*']\n"
        )
        args = parse_args(["--config", str(cfg)])
        config = merge_config(args)
        assert config["recursive"] is True
        assert config["fail_on"] == "warning"
        assert config["locale"] == "DE"
        assert config["check_access_not_granted"] is True
        assert config["deny_actions"] == ["iam:*"]

    def test_cli_overrides_file_for_new_options(self, tmp_path):
        cfg = tmp_path / "c.yaml"
        cfg.write_text("policies_path: .\nfail_on: warning\n")
        config = merge_config(parse_args(["--config", str(cfg), "--fail-on", "none"]))
        assert config["fail_on"] == "none"

    def test_invalid_merged_config_exits_2(self, tmp_path, monkeypatch):
        cfg = tmp_path / "c.yaml"
        cfg.write_text(f"policies_path: {tmp_path}\ncheck_no_new_access: true\n")
        monkeypatch.setattr(sys, "argv", ["validate-aws-policies", "--config", str(cfg)])
        assert main() == EXIT_CONFIG_ERROR


class TestSarif:
    def test_structure_and_column_shift(self):
        sarif = build_sarif(
            [
                result(
                    "a.json", finding("SECURITY_WARNING", code="R1"), finding("SUGGESTION", "R2")
                ),
                result("b.json"),
            ],
            base_dir="policies",
        )
        run = sarif["runs"][0]
        assert sarif["version"] == "2.1.0"
        assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["R1", "R2"]
        assert run["tool"]["driver"]["rules"][0]["helpUri"].startswith("https://")
        first = run["results"][0]
        assert first["level"] == "warning" and run["results"][1]["level"] == "note"
        loc = first["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "policies/a.json"
        # AA: line 3, column 4..9 (0-based) -> SARIF columns 5..10 (1-based)
        assert loc["region"] == {"startLine": 3, "startColumn": 5, "endLine": 3, "endColumn": 10}
        assert [a["location"]["uri"] for a in run["artifacts"]] == [
            "policies/a.json",
            "policies/b.json",
        ]
        assert len(run["results"]) == 2  # clean policy adds none

    def test_finding_without_location_has_no_region(self):
        sarif = build_sarif([result("a.json", finding("ERROR", spans=False))])
        assert "region" not in sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]


class TestHtmlReport:
    def render(self, results, **kw):
        return render_html(results, **kw)

    def test_escapes_untrusted_content(self):
        evil = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
        doc = self.render(
            [
                {
                    "filePolicy": evil,
                    "summary": [
                        {
                            "policyName": "p",
                            "issueCode": evil,
                            "findingType": "WARNING",
                            "details": {
                                "findingDetails": evil,
                                "learnMoreLink": "javascript:alert(3)",
                            },
                        }
                    ],
                }
            ]
        )
        assert evil not in doc
        assert "<img src=x" not in doc
        assert 'href="javascript:' not in doc
        assert doc.count("<script>") == 1  # only the report's own script

    def test_verdicts(self):
        assert "Validation failed" in self.render([result("a.json", finding("ERROR"))])
        assert "Passed with findings" in self.render([result("a.json", finding("WARNING"))])
        assert "All policies passed" in self.render([result("a.json")])
        assert "All policies passed" in self.render([])

    def test_counts_cards_and_message(self):
        doc = self.render(
            [
                result("a.json", finding("ERROR", message="Broken thing"), finding("WARNING")),
                result("b.json"),
            ]
        )
        assert "Broken thing" in doc  # message read from details (was "No details available")
        assert "No details available" not in doc
        assert 'data-sev="ERROR"' in doc and "Line 3, column 5" in doc
        assert "Learn more" in doc
        assert "Clean" in doc

    def test_custom_check_reasons_and_chips(self):
        failing = result("a.json")
        failing["summary"] = [
            {
                "policyName": "a",
                "issueCode": "CHECK_NO_NEW_ACCESS",
                "findingType": "ERROR",
                "details": {
                    "source": "custom_check",
                    "findingDetails": "New access",
                    "reasons": [{"description": "s3:* added", "statementIndex": 2}],
                },
            }
        ]
        failing["checks"] = [{"name": "CHECK_NO_NEW_ACCESS", "result": "FAIL"}]
        meta = {"checks": ["CheckNoNewAccess"], "tool_version": "9.9.9"}
        doc = self.render([failing], metadata=meta)
        assert "s3:* added" in doc and "index 2" in doc
        assert "CHECK_NO_NEW_ACCESS: FAIL" in doc
        assert "CheckNoNewAccess" in doc and "v9.9.9" in doc

    def test_is_self_contained(self):
        doc = self.render([result("a.json", finding("WARNING"))])
        assert "http-equiv=\"Content-Security-Policy\"" in doc
        for token in ("<link ", "src=\"http", "@import", "url(http"):
            assert token not in doc
        assert "prefers-color-scheme" in doc and "@media print" in doc

    def test_report_file_name_and_metadata(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = ReportGenerator().create_html_report(
            [result("a.json")],
            metadata={"policy_sets": [{"path": "policies", "policy_type": "scp"}], "locale": "EN"},
        )
        assert path.name.startswith("AccessAnalyzerReport_") and path.suffix == ".html"
        text = path.read_text(encoding="utf-8")
        assert "policies" in text and "scp" in text

    def test_markdown_report_shows_real_messages(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = ReportGenerator().create_markdown_report(
            [result("a.json", finding("WARNING", message="Real message")), result("b.json")]
        )
        text = path.read_text(encoding="utf-8")
        assert "Real message" in text and "No details available" not in text
        assert "**Findings:** 1" in text and "Total Findings | 1" in text
