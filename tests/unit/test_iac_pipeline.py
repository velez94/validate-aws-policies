"""Tests for validating IaC inputs through the pipeline (validator, checks, CLI, reports)."""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import boto3
import pytest
from botocore.stub import Stubber

from validate_aws_policies.cli.args import parse_args
from validate_aws_policies.cli.exit_codes import (
    EXIT_CONFIG_ERROR,
    EXIT_FILE_ERROR,
    EXIT_SUCCESS,
    EXIT_VALIDATION_ERROR,
)
from validate_aws_policies.cli.validation import validate_merged_config
from validate_aws_policies.core.validator import PolicyValidator
from validate_aws_policies.iam_access_analyzer.checks import run_policy_checks
from validate_aws_policies.iam_access_analyzer.iam_access_analyzer import validate_policy_documents
from validate_aws_policies.ops.html_report import render_html
from validate_aws_policies.ops.sarif import build_sarif
from validate_aws_policies.validate_policies import main, merge_config

FIXTURES = Path(__file__).parent.parent / "fixtures" / "iac"
TF_PLAN = str(FIXTURES / "terraform" / "plan.json")
CFN_YAML = str(FIXTURES / "cloudformation" / "template.yaml")
PULUMI_PREVIEW = str(FIXTURES / "pulumi" / "preview.json")

MODULE = "validate_aws_policies.core.validator"
DOC = json.dumps({"Version": "2012-10-17", "Statement": []})


@pytest.fixture
def client():
    return boto3.client(
        "accessanalyzer",
        region_name="us-east-1",
        aws_access_key_id="x",
        aws_secret_access_key="x",
    )


def clean(name):
    return {
        "filePolicy": name,
        "summary": [
            {
                "policyName": name,
                "issueCode": "None",
                "findingType": "None",
                "details": "No findings",
            }
        ],
    }


def fake_validate(documents, **kwargs):
    return [clean(name) for name, _text in documents]


# ---------------------------------------------------------------------------
# validate_policy_documents
# ---------------------------------------------------------------------------


class TestValidatePolicyDocuments:
    def test_documents_are_validated_with_their_names(self, client):
        stub = Stubber(client)
        finding = {
            "findingDetails": "d",
            "findingType": "WARNING",
            "issueCode": "X",
            "learnMoreLink": "https://example.com",
            "locations": [],
        }
        params = {
            "policyDocument": DOC,
            "policyType": "RESOURCE_POLICY",
            "locale": "EN",
            "validatePolicyResourceType": "AWS::S3::Bucket",
            "maxResults": 20,
        }
        stub.add_response("validate_policy", {"findings": [finding]}, params)
        stub.add_response("validate_policy", {"findings": []}, params)
        with stub:
            report = validate_policy_documents(
                [("module.x.aws_s3_bucket_policy.a", DOC), ("aws_s3_bucket_policy.b", DOC)],
                policy_type="resource",
                resource_type="s3-bucket",
                client=client,
            )
        assert [r["filePolicy"] for r in report] == [
            "module.x.aws_s3_bucket_policy.a",
            "aws_s3_bucket_policy.b",
        ]
        # the whole resource address is the name, not just the part after the last dot
        assert report[0]["summary"][0]["policyName"] == "module.x.aws_s3_bucket_policy.a"

    def test_error_findings_respect_fail_fast(self, client):
        error = {
            "findingDetails": "bad",
            "findingType": "ERROR",
            "issueCode": "E",
            "learnMoreLink": "https://example.com",
            "locations": [],
        }
        for fail_fast, raises in ((True, True), (False, False)):
            stub = Stubber(client)
            stub.add_response("validate_policy", {"findings": [error]})
            with stub:
                if raises:
                    with pytest.raises(ValueError):
                        validate_policy_documents([("a", DOC)], client=client, fail_fast=fail_fast)
                else:
                    report = validate_policy_documents([("a", DOC)], client=client, fail_fast=False)
                    assert report[0]["summary"][0]["findingType"] == "ERROR"

    def test_nothing_to_validate(self):
        assert validate_policy_documents([]) == []

    def test_option_errors(self, client):
        with pytest.raises(ValueError):
            validate_policy_documents([("a", DOC)], resource_type="s3-bucket", client=client)
        with pytest.raises(ValueError):
            validate_policy_documents([("a", DOC)], locale="xx", client=client)


# ---------------------------------------------------------------------------
# Custom checks on in-memory documents
# ---------------------------------------------------------------------------


class TestChecksWithDocuments:
    def test_no_new_access_uses_reference_documents(self, client):
        stub = Stubber(client)
        stub.add_response(
            "check_no_new_access",
            {"result": "FAIL", "message": "new access", "reasons": []},
            {
                "existingPolicyDocument": '{"old": true}',
                "newPolicyDocument": DOC,
                "policyType": "IDENTITY_POLICY",
            },
        )
        results = [{**clean("aws_iam_policy.a"), "source": {"type": "terraform-plan"}}]
        with stub:
            run_policy_checks(
                results,
                None,
                "identity",
                {"check_no_new_access": True},
                client=client,
                documents={"aws_iam_policy.a": DOC},
                reference_documents={"aws_iam_policy.a": '{"old": true}'},
            )
        entry = results[0]["summary"][0]
        assert entry["issueCode"] == "CHECK_NO_NEW_ACCESS"
        # the resource address is the policy name; it is not cut at the last dot
        assert entry["policyName"] == "aws_iam_policy.a"

    def test_missing_baseline_entry(self, client):
        for strict in (False, True):
            results = [clean("aws_iam_policy.new")]
            with Stubber(client):
                run_policy_checks(
                    results,
                    None,
                    "identity",
                    {"check_no_new_access": True, "strict_references": strict},
                    client=client,
                    documents={"aws_iam_policy.new": DOC},
                    reference_documents={},
                )
            if strict:
                assert "reference input" in results[0]["summary"][0]["details"]["message"]
            else:
                assert results[0]["checks"][0]["result"] == "SKIPPED"

    def test_documents_not_in_the_mapping_are_skipped(self, client):
        results = [clean("other")]
        with Stubber(client):
            run_policy_checks(
                results,
                None,
                "identity",
                {"check_access_not_granted": True, "deny_actions": ["a:b"]},
                client=client,
                documents={},
            )
        assert "checks" not in results[0]

    def test_directory_or_documents_is_required(self, client):
        with pytest.raises(ValueError):
            run_policy_checks(
                [clean("a")],
                None,
                "identity",
                {"check_access_not_granted": True, "deny_actions": ["a:b"]},
                client=client,
            )


# ---------------------------------------------------------------------------
# PolicyValidator with IaC inputs
# ---------------------------------------------------------------------------


def iac_config(**extra):
    return {"input": [TF_PLAN], "dry_run": True, "format": "json", **extra}


class TestValidatorIac:
    def run(self, config, capsys=None):
        with patch(f"{MODULE}.validate_policy_documents", side_effect=fake_validate) as validate:
            code = PolicyValidator(config).run()
        return code, validate

    def test_documents_are_grouped_by_type(self):
        code, validate = self.run(iac_config())
        assert code == EXIT_SUCCESS
        groups = {
            (c.kwargs["policy_type"], c.kwargs["resource_type"]): [n for n, _t in c.args[0]]
            for c in validate.call_args_list
        }
        assert groups[("identity", None)] == [
            "aws_iam_policy.deploy",
            "aws_iam_policy.too_broad",
            "aws_iam_role_policy.app_inline",
        ]
        assert groups[("resource", "trust-policy")] == ["aws_iam_role.app#assume_role_policy"]
        assert groups[("resource", "s3-bucket")] == ["aws_s3_bucket_policy.public"]
        assert groups[("scp", None)] == ["aws_organizations_policy.deny_regions"]
        assert groups[("resource", None)] == ["module.queue.aws_sqs_queue_policy.q"]

    def test_options_are_forwarded(self):
        _, validate = self.run(iac_config(locale="ES", max_findings=5, continue_on_error=True))
        kwargs = validate.call_args.kwargs
        assert (kwargs["locale"], kwargs["max_findings"], kwargs["fail_fast"]) == ("ES", 5, False)

    def test_results_carry_the_source(self, capsys):
        self.run(iac_config())
        results = json.loads(capsys.readouterr().out)
        first = next(r for r in results if r["filePolicy"] == "aws_iam_policy.deploy")
        assert first["source"] == {
            "type": "terraform-plan",
            "file": TF_PLAN,
            "resourceType": "aws_iam_policy",
        }

    def test_unknown_policies_are_listed_in_text_output(self, capsys):
        self.run(iac_config(format="text"))
        out = capsys.readouterr().out
        assert "Skipped (value not known before deployment):" in out
        assert "aws_s3_bucket_policy.logs" in out

    def test_unknown_values_fail(self):
        code, _ = self.run(iac_config(unknown_values="fail"))
        assert code == EXIT_VALIDATION_ERROR
        code, _ = self.run(iac_config(unknown_values="skip"))
        assert code == EXIT_SUCCESS

    def test_no_policies_found(self, tmp_path):
        empty = tmp_path / "t.json"
        empty.write_text(json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}))
        code, validate = self.run({"input": [str(empty)], "dry_run": True})
        assert code == EXIT_SUCCESS
        validate.assert_not_called()

    def test_missing_input_is_a_file_error_and_bad_input_a_config_error(self, tmp_path):
        assert (
            self.run({"input": [str(tmp_path / "x.json")], "dry_run": True})[0] == EXIT_FILE_ERROR
        )
        junk = tmp_path / "junk.json"
        junk.write_text('{"hello": 1}')
        assert self.run({"input": [str(junk)], "dry_run": True})[0] == EXIT_CONFIG_ERROR

    def test_cloudformation_parameters_and_region(self, monkeypatch):
        monkeypatch.setenv("AWS_REGION", "eu-west-1")
        _, validate = self.run(
            {"input": [CFN_YAML], "dry_run": True, "params": {"BucketName": "mine"}}
        )
        texts = {n: t for c in validate.call_args_list for n, t in c.args[0]}
        assert "arn:aws:s3:::mine/*" in texts["AppRole#Policies[2]"]
        assert "eu-west-1" in texts["AppRole#Policies[0]"]

    def test_only_changed_reaches_the_extractor(self):
        _, validate = self.run({"input": [PULUMI_PREVIEW], "dry_run": True, "only_changed": True})
        names = [n for c in validate.call_args_list for n, _t in c.args[0]]
        assert "aws:iam/policy:Policy::unchanged" not in names

    def test_findings_fail_the_run_by_threshold(self):
        def with_warning(documents, **kwargs):
            results = fake_validate(documents, **kwargs)
            results[0]["summary"] = [
                {"policyName": "x", "issueCode": "W", "findingType": "WARNING", "details": {}}
            ]
            return results

        with patch(f"{MODULE}.validate_policy_documents", side_effect=with_warning):
            assert PolicyValidator(iac_config(fail_on="warning")).run() == EXIT_VALIDATION_ERROR
        with patch(f"{MODULE}.validate_policy_documents", side_effect=with_warning):
            assert PolicyValidator(iac_config(fail_on="error")).run() == EXIT_SUCCESS

    def test_checks_receive_documents_and_baseline(self, tmp_path):
        baseline = {
            "format_version": "1.2",
            "resource_changes": [
                {
                    "address": "aws_iam_policy.deploy",
                    "mode": "managed",
                    "type": "aws_iam_policy",
                    "name": "deploy",
                    "change": {"actions": ["create"], "after": {"policy": '{"base": 1}'}},
                }
            ],
        }
        path = tmp_path / "baseline.json"
        path.write_text(json.dumps(baseline))
        with patch(f"{MODULE}.validate_policy_documents", side_effect=fake_validate), patch(
            f"{MODULE}.run_policy_checks"
        ) as checks:
            PolicyValidator(iac_config(check_no_new_access=True, reference_input=[str(path)])).run()
        assert checks.call_count == 5  # one call per policy type group
        kwargs = checks.call_args.kwargs
        assert kwargs["reference_documents"] == {"aws_iam_policy.deploy": '{"base": 1}'}
        assert "aws_iam_policy.deploy" in checks.call_args_list[0].kwargs["documents"]

    def test_file_mode_is_unchanged(self, tmp_path):
        (tmp_path / "a.json").write_text("{}")
        with patch(f"{MODULE}.validate_policies", return_value=[clean("a.json")]) as validate:
            code = PolicyValidator(
                {"policies_path": str(tmp_path), "dry_run": True, "format": "json"}
            ).run()
        assert code == EXIT_SUCCESS
        validate.assert_called_once()


# ---------------------------------------------------------------------------
# CLI and config
# ---------------------------------------------------------------------------


class TestCli:
    def test_iac_flags_parse(self, tmp_path):
        args = parse_args(
            [
                "--input", "a.json", "b.yaml",
                "--source", "cloudformation",
                "--reference-input", "base.json",
                "--param", "Env=prod", "--param", "Name=a=b",
                "--unknown-values", "fail",
                "--only-changed",
            ]
        )  # fmt: skip
        assert args.input == ["a.json", "b.yaml"]
        assert args.source == "cloudformation"
        assert args.reference_input == ["base.json"]
        assert args.param == [("Env", "prod"), ("Name", "a=b")]
        assert args.unknown_values == "fail" and args.only_changed

    def test_policies_path_is_not_needed_with_input_but_conflicts_with_it(self, tmp_path):
        assert parse_args(["-i", "plan.json"]).input == ["plan.json"]
        with pytest.raises(SystemExit):
            parse_args(["-i", "plan.json", "-d", str(tmp_path)])
        with pytest.raises(SystemExit):
            parse_args([])

    def test_bad_param_and_source(self):
        with pytest.raises(SystemExit):
            parse_args(["-i", "p.json", "--param", "novalue"])
        with pytest.raises(SystemExit):
            parse_args(["-i", "p.json", "--source", "ansible"])

    def test_merge_config(self, tmp_path):
        cfg = tmp_path / "c.yaml"
        cfg.write_text(
            "input: plan.json\nsource: terraform-plan\nparams: {Env: dev, Keep: x}\n"
            "only_changed: true\nreference_input: [base.json]\n"
        )
        config = merge_config(parse_args(["--config", str(cfg), "--param", "Env=prod"]))
        assert config["input"] == ["plan.json"]
        assert config["reference_input"] == ["base.json"]
        assert config["params"] == {"Env": "prod", "Keep": "x"}
        assert config["only_changed"] is True and config["source"] == "terraform-plan"

    def test_command_line_input_beats_file(self, tmp_path):
        cfg = tmp_path / "c.yaml"
        cfg.write_text("input: from-file.json\n")
        config = merge_config(
            parse_args(["--config", str(cfg), "-i", "cli.json", "--source", "pulumi"])
        )
        assert config["input"] == ["cli.json"] and config["source"] == "pulumi"

    def test_validation_rules(self, tmp_path):
        assert validate_merged_config({"input": ["p.json"]}) == []
        errors = validate_merged_config(
            {"input": ["p.json"], "policy_sets": [{"path": str(tmp_path)}], "source": "ansible"}
        )
        assert any("policy_sets" in e for e in errors) and any("source" in e for e in errors)
        assert any("unknown_values" in e for e in validate_merged_config({"unknown_values": "x"}))
        # checks on IaC need a baseline input, not a reference directory
        errors = validate_merged_config({"input": ["p.json"], "check_no_new_access": True})
        assert any("reference_input" in e for e in errors)
        assert not validate_merged_config(
            {"input": ["p.json"], "check_no_new_access": True, "reference_input": ["b.json"]}
        )
        # policy and resource types come from the resource map, so they are not rejected
        assert not validate_merged_config(
            {"input": ["p.json"], "check_no_public_access": "s3-bucket", "resource_type": "x"}
        )

    def test_main_end_to_end(self, capsys, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["validate-aws-policies", "-i", TF_PLAN, "--dry-run"])
        with patch(f"{MODULE}.validate_policy_documents", side_effect=fake_validate):
            assert main() == EXIT_SUCCESS
        results = json.loads(capsys.readouterr().out)
        assert len(results) == 7

    def test_main_reports_unrecognized_input_as_config_error(self, tmp_path, monkeypatch):
        junk = tmp_path / "junk.json"
        junk.write_text('{"hello": 1}')
        monkeypatch.setattr(sys, "argv", ["validate-aws-policies", "-i", str(junk), "--dry-run"])
        assert main() == EXIT_CONFIG_ERROR


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

SPAN = {
    "path": [],
    "span": {
        "start": {"line": 1, "column": 2, "offset": 2},
        "end": {"line": 1, "column": 8, "offset": 8},
    },
}


def iac_result(name="aws_iam_policy.a", file="plan.json"):
    return {
        "filePolicy": name,
        "summary": [
            {
                "policyName": name,
                "issueCode": "MISSING_VERSION",
                "findingType": "WARNING",
                "details": {"findingDetails": "msg", "locations": [SPAN]},
            }
        ],
        "source": {"type": "terraform-plan", "file": file, "resourceType": "aws_iam_policy"},
    }


class TestIacReports:
    def test_sarif_uses_the_input_file_and_a_logical_location(self):
        sarif = build_sarif([iac_result(), iac_result("aws_iam_policy.b")], base_dir="ignored")
        run = sarif["runs"][0]
        assert [a["location"]["uri"] for a in run["artifacts"]] == ["plan.json"]  # once
        first = run["results"][0]
        location = first["locations"][0]
        assert location["physicalLocation"]["artifactLocation"]["uri"] == "plan.json"
        assert "region" not in location["physicalLocation"]  # spans refer to the embedded JSON
        assert location["logicalLocations"][0]["name"] == "aws_iam_policy.a"
        assert first["message"]["text"].startswith("aws_iam_policy.a: ")

    def test_sarif_for_files_is_unchanged(self):
        result = {k: v for k, v in iac_result("p.json").items() if k != "source"}
        sarif = build_sarif([result], base_dir="policies")
        location = sarif["runs"][0]["results"][0]["locations"][0]
        assert location["physicalLocation"]["artifactLocation"]["uri"] == "policies/p.json"
        assert "region" in location["physicalLocation"] and "logicalLocations" not in location

    def test_html_shows_source_inputs_and_skipped(self):
        document = render_html(
            [iac_result()],
            metadata={
                "inputs": [{"file": "plan.json", "type": "terraform-plan", "policies": 1}],
                "skipped": [{"id": "aws_s3_bucket_policy.logs", "reason": "not known until apply"}],
            },
        )
        assert "terraform-plan" in document and "aws_iam_policy" in document
        assert "Inputs" in document and "plan.json" in document
        assert "Not validated" in document and "aws_s3_bucket_policy.logs" in document
        assert "not known until apply" in document

    def test_html_escapes_iac_values(self):
        evil = "<script>alert(1)</script>"
        result = iac_result(evil, file=evil)
        document = render_html(
            [result],
            metadata={"skipped": [{"id": evil, "reason": evil}], "inputs": [{"file": evil}]},
        )
        assert evil not in document
