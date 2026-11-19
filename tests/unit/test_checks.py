"""Tests for custom policy checks, feature detection and the new validate_policies options.

AWS calls are stubbed with botocore's Stubber against the real service model, so the
tests fail if a request does not match the Access Analyzer API shape.
"""

import json
from unittest.mock import patch

import boto3
import pytest
from botocore.stub import Stubber

from validate_aws_policies.iam_access_analyzer import checks as checks_mod
from validate_aws_policies.iam_access_analyzer.checks import run_policy_checks
from validate_aws_policies.iam_access_analyzer.features import (
    SdkFeatureError,
    ensure_enum_value,
    ensure_operation,
    enum_values,
    normalize_resource_type,
)
from validate_aws_policies.iam_access_analyzer.iam_access_analyzer import validate_policies

DOC = json.dumps({"Version": "2012-10-17", "Statement": []})


@pytest.fixture
def client():
    return boto3.client(
        "accessanalyzer",
        region_name="us-east-1",
        aws_access_key_id="x",
        aws_secret_access_key="x",
    )


def clean_result(name="a.json"):
    return {
        "filePolicy": name,
        "summary": [
            {
                "policyName": "a",
                "issueCode": "None",
                "findingType": "None",
                "details": "No findings",
            }
        ],
    }


@pytest.fixture
def policies(tmp_path):
    (tmp_path / "a.json").write_text(DOC)
    ref = tmp_path / "ref"
    ref.mkdir()
    (ref / "a.json").write_text(DOC)
    return tmp_path


class TestCheckNoNewAccess:
    def test_pass(self, client, policies):
        stub = Stubber(client)
        stub.add_response(
            "check_no_new_access",
            {"result": "PASS", "message": "No new access", "reasons": []},
            {
                "existingPolicyDocument": DOC,
                "newPolicyDocument": DOC,
                "policyType": "IDENTITY_POLICY",
            },
        )
        results = [clean_result()]
        with stub:
            run_policy_checks(
                results,
                policies,
                "identity",
                {"check_no_new_access": True, "reference_path": str(policies / "ref")},
                client=client,
            )
        assert results[0]["checks"][0]["result"] == "PASS"
        assert results[0]["summary"][0]["findingType"] == "None"  # placeholder kept

    def test_fail_adds_error_and_removes_placeholder(self, client, policies):
        stub = Stubber(client)
        stub.add_response(
            "check_no_new_access",
            {
                "result": "FAIL",
                "message": "The modified permissions grant new access.",
                "reasons": [
                    {"description": "New access s3:*", "statementIndex": 1, "statementId": "S1"}
                ],
            },
            {
                "existingPolicyDocument": DOC,
                "newPolicyDocument": DOC,
                "policyType": "IDENTITY_POLICY",
            },
        )
        results = [clean_result()]
        with stub:
            run_policy_checks(
                results,
                policies,
                "identity",
                {"check_no_new_access": True, "reference_path": str(policies / "ref")},
                client=client,
            )
        summary = results[0]["summary"]
        assert len(summary) == 1
        assert summary[0]["issueCode"] == "CHECK_NO_NEW_ACCESS"
        assert summary[0]["findingType"] == "ERROR"
        assert summary[0]["details"]["source"] == "custom_check"
        assert summary[0]["details"]["reasons"][0]["statementId"] == "S1"
        assert results[0]["checks"][0]["result"] == "FAIL"

    def test_resource_policy_type_is_sent(self, client, policies):
        stub = Stubber(client)
        stub.add_response(
            "check_no_new_access",
            {"result": "PASS", "message": "", "reasons": []},
            {
                "existingPolicyDocument": DOC,
                "newPolicyDocument": DOC,
                "policyType": "RESOURCE_POLICY",
            },
        )
        with stub:
            run_policy_checks(
                [clean_result()],
                policies,
                "resource",
                {"check_no_new_access": True, "reference_path": str(policies / "ref")},
                client=client,
            )

    def test_missing_reference_is_skipped_by_default(self, client, policies):
        (policies / "ref" / "a.json").unlink()
        results = [clean_result()]
        with Stubber(client):  # no API call expected
            run_policy_checks(
                results,
                policies,
                "identity",
                {"check_no_new_access": True, "reference_path": str(policies / "ref")},
                client=client,
            )
        assert results[0]["checks"][0]["result"] == "SKIPPED"
        assert results[0]["summary"][0]["findingType"] == "None"

    def test_missing_reference_fails_when_strict(self, client, policies):
        (policies / "ref" / "a.json").unlink()
        results = [clean_result()]
        with Stubber(client):
            run_policy_checks(
                results,
                policies,
                "identity",
                {
                    "check_no_new_access": True,
                    "reference_path": str(policies / "ref"),
                    "strict_references": True,
                },
                client=client,
            )
        assert results[0]["summary"][0]["issueCode"] == "CHECK_NO_NEW_ACCESS"
        assert "No reference policy" in results[0]["summary"][0]["details"]["message"]


class TestOtherChecks:
    def test_access_not_granted_request_shape(self, client, policies):
        stub = Stubber(client)
        stub.add_response(
            "check_access_not_granted",
            {"result": "FAIL", "message": "grants iam:*", "reasons": []},
            {
                "policyDocument": DOC,
                "access": [{"actions": ["iam:*"], "resources": ["arn:aws:s3:::b"]}],
                "policyType": "IDENTITY_POLICY",
            },
        )
        results = [clean_result()]
        with stub:
            run_policy_checks(
                results,
                policies,
                "identity",
                {
                    "check_access_not_granted": True,
                    "deny_actions": ["iam:*"],
                    "deny_resources": ["arn:aws:s3:::b"],
                },
                client=client,
            )
        assert results[0]["summary"][0]["issueCode"] == "CHECK_ACCESS_NOT_GRANTED"

    def test_access_not_granted_actions_only(self, client, policies):
        stub = Stubber(client)
        stub.add_response(
            "check_access_not_granted",
            {"result": "PASS", "message": "", "reasons": []},
            {
                "policyDocument": DOC,
                "access": [{"actions": ["s3:Delete*"]}],
                "policyType": "IDENTITY_POLICY",
            },
        )
        with stub:
            run_policy_checks(
                [clean_result()],
                policies,
                "identity",
                {"check_access_not_granted": True, "deny_actions": ["s3:Delete*"]},
                client=client,
            )

    @pytest.mark.parametrize("given", ["s3-bucket", "AWS::S3::Bucket", "aws-s3-bucket"])
    def test_no_public_access(self, client, policies, given):
        stub = Stubber(client)
        stub.add_response(
            "check_no_public_access",
            {"result": "FAIL", "message": "public", "reasons": [{"description": "Principal *"}]},
            {"policyDocument": DOC, "resourceType": "AWS::S3::Bucket"},
        )
        results = [clean_result()]
        with stub:
            run_policy_checks(
                results,
                policies,
                "resource",
                {"check_no_public_access": given},
                client=client,
            )
        assert results[0]["summary"][0]["issueCode"] == "CHECK_NO_PUBLIC_ACCESS"

    def test_no_public_access_is_skipped_for_identity_policies(self, client, policies):
        results = [clean_result()]
        with Stubber(client):
            run_policy_checks(
                results,
                policies,
                "identity",
                {"check_no_public_access": "s3-bucket"},
                client=client,
            )
        assert "checks" not in results[0]

    @pytest.mark.parametrize("kind", ["scp", "rcp"])
    def test_unsupported_policy_types_are_skipped(self, client, policies, kind):
        results = [clean_result()]
        with Stubber(client):
            run_policy_checks(
                results, policies, kind, {"check_access_not_granted": True, "deny_actions": ["a:b"]}
            )
        assert "checks" not in results[0]

    def test_public_access_skipped_for_sets_of_another_resource_type(self, client, policies):
        results = [clean_result()]
        with Stubber(client):  # no API call expected
            run_policy_checks(
                results,
                policies,
                "resource",
                {"check_no_public_access": "s3-bucket"},
                client=client,
                resource_type="trust-policy",
            )
        assert "checks" not in results[0]

    def test_public_access_runs_for_sets_of_the_same_resource_type(self, client, policies):
        stub = Stubber(client)
        stub.add_response(
            "check_no_public_access",
            {"result": "PASS", "message": "", "reasons": []},
            {"policyDocument": DOC, "resourceType": "AWS::S3::Bucket"},
        )
        results = [clean_result()]
        with stub:
            run_policy_checks(
                results,
                policies,
                "resource",
                {"check_no_public_access": "AWS::S3::Bucket"},
                client=client,
                resource_type="s3-bucket",
            )
        assert results[0]["checks"][0]["result"] == "PASS"

    def test_policies_with_errors_are_not_checked(self, client, policies):
        results = [
            {
                "filePolicy": "a.json",
                "summary": [{"policyName": "a", "issueCode": "X", "findingType": "ERROR"}],
            }
        ]
        with Stubber(client):  # an API call would raise
            run_policy_checks(
                results,
                policies,
                "identity",
                {"check_access_not_granted": True, "deny_actions": ["a:b"]},
                client=client,
            )
        assert "checks" not in results[0]

    def test_nothing_requested_does_nothing(self, policies):
        results = [clean_result()]
        run_policy_checks(results, policies, "identity", {})
        assert "checks" not in results[0]

    def test_client_created_with_retries_when_not_given(self, policies):
        with patch.object(checks_mod, "get_client") as get_client:
            get_client.return_value.meta.service_model.operation_names = ["CheckNoPublicAccess"]
            get_client.return_value.meta.service_model.shape_for.side_effect = KeyError
            get_client.return_value.check_no_public_access.return_value = {"result": "PASS"}
            run_policy_checks(
                [clean_result()], policies, "resource", {"check_no_public_access": "x"}
            )
        get_client.assert_called_once()


class TestFeatureDetection:
    def test_missing_operation(self, client):
        with patch.object(client.meta.service_model, "_service_description", {}):
            pass  # real model has the operation
        ensure_operation(client, "CheckNoNewAccess")
        with pytest.raises(SdkFeatureError, match="Upgrade"):
            ensure_operation(client, "CheckSomethingNew")

    def test_old_sdk_without_operation_gives_config_error_message(self, policies):
        class Old:
            class meta:  # noqa: N801
                class service_model:  # noqa: N801
                    operation_names = ["ValidatePolicy"]

        with pytest.raises(SdkFeatureError, match="CheckNoNewAccess"):
            run_policy_checks(
                [clean_result()],
                policies,
                "identity",
                {"check_no_new_access": True, "reference_path": str(policies)},
                client=Old(),
            )

    def test_enum_value_checked_against_model(self, client):
        shape = "ValidatePolicyRequest"
        known = enum_values(client, shape, "policyType") or []
        if "RESOURCE_CONTROL_POLICY" not in known:
            pytest.skip("installed boto3 predates resource control policies")
        ensure_enum_value(client, shape, "policyType", "RESOURCE_CONTROL_POLICY", "x")
        with pytest.raises(SdkFeatureError):
            ensure_enum_value(client, "ValidatePolicyRequest", "policyType", "NOPE", "Policy type")

    def test_normalize_resource_type(self):
        allowed = ["AWS::S3::Bucket", "AWS::KMS::Key", "AWS::SQS::Queue"]
        assert normalize_resource_type("kms-key", allowed) == "AWS::KMS::Key"
        assert normalize_resource_type("S3-Bucket", allowed) == "AWS::S3::Bucket"
        assert normalize_resource_type("AWS::SQS::Queue", allowed) == "AWS::SQS::Queue"
        with pytest.raises(ValueError):
            normalize_resource_type("ec2-instance", allowed)


class TestValidatePoliciesOptions:
    def call(self, client, tmp_path, findings=None, **kwargs):
        (tmp_path / "p.json").write_text(DOC)
        stub = Stubber(client)
        expected = {
            "policyDocument": DOC,
            "policyType": kwargs.pop("api_type", "IDENTITY_POLICY"),
            "locale": kwargs.pop("api_locale", "EN"),
            "maxResults": 20,
        }
        expected.update(kwargs.pop("extra", {}))
        stub.add_response("validate_policy", {"findings": findings or []}, expected)
        with stub:
            return validate_policies(["p.json"], tmp_path, client=client, **kwargs)

    def test_defaults_are_backward_compatible(self, client, tmp_path):
        self.call(client, tmp_path)

    def test_resource_type_and_locale(self, client, tmp_path):
        self.call(
            client,
            tmp_path,
            policy_type="resource",
            resource_type="s3-bucket",
            locale="es",
            api_type="RESOURCE_POLICY",
            api_locale="ES",
            extra={"validatePolicyResourceType": "AWS::S3::Bucket"},
        )

    def test_rcp(self, client, tmp_path):
        known = enum_values(client, "ValidatePolicyRequest", "policyType") or []
        if "RESOURCE_CONTROL_POLICY" not in known:
            # Old boto3 (for example the 1.34.138 floor): clear error instead of a crash
            with pytest.raises(SdkFeatureError, match="Upgrade"):
                validate_policies([], tmp_path, policy_type="rcp", client=client)
            return
        self.call(client, tmp_path, policy_type="rcp", api_type="RESOURCE_CONTROL_POLICY")

    def test_resource_type_requires_resource_policy(self, client, tmp_path):
        with pytest.raises(ValueError, match="resource"):
            validate_policies([], tmp_path, resource_type="s3-bucket", client=client)

    def test_invalid_locale_and_max_findings(self, client, tmp_path):
        with pytest.raises(ValueError):
            validate_policies([], tmp_path, locale="xx", client=client)
        with pytest.raises(ValueError):
            validate_policies([], tmp_path, max_findings=0, client=client)

    def test_all_findings_are_collected_across_pages(self, client, tmp_path):
        (tmp_path / "p.json").write_text(DOC)
        finding = {
            "findingDetails": "d",
            "findingType": "WARNING",
            "issueCode": "X",
            "learnMoreLink": "https://example.com",
            "locations": [],
        }
        stub = Stubber(client)
        # 6 pages of 20 findings: more than the 100-finding cap the tool used to apply
        pages = [
            {"findings": [dict(finding) for _ in range(20)], "nextToken": f"t{i}"}
            for i in range(5)
        ]
        pages.append({"findings": [dict(finding) for _ in range(20)]})
        for page in pages:
            stub.add_response("validate_policy", page)
        with stub:
            result = validate_policies(["p.json"], tmp_path, client=client, fail_fast=False)
        assert len(result[0]["summary"]) == 120

    def test_max_findings_limits_collection(self, client, tmp_path):
        (tmp_path / "p.json").write_text(DOC)
        finding = {
            "findingDetails": "d",
            "findingType": "WARNING",
            "issueCode": "X",
            "learnMoreLink": "https://example.com",
            "locations": [],
        }
        stub = Stubber(client)
        stub.add_response(
            "validate_policy",
            {"findings": [dict(finding) for _ in range(20)], "nextToken": "t"},
        )
        with stub:
            result = validate_policies(
                ["p.json"], tmp_path, client=client, max_findings=5, fail_fast=False
            )
        assert len(result[0]["summary"]) == 5

    def test_fail_fast_false_keeps_error_findings(self, client, tmp_path):
        error = {
            "findingDetails": "bad",
            "findingType": "ERROR",
            "issueCode": "E",
            "learnMoreLink": "https://example.com",
            "locations": [],
        }
        (tmp_path / "p.json").write_text(DOC)
        stub = Stubber(client)
        stub.add_response("validate_policy", {"findings": [error]})
        with stub:
            result = validate_policies(["p.json"], tmp_path, client=client, fail_fast=False)
        assert result[0]["summary"][0]["findingType"] == "ERROR"

        stub2 = Stubber(client)
        stub2.add_response("validate_policy", {"findings": [error]})
        with stub2, pytest.raises(ValueError):
            validate_policies(["p.json"], tmp_path, client=client)

    def test_recursive_relative_names(self, client, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "n.json").write_text(DOC)
        stub = Stubber(client)
        stub.add_response("validate_policy", {"findings": []})
        with stub:
            result = validate_policies(["sub/n.json"], tmp_path, client=client)
        assert result[0]["filePolicy"] == "sub/n.json"
