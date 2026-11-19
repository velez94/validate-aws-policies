"""Tests for the IaC extractors: Terraform/OpenTofu, CloudFormation and Pulumi."""

import json
import logging
from pathlib import Path

import pytest

from validate_aws_policies.sources import (
    CLOUDFORMATION,
    PULUMI,
    TERRAFORM,
    ExtractOptions,
    SourceError,
    detect_source,
    extract,
)
from validate_aws_policies.sources.base import MapEntry, document_id, policy_text, walk_path
from validate_aws_policies.sources.cloudformation import (
    Resolver,
    Unresolved,
    extract_cloudformation,
    load_template,
)
from validate_aws_policies.sources.pulumi import UNKNOWN_MARKER, extract_pulumi
from validate_aws_policies.sources.terraform import extract_terraform

FIXTURES = Path(__file__).parent.parent / "fixtures" / "iac"
TF_PLAN = FIXTURES / "terraform" / "plan.json"
TOFU_PLAN = FIXTURES / "terraform" / "tofu-plan.json"
CFN_YAML = FIXTURES / "cloudformation" / "template.yaml"
CFN_JSON = FIXTURES / "cloudformation" / "template.json"
PULUMI_EXPORT = FIXTURES / "pulumi" / "stack-export.json"
PULUMI_PREVIEW = FIXTURES / "pulumi" / "preview.json"


def ids(result):
    return sorted(d.id for d in result.documents)


def by_id(result):
    return {d.id: d for d in result.documents}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestWalkPath:
    def test_simple_and_fan_out(self):
        value = {"a": {"b": "x"}, "items": [{"p": "1"}, {"p": "2"}]}
        assert [r[2] for r in walk_path(value, None, ["a", "b"])] == ["x"]
        leaves = list(walk_path(value, None, ["items[*]", "p"]))
        assert [(r[0], r[1], r[2]) for r in leaves] == [((0,), "items", "1"), ((1,), "items", "2")]

    def test_unknown_mask(self):
        leaves = list(walk_path({}, {"policy": True}, ["policy"]))
        assert leaves == [((), None, None, True)]
        leaves = list(
            walk_path({"items": [{"p": "1"}, {}]}, {"items": [{}, {"p": True}]}, ["items[*]", "p"])
        )
        assert [(r[0], r[3]) for r in leaves] == [((0,), False), ((1,), True)]

    def test_missing_paths_yield_nothing(self):
        assert list(walk_path({"a": 1}, None, ["b"])) == []
        assert list(walk_path({"a": "text"}, None, ["a", "b"])) == []
        assert list(walk_path({"items": "no-list"}, None, ["items[*]", "p"])) == []

    def test_document_id(self):
        plain = MapEntry("t", "policy", "identity")
        labelled = MapEntry("t", "x", "identity", label="trust")
        fan = MapEntry("t", "items[*].p", "identity")
        assert document_id("a.b", plain, (), None) == "a.b"
        assert document_id("a.b", labelled, (), None) == "a.b#trust"
        assert document_id("a.b", fan, (1,), "items") == "a.b#items[1]"

    def test_policy_text(self):
        assert policy_text(None) is None and policy_text("  ") is None and policy_text(5) is None
        assert policy_text('{"a": 1}') == '{"a": 1}'
        assert json.loads(policy_text({"a": 1})) == {"a": 1}


# ---------------------------------------------------------------------------
# Terraform and OpenTofu
# ---------------------------------------------------------------------------


class TestTerraform:
    def test_real_plan_documents(self):
        result = extract([str(TF_PLAN)])
        assert ids(result) == [
            "aws_iam_policy.deploy",
            "aws_iam_policy.too_broad",
            "aws_iam_role.app#assume_role_policy",
            "aws_iam_role_policy.app_inline",
            "aws_organizations_policy.deny_regions",
            "aws_s3_bucket_policy.public",
            "module.queue.aws_sqs_queue_policy.q",
        ]
        docs = by_id(result)
        assert docs["aws_iam_policy.deploy"].policy_type == "identity"
        trust = docs["aws_iam_role.app#assume_role_policy"]
        assert (trust.policy_type, trust.resource_type) == ("resource", "trust-policy")
        bucket = docs["aws_s3_bucket_policy.public"]
        assert (bucket.policy_type, bucket.resource_type) == ("resource", "s3-bucket")
        assert docs["aws_organizations_policy.deny_regions"].policy_type == "scp"
        assert docs["module.queue.aws_sqs_queue_policy.q"].resource_type is None
        assert all(d.source_type == TERRAFORM for d in result.documents)
        json.loads(docs["aws_iam_policy.deploy"].text)  # valid policy JSON

    def test_unknown_policy_is_skipped_but_computed_attributes_are_not_reported(self):
        result = extract([str(TF_PLAN)])
        # aws_s3_bucket_policy.logs depends on the bucket ARN: unknown until apply
        assert [s.id for s in result.skipped] == ["aws_s3_bucket_policy.logs"]
        # aws_s3_bucket.*.policy, aws_sqs_queue.q.policy and aws_iam_role.inline_policy are
        # computed attributes nobody set: they must not show up as skipped policies.
        skipped_ids = {s.id for s in result.skipped}
        assert not any(
            i.startswith(("aws_s3_bucket.", "module.queue.aws_sqs_queue.q")) for i in skipped_ids
        )

    def test_opentofu_plan_gives_the_same_result(self):
        terraform, tofu = extract([str(TF_PLAN)]), extract([str(TOFU_PLAN)])
        assert ids(terraform) == ids(tofu)
        assert [s.id for s in terraform.skipped] == [s.id for s in tofu.skipped]

    def test_only_changed(self):
        plan = json.loads(TF_PLAN.read_text())
        for change in plan["resource_changes"]:
            if change["address"] == "aws_iam_policy.deploy":
                change["change"]["actions"] = ["no-op"]
        result = extract_terraform(plan, "p.json", ExtractOptions(only_changed=True))
        assert "aws_iam_policy.deploy" not in ids(result)
        assert "aws_iam_policy.too_broad" in ids(result)
        everything = extract_terraform(plan, "p.json", ExtractOptions())
        assert "aws_iam_policy.deploy" in ids(everything)  # unchanged policies still count

    def test_deleted_resources_and_data_sources_are_ignored(self):
        plan = json.loads(TF_PLAN.read_text())
        for change in plan["resource_changes"]:
            if change["address"] == "aws_iam_policy.deploy":
                change["change"]["actions"] = ["delete"]
        plan["resource_changes"].append(
            {
                "address": "data.aws_iam_policy.x",
                "mode": "data",
                "type": "aws_iam_policy",
                "name": "x",
                "change": {"actions": ["read"], "after": {"policy": '{"Version": "2012-10-17"}'}},
            }
        )
        result = extract_terraform(plan, "p.json")
        assert "aws_iam_policy.deploy" not in ids(result)
        assert "data.aws_iam_policy.x" not in ids(result)

    def test_replace_counts_as_changed(self):
        plan = {
            "format_version": "1.2",
            "resource_changes": [
                {
                    "address": "aws_iam_policy.p",
                    "mode": "managed",
                    "type": "aws_iam_policy",
                    "name": "p",
                    "change": {
                        "actions": ["delete", "create"],
                        "after": {"policy": '{"Version": "2012-10-17", "Statement": []}'},
                    },
                }
            ],
        }
        assert ids(extract_terraform(plan, "p", ExtractOptions(only_changed=True))) == [
            "aws_iam_policy.p"
        ]

    def test_state_json(self):
        state = {
            "format_version": "1.0",
            "values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_iam_policy.a",
                            "mode": "managed",
                            "type": "aws_iam_policy",
                            "name": "a",
                            "values": {"policy": '{"Version": "2012-10-17"}'},
                        }
                    ],
                    "child_modules": [
                        {
                            "address": "module.m",
                            "resources": [
                                {
                                    "address": "module.m.aws_sqs_queue_policy.q",
                                    "mode": "managed",
                                    "type": "aws_sqs_queue_policy",
                                    "name": "q",
                                    "values": {"policy": '{"Version": "2012-10-17"}'},
                                }
                            ],
                        }
                    ],
                }
            },
        }
        assert ids(extract_terraform(state, "state.json")) == [
            "aws_iam_policy.a",
            "module.m.aws_sqs_queue_policy.q",
        ]

    def _plan_with(self, after, unknown, expressions, resource_type="aws_iam_role"):
        return {
            "format_version": "1.2",
            "resource_changes": [
                {
                    "address": f'{resource_type}.r["k"]',
                    "mode": "managed",
                    "type": resource_type,
                    "name": "r",
                    "change": {"actions": ["create"], "after": after, "after_unknown": unknown},
                }
            ],
            "configuration": {
                "root_module": {
                    "resources": [{"type": resource_type, "name": "r", "expressions": expressions}]
                }
            },
        }

    def test_inline_policy_blocks_get_an_index(self):
        policy = '{"Version": "2012-10-17"}'
        plan = self._plan_with(
            {"inline_policy": [{"name": "a", "policy": policy}, {"name": "b", "policy": policy}]},
            {"inline_policy": [{}, {}]},
            {"inline_policy": [{}]},
        )
        assert ids(extract_terraform(plan, "p")) == [
            'aws_iam_role.r["k"]#inline_policy[0]',
            'aws_iam_role.r["k"]#inline_policy[1]',
        ]

    def test_configured_but_unknown_is_skipped_and_unconfigured_is_ignored(self):
        configured = self._plan_with({}, {"assume_role_policy": True}, {"assume_role_policy": {}})
        result = extract_terraform(configured, "p")
        assert [s.id for s in result.skipped] == ['aws_iam_role.r["k"]#assume_role_policy']

        computed = self._plan_with({}, {"assume_role_policy": True}, {"name": {}})
        assert extract_terraform(computed, "p").skipped == []

    def test_unknown_without_configuration_is_reported(self):
        plan = self._plan_with({}, {"assume_role_policy": True}, {})
        del plan["configuration"]
        assert len(extract_terraform(plan, "p").skipped) == 1

    @pytest.mark.parametrize(
        "declared,expected",
        [
            ("SERVICE_CONTROL_POLICY", "scp"),
            ("RESOURCE_CONTROL_POLICY", "rcp"),
            (None, "scp"),
            ("TAG_POLICY", None),
            ("BACKUP_POLICY", None),
        ],
    )
    def test_organizations_policy_types(self, declared, expected):
        after = {"content": '{"Version": "2012-10-17"}'}
        if declared:
            after["type"] = declared
        plan = self._plan_with(after, {}, {}, resource_type="aws_organizations_policy")
        docs = extract_terraform(plan, "p").documents
        assert [d.policy_type for d in docs] == ([expected] if expected else [])

    def test_object_values_are_serialized(self):
        plan = self._plan_with(
            {"policy": {"Version": "2012-10-17"}}, {}, {}, resource_type="aws_iam_policy"
        )
        assert json.loads(extract_terraform(plan, "p").documents[0].text) == {
            "Version": "2012-10-17"
        }

    def test_only_policy_attributes_are_read(self, caplog):
        plan = self._plan_with(
            {"policy": '{"Version": "2012-10-17"}', "secret_token": "S3CR3T-VALUE"},
            {},
            {},
            resource_type="aws_iam_policy",
        )
        with caplog.at_level(logging.DEBUG):
            result = extract_terraform(plan, "p")
        assert "S3CR3T-VALUE" not in caplog.text
        assert "S3CR3T-VALUE" not in repr(result)


# ---------------------------------------------------------------------------
# CloudFormation
# ---------------------------------------------------------------------------


def template(resources, **sections):
    return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, **sections}


def bucket_policy(statement):
    return {
        "Type": "AWS::S3::BucketPolicy",
        "Properties": {"PolicyDocument": {"Version": "2012-10-17", "Statement": [statement]}},
    }


def resolved(node, **kwargs):
    options = ExtractOptions(**kwargs.pop("options", {}))
    return Resolver(kwargs.pop("template", template({})), options).resolve(node)


class TestCloudFormation:
    def test_yaml_fixture(self):
        result = extract([str(CFN_YAML)])
        assert ids(result) == [
            "AppRole#AssumeRolePolicyDocument",
            "AppRole#Policies[0]",
            "AppRole#Policies[1]",
            "DataBucketPolicy",
            "DenyRegions",
            "ProdOnlyPolicy",
            "QueuePolicy",
            "WorkerKey",
        ]
        assert all(d.source_type == CLOUDFORMATION for d in result.documents)
        # a parameter without a value and an unsupported intrinsic are skipped, not guessed
        reasons = {s.id: s.reason for s in result.skipped}
        assert "BucketName" in reasons["AppRole#Policies[2]"]
        assert "GetAZs" in reasons["UnresolvableRole#AssumeRolePolicyDocument"]

    def test_param_override_resolves_the_policy(self):
        result = extract([str(CFN_YAML)], options=ExtractOptions(params={"BucketName": "mine"}))
        policy = json.loads(by_id(result)["AppRole#Policies[2]"].text)
        assert policy["Statement"][0]["Resource"] == "arn:aws:s3:::mine/*"
        assert "AppRole#Policies[2]" not in {s.id for s in result.skipped}

    def test_resolved_values(self):
        docs = by_id(extract([str(CFN_YAML)]))
        logs = json.loads(docs["AppRole#Policies[0]"].text)["Statement"][0]["Resource"]
        assert logs == "arn:aws:logs:us-east-1:123456789012:log-group:/app/prod:*"
        data = json.loads(docs["AppRole#Policies[1]"].text)["Statement"][0]["Resource"]
        assert data == "arn:aws:s3:::DataBucket/*"
        queue = json.loads(docs["QueuePolicy"].text)["Statement"][0]
        assert queue["Resource"] == "arn:aws:sqs:us-east-1:123456789012:Queue"
        assert queue["Condition"]["ArnEquals"]["aws:SourceArn"] == (
            "arn:aws:iam::123456789012:role/imported-shared-topic-arn"
        )
        actions = json.loads(docs["ProdOnlyPolicy"].text)["Statement"][0]["Action"]
        assert actions == ["ec2:DescribeInstances", "ec2:DescribeVolumes"]
        bucket = json.loads(docs["DataBucketPolicy"].text)["Statement"]
        assert bucket[0]["Principal"]["AWS"] == [
            "arn:aws:iam::111122223333:root",
            "arn:aws:iam::444455556666:root",
        ]
        assert len(bucket) == 2 and bucket[1]["Effect"] == "Deny"  # Fn::If took the true branch

    def test_conditions_decide_resources_and_statements(self):
        docs = by_id(extract([str(CFN_YAML)], options=ExtractOptions(params={"Env": "dev"})))
        assert "ProdOnlyPolicy" not in docs  # Condition IsProd is false
        assert "DevOnlyPolicy" in docs  # Condition NotProd is true
        statements = json.loads(docs["DataBucketPolicy"].text)["Statement"]
        assert len(statements) == 1  # the Fn::If false branch is AWS::NoValue

    def test_non_validated_organization_policy_types_are_skipped(self):
        assert "RequiredTags" not in by_id(extract([str(CFN_YAML)]))

    def test_json_template(self):
        result = extract([str(CFN_JSON)])
        assert ids(result) == ["BucketPolicy", "Inline"]
        resource = json.loads(by_id(result)["BucketPolicy"].text)["Statement"][0]["Resource"]
        assert resource == "arn:aws:s3:::reports/*"

    def test_region_option_and_pseudo_parameters(self):
        r = Resolver(template({}), ExtractOptions(region="eu-west-1"))
        assert r.resolve({"Ref": "AWS::Region"}) == "eu-west-1"
        assert r.resolve({"Ref": "AWS::AccountId"}) == "123456789012"
        assert r.resolve({"Ref": "AWS::Partition"}) == "aws"
        with pytest.raises(Unresolved):
            r.resolve({"Ref": "AWS::Nope"})

    def test_sub_forms(self):
        r = Resolver(
            template({}, Parameters={"Env": {"Type": "String", "Default": "x"}}), ExtractOptions()
        )
        assert r.resolve({"Fn::Sub": "a-${Env}-${AWS::Region}"}) == "a-x-us-east-1"
        assert r.resolve({"Fn::Sub": ["${Name}-${Env}", {"Name": "n"}]}) == "n-x"
        assert r.resolve({"Fn::Sub": "literal-${!NotAVariable}"}) == "literal-${NotAVariable}"

    def test_list_functions(self):
        r = Resolver(template({}), ExtractOptions())
        assert r.resolve({"Fn::Join": ["-", ["a", "b"]]}) == "a-b"
        assert r.resolve({"Fn::Select": [1, ["a", "b"]]}) == "b"
        assert r.resolve({"Fn::Split": [",", "a,b"]}) == ["a", "b"]
        assert r.resolve({"Fn::ToJsonString": {"a": 1}}) == '{"a": 1}'
        with pytest.raises(Unresolved):
            r.resolve({"Fn::Select": [5, ["a"]]})
        with pytest.raises(Unresolved):
            r.resolve({"Fn::Join": ["", [{"Ref": "Missing"}]]})

    def test_find_in_map_and_conditions(self):
        t = template(
            {},
            Mappings={"M": {"a": {"b": "found"}}},
            Parameters={"Env": {"Type": "String", "Default": "prod"}},
            Conditions={
                "IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]},
                "Both": {
                    "Fn::And": [{"Condition": "IsProd"}, {"Fn::Not": [{"Fn::Equals": [1, 2]}]}]
                },
                "Either": {"Fn::Or": [{"Fn::Equals": [1, 2]}, {"Condition": "IsProd"}]},
            },
        )
        r = Resolver(t, ExtractOptions())
        assert r.resolve({"Fn::FindInMap": ["M", "a", "b"]}) == "found"
        assert r.condition("Both") and r.condition("Either")
        assert r.resolve({"Fn::If": ["IsProd", "yes", "no"]}) == "yes"
        with pytest.raises(Unresolved):
            r.resolve({"Fn::FindInMap": ["M", "a", "missing"]})
        with pytest.raises(Unresolved):
            r.condition("Nope")

    def test_get_att_and_ref_placeholders(self):
        t = template(
            {
                "Role": {"Type": "AWS::IAM::Role"},
                "Topic": {"Type": "AWS::SNS::Topic"},
                "Q": {"Type": "AWS::SQS::Queue"},
                "Fn": {"Type": "AWS::Lambda::Function"},
                "Thing": {"Type": "AWS::Foo::Bar"},
            }
        )
        r = Resolver(t, ExtractOptions())
        assert r.resolve({"Fn::GetAtt": ["Role", "Arn"]}) == "arn:aws:iam::123456789012:role/Role"
        assert r.resolve({"Fn::GetAtt": "Fn.Arn"}).startswith("arn:aws:lambda:us-east-1:")
        assert (
            r.resolve({"Fn::GetAtt": ["Thing", "Arn"]})
            == "arn:aws:foo:us-east-1:123456789012:Thing"
        )
        assert r.resolve({"Fn::GetAtt": ["Role", "RoleId"]}) == "Role-RoleId"
        assert r.resolve({"Ref": "Topic"}).startswith("arn:aws:sns:")
        assert r.resolve({"Ref": "Q"}).startswith("https://sqs.")
        assert r.resolve({"Ref": "Role"}) == "Role"
        with pytest.raises(Unresolved):
            r.resolve({"Fn::GetAtt": ["Missing", "Arn"]})

    def test_ssm_parameter_types_are_unresolved(self):
        t = template(
            {}, Parameters={"P": {"Type": "AWS::SSM::Parameter::Value<String>", "Default": "/x"}}
        )
        with pytest.raises(Unresolved):
            Resolver(t, ExtractOptions()).resolve({"Ref": "P"})

    def test_yaml_short_forms_and_unquoted_version(self):
        data = load_template(
            "Resources:\n  P:\n    Type: AWS::IAM::ManagedPolicy\n    Properties:\n"
            "      PolicyDocument:\n        Version: 2012-10-17\n        Statement:\n"
            "          - Effect: Allow\n            Action: s3:Get*\n"
            "            Resource: !GetAtt B.Arn\n  B:\n    Type: AWS::S3::Bucket\n"
        )
        statement = data["Resources"]["P"]["Properties"]["PolicyDocument"]
        assert statement["Version"] == "2012-10-17"  # a string, not a date
        assert statement["Statement"][0]["Resource"] == {"Fn::GetAtt": ["B", "Arn"]}
        assert json.dumps(extract_cloudformation(data, "t").documents[0].text)

    def test_transform_warning(self, caplog):
        t = template(
            {"B": bucket_policy({"Effect": "Allow", "Action": "s3:*", "Resource": "*"})},
            Transform="AWS::Serverless-2016-10-31",
        )
        with caplog.at_level(logging.WARNING):
            extract_cloudformation(t, "t.yaml")
        assert "Transform" in caplog.text

    def test_unresolved_value_in_one_document_does_not_hide_others(self):
        t = template(
            {
                "R": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
                        "Policies": [
                            {"PolicyName": "ok", "PolicyDocument": {"Version": "2012-10-17"}},
                            {
                                "PolicyName": "bad",
                                "PolicyDocument": {"Fn::ImportValue": {"Fn::GetAZs": ""}},
                            },
                        ],
                    },
                }
            }
        )
        result = extract_cloudformation(t, "t")
        assert "R#Policies[0]" in ids(result) and "R#AssumeRolePolicyDocument" in ids(result)
        assert [s.id for s in result.skipped] == ["R#Policies[1]"]

    def test_organizations_policy_type_resolved_from_parameter(self):
        t = template(
            {
                "O": {
                    "Type": "AWS::Organizations::Policy",
                    "Properties": {"Type": {"Ref": "T"}, "Content": {"Version": "2012-10-17"}},
                }
            },
            Parameters={"T": {"Type": "String", "Default": "RESOURCE_CONTROL_POLICY"}},
        )
        assert [d.policy_type for d in extract_cloudformation(t, "t").documents] == ["rcp"]


# ---------------------------------------------------------------------------
# Pulumi
# ---------------------------------------------------------------------------


class TestPulumi:
    def test_stack_export(self):
        result = extract([str(PULUMI_EXPORT)])
        assert ids(result) == [
            "aws:iam/policy:Policy::deploy",
            "aws:iam/policy:Policy::too-broad",
            "aws:iam/role:Role::app#assumeRolePolicy",
            "aws:iam/role:Role::app#inlinePolicies[0]",
            "aws:organizations/policy:Policy::deny-regions",
            "aws:s3/bucketPolicy:BucketPolicy::public",
        ]
        docs = by_id(result)
        assert all(d.source_type == PULUMI for d in result.documents)
        assert docs["aws:s3/bucketPolicy:BucketPolicy::public"].resource_type == "s3-bucket"
        assert docs["aws:iam/role:Role::app#assumeRolePolicy"].resource_type == "trust-policy"
        assert docs["aws:organizations/policy:Policy::deny-regions"].policy_type == "scp"
        # object values are serialized, strings are passed through
        assert (
            json.loads(docs["aws:iam/policy:Policy::too-broad"].text)["Statement"][0]["Resource"]
            == "*"
        )

    def test_preview_with_unknown_and_delete(self):
        result = extract([str(PULUMI_PREVIEW)])
        assert ids(result) == [
            "aws:iam/policy:Policy::deploy",
            "aws:iam/policy:Policy::unchanged",
            "aws:iam/rolePolicy:RolePolicy::inline",
        ]
        assert [s.id for s in result.skipped] == ["aws:s3/bucketPolicy:BucketPolicy::logs"]

    def test_only_changed(self):
        result = extract([str(PULUMI_PREVIEW)], options=ExtractOptions(only_changed=True))
        assert "aws:iam/policy:Policy::unchanged" not in ids(result)
        assert "aws:iam/policy:Policy::deploy" in ids(result)

    def test_inputs_win_over_outputs_and_outputs_are_the_fallback(self):
        state = {
            "deployment": {
                "resources": [
                    {
                        "urn": "urn:pulumi:s::p::aws:iam/policy:Policy::a",
                        "type": "aws:iam/policy:Policy",
                        "inputs": {"policy": '{"from": "inputs"}'},
                        "outputs": {"policy": '{"from": "outputs"}'},
                    },
                    {
                        "urn": "urn:pulumi:s::p::aws:iam/policy:Policy::b",
                        "type": "aws:iam/policy:Policy",
                        "inputs": {},
                        "outputs": {"policy": '{"from": "outputs"}'},
                    },
                ]
            }
        }
        docs = by_id(extract_pulumi(state, "s.json"))
        assert json.loads(docs["aws:iam/policy:Policy::a"].text) == {"from": "inputs"}
        assert json.loads(docs["aws:iam/policy:Policy::b"].text) == {"from": "outputs"}

    def test_unknown_marker_inside_an_object_is_unknown(self):
        state = {
            "deployment": {
                "resources": [
                    {
                        "urn": "urn:pulumi:s::p::aws:iam/policy:Policy::a",
                        "type": "aws:iam/policy:Policy",
                        "inputs": {"policy": {"Statement": [{"Resource": UNKNOWN_MARKER}]}},
                    }
                ]
            }
        }
        result = extract_pulumi(state, "s.json")
        assert result.documents == [] and len(result.skipped) == 1

    def test_unmapped_and_malformed_states_are_ignored(self):
        state = {"deployment": {"resources": [{"type": "aws:s3/bucket:Bucket", "urn": "u"}, {}]}}
        assert extract_pulumi(state, "s.json").documents == []


# ---------------------------------------------------------------------------
# Detection, files and errors
# ---------------------------------------------------------------------------


class TestExtractEntryPoint:
    def test_detect_source(self):
        assert detect_source(json.loads(TF_PLAN.read_text())) == TERRAFORM
        assert detect_source(json.loads(PULUMI_EXPORT.read_text())) == PULUMI
        assert detect_source(json.loads(PULUMI_PREVIEW.read_text())) == PULUMI
        assert detect_source(json.loads(CFN_JSON.read_text())) == CLOUDFORMATION
        with pytest.raises(SourceError):
            detect_source({"hello": "world"})
        with pytest.raises(SourceError):
            detect_source(["not", "a", "dict"])

    def test_explicit_source_must_match_the_content(self):
        with pytest.raises(SourceError, match="not Terraform"):
            extract([str(CFN_JSON)], "terraform-plan")
        with pytest.raises(SourceError, match="not a CloudFormation"):
            extract([str(TF_PLAN)], "cloudformation")
        with pytest.raises(SourceError, match="not Pulumi"):
            extract([str(TF_PLAN)], "pulumi")
        with pytest.raises(SourceError, match="Unsupported source"):
            extract([str(TF_PLAN)], "ansible")

    def test_auto_is_the_default(self):
        assert extract([str(TF_PLAN)], "auto").documents

    def test_missing_input_and_bad_content(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            extract([str(tmp_path / "nope.json")])
        bad = tmp_path / "bad.json"
        bad.write_text("{ not json or yaml: [")
        with pytest.raises(SourceError, match="not valid"):
            extract([str(bad)])
        other = tmp_path / "other.json"
        other.write_text('{"hello": "world"}')
        with pytest.raises(SourceError, match="Unrecognized"):
            extract([str(other)])
        binary = tmp_path / "bin.json"
        binary.write_bytes(b"\xff\xfe\x00")
        with pytest.raises(SourceError):
            extract([str(binary)])

    def test_directory_of_templates(self, tmp_path):
        (tmp_path / "a.yaml").write_text(CFN_YAML.read_text())
        (tmp_path / "b.json").write_text(CFN_JSON.read_text())
        (tmp_path / "notes.txt").write_text("ignored")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "c.json").write_text(CFN_JSON.read_text())
        flat = extract([str(tmp_path)])
        assert {d.file for d in flat.documents} == {
            str(tmp_path / "a.yaml"),
            str(tmp_path / "b.json"),
        }
        deep = extract([str(tmp_path)], recursive=True)
        assert str(tmp_path / "sub" / "c.json") in {d.file for d in deep.documents}

    def test_empty_directory(self, tmp_path):
        with pytest.raises(SourceError, match="No template files"):
            extract([str(tmp_path)])

    def test_several_inputs_get_file_prefixed_ids(self):
        result = extract([str(CFN_JSON), str(CFN_YAML)])
        assert "template.json:BucketPolicy" in ids(result)
        assert "template.yaml:DataBucketPolicy" in ids(result)
        assert all(":" in s.id for s in result.skipped)


class TestDirectoryInputs:
    def test_cdk_out_style_directory_ignores_manifests_and_assets(self, tmp_path):
        out = tmp_path / "cdk.out"
        out.mkdir()
        (out / "Stack.template.json").write_text(CFN_JSON.read_text())
        (out / "manifest.json").write_text('{"version": "36.0.0", "artifacts": {}}')
        (out / "tree.json").write_text('{"version": "tree-0.1", "tree": {}}')
        (out / "Stack.assets.json").write_text('{"version": "36.0.0", "files": {}}')
        (out / "cdk.out").write_text('{"version":"36.0.0"}')
        result = extract([str(out)])
        assert {d.file for d in result.documents} == {str(out / "Stack.template.json")}
        assert "BucketPolicy" in ids(result)  # one template: ids are not prefixed

    def test_directory_without_any_template_is_an_error(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "x", "version": "1.0.0"}')
        with pytest.raises(SourceError, match="No supported input"):
            extract([str(tmp_path)])

    def test_explicit_files_stay_strict(self, tmp_path):
        manifest = tmp_path / "manifest.json"
        manifest.write_text('{"version": "36.0.0", "artifacts": {}}')
        with pytest.raises(SourceError):
            extract([str(manifest)])

    def test_unreadable_files_in_a_directory_are_skipped(self, tmp_path):
        (tmp_path / "ok.json").write_text(CFN_JSON.read_text())
        (tmp_path / "broken.yaml").write_text("{ not: [valid")
        assert ids(extract([str(tmp_path)])) == ["BucketPolicy", "Inline"]
