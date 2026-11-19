"""Extract policies from CloudFormation templates (JSON or YAML, also CDK output).

Intrinsic functions are resolved with template parameters, ``--param`` overrides and
well-formed placeholders for references to other resources, so the policy still
validates. A value that cannot be resolved is reported as skipped, never guessed.
"""

import json
import logging
import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

import yaml

from .base import (
    CLOUDFORMATION,
    ORGANIZATION_POLICY_TYPES,
    ExtractionResult,
    ExtractOptions,
    MapEntry,
    PolicyDocument,
    SkippedPolicy,
    document_id,
    policy_text,
)
from .resource_maps import CLOUDFORMATION_MAP

logger = logging.getLogger(__name__)

ACCOUNT_ID = "123456789012"


class Unresolved(Exception):
    """An intrinsic function could not be resolved to a value."""


class _NoValue:
    """Marker for ``Ref: AWS::NoValue`` (the key is removed)."""


NO_VALUE = _NoValue()


# ---------------------------------------------------------------------------
# YAML loader with CloudFormation short-form tags
# ---------------------------------------------------------------------------


class CloudFormationLoader(yaml.SafeLoader):
    """SafeLoader that understands ``!Ref``, ``!Sub``, ``!GetAtt`` and the other tags."""


# CloudFormation policies use Version: 2012-10-17 unquoted; keep it a string.
CloudFormationLoader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def _tag_constructor(loader: yaml.Loader, suffix: str, node: yaml.Node) -> Dict[str, Any]:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node, deep=True)
    else:
        raise yaml.constructor.ConstructorError(None, None, "unsupported tag node", node.start_mark)

    if suffix == "Ref":
        return {"Ref": value}
    if suffix == "Condition":
        return {"Condition": value}
    if suffix == "GetAtt" and isinstance(value, str):
        value = value.split(".", 1)
    return {f"Fn::{suffix}": value}


CloudFormationLoader.add_multi_constructor("!", _tag_constructor)


def load_template(text: str) -> Any:
    """Parse a CloudFormation template from JSON or YAML text."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    return yaml.load(text, Loader=CloudFormationLoader)  # noqa: S506 (SafeLoader subclass)


def is_cloudformation(data: Any) -> bool:
    """True if the parsed document looks like a CloudFormation template."""
    return isinstance(data, dict) and (
        isinstance(data.get("Resources"), dict) or "AWSTemplateFormatVersion" in data
    )


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

_SUB_VARIABLE = re.compile(r"\$\{([^}]*)\}")

# Service name used in ARNs when it differs from the lower-cased namespace
_ARN_SERVICE = {"AWS::ElasticLoadBalancingV2": "elasticloadbalancing", "AWS::Logs": "logs"}


class Resolver:
    """Resolve intrinsic functions of one template."""

    def __init__(self, template: Dict[str, Any], options: ExtractOptions):
        self.template = template
        self.region = options.region
        self.overrides = options.params
        self.parameters = template.get("Parameters") or {}
        self.mappings = template.get("Mappings") or {}
        self.conditions = template.get("Conditions") or {}
        self.resources = template.get("Resources") or {}
        self._condition_cache: Dict[str, bool] = {}

    # --- placeholders -----------------------------------------------------

    def _pseudo(self, name: str) -> Any:
        values = {
            "AWS::AccountId": ACCOUNT_ID,
            "AWS::Region": self.region,
            "AWS::Partition": "aws",
            "AWS::StackName": "stack",
            "AWS::StackId": f"arn:aws:cloudformation:{self.region}:{ACCOUNT_ID}:stack/stack/id",
            "AWS::URLSuffix": "amazonaws.com",
            "AWS::NoValue": NO_VALUE,
        }
        if name not in values:
            raise Unresolved(f"unknown pseudo parameter {name}")
        return values[name]

    def arn(self, logical_id: str, resource_type: str) -> str:
        """A well-formed ARN for a resource of the template."""
        region, account = self.region, ACCOUNT_ID
        namespace = resource_type.split("::")[1] if "::" in resource_type else "service"
        service = _ARN_SERVICE.get("::".join(resource_type.split("::")[:2]), namespace.lower())
        special = {
            "AWS::IAM::Role": f"arn:aws:iam::{account}:role/{logical_id}",
            "AWS::IAM::User": f"arn:aws:iam::{account}:user/{logical_id}",
            "AWS::IAM::Group": f"arn:aws:iam::{account}:group/{logical_id}",
            "AWS::IAM::ManagedPolicy": f"arn:aws:iam::{account}:policy/{logical_id}",
            "AWS::IAM::Policy": f"arn:aws:iam::{account}:policy/{logical_id}",
            "AWS::S3::Bucket": f"arn:aws:s3:::{logical_id}",
            "AWS::KMS::Key": f"arn:aws:kms:{region}:{account}:key/{logical_id}",
            "AWS::Lambda::Function": f"arn:aws:lambda:{region}:{account}:function:{logical_id}",
            "AWS::DynamoDB::Table": f"arn:aws:dynamodb:{region}:{account}:table/{logical_id}",
        }
        return special.get(resource_type, f"arn:aws:{service}:{region}:{account}:{logical_id}")

    def _ref_resource(self, logical_id: str, resource_type: str) -> str:
        """What ``Ref`` returns for a resource: usually a name, sometimes an ARN or URL."""
        if resource_type in ("AWS::SNS::Topic", "AWS::IAM::ManagedPolicy"):
            return self.arn(logical_id, resource_type)
        if resource_type == "AWS::SQS::Queue":
            return f"https://sqs.{self.region}.amazonaws.com/{ACCOUNT_ID}/{logical_id}"
        return logical_id

    # --- references -------------------------------------------------------

    def _ref(self, name: str) -> Any:
        if name.startswith("AWS::"):
            return self._pseudo(name)
        if name in self.parameters:
            return self._parameter(name)
        if name in self.resources:
            return self._ref_resource(name, str(self.resources[name].get("Type", "")))
        raise Unresolved(f"Ref to unknown name {name}")

    def _parameter(self, name: str) -> Any:
        spec = self.parameters[name] or {}
        if name in self.overrides:
            value: Any = self.overrides[name]
        elif "Default" in spec:
            value = spec["Default"]
        else:
            raise Unresolved(f"parameter {name} has no value (use --param {name}=VALUE)")
        param_type = str(spec.get("Type", "String"))
        if param_type == "CommaDelimitedList" or param_type.startswith("List<"):
            if isinstance(value, str):
                return [item.strip() for item in value.split(",")]
            return value
        if param_type.startswith("AWS::SSM::Parameter::Value"):
            raise Unresolved(f"parameter {name} is resolved from SSM at deploy time")
        return value

    def _get_att(self, logical_id: str, attribute: str) -> Any:
        resource = self.resources.get(logical_id)
        if resource is None:
            raise Unresolved(f"GetAtt on unknown resource {logical_id}")
        resource_type = str(resource.get("Type", ""))
        if attribute == "Arn" or attribute.endswith("Arn"):
            return self.arn(logical_id, resource_type)
        return f"{logical_id}-{attribute}"

    # --- conditions -------------------------------------------------------

    def condition(self, name: str) -> bool:
        if name in self._condition_cache:
            return self._condition_cache[name]
        if name not in self.conditions:
            raise Unresolved(f"unknown condition {name}")
        value = self._evaluate(self.conditions[name])
        self._condition_cache[name] = value
        return value

    def _evaluate(self, expression: Any) -> bool:
        if isinstance(expression, dict) and len(expression) == 1:
            (key, args), = expression.items()
            if key == "Condition":
                return self.condition(str(args))
            if key == "Fn::Equals":
                return str(self.resolve(args[0])) == str(self.resolve(args[1]))
            if key == "Fn::Not":
                return not self._evaluate(args[0])
            if key == "Fn::And":
                return all(self._evaluate(item) for item in args)
            if key == "Fn::Or":
                return any(self._evaluate(item) for item in args)
        raise Unresolved(f"unsupported condition {expression!r}")

    # --- resolution -------------------------------------------------------

    def is_intrinsic(self, node: Any) -> bool:
        if not isinstance(node, dict) or len(node) != 1:
            return False
        key = str(next(iter(node)))
        return key == "Ref" or key.startswith("Fn::")

    def resolve(self, node: Any) -> Any:
        """Resolve a template fragment. Raises ``Unresolved``."""
        if isinstance(node, list):
            items = [self.resolve(item) for item in node]
            return [item for item in items if item is not NO_VALUE]
        if not isinstance(node, dict):
            return node
        if self.is_intrinsic(node):
            return self._intrinsic(*next(iter(node.items())))
        resolved = {}
        for key, value in node.items():
            item = self.resolve(value)
            if item is not NO_VALUE:
                resolved[key] = item
        return resolved

    def _intrinsic(self, name: str, args: Any) -> Any:  # noqa: C901 (flat dispatch)
        if name == "Ref":
            return self._ref(str(args))
        if name == "Fn::GetAtt":
            if isinstance(args, str):
                args = args.split(".", 1)
            if len(args) != 2:
                raise Unresolved("malformed Fn::GetAtt")
            return self._get_att(str(self.resolve(args[0])), str(self.resolve(args[1])))
        if name == "Fn::Sub":
            return self._sub(args)
        if name == "Fn::Join":
            delimiter, items = args
            values = self.resolve(items)
            if not isinstance(values, list):
                raise Unresolved("Fn::Join over a non-list")
            return str(self.resolve(delimiter)).join(self._scalar(v) for v in values)
        if name == "Fn::Select":
            index, items = self.resolve(args[0]), self.resolve(args[1])
            try:
                return items[int(index)]
            except (IndexError, TypeError, ValueError) as error:
                raise Unresolved(f"Fn::Select failed: {error}") from None
        if name == "Fn::Split":
            return str(self.resolve(args[1])).split(str(self.resolve(args[0])))
        if name == "Fn::FindInMap":
            map_name, top, second = (self.resolve(item) for item in args)
            try:
                return self.mappings[map_name][top][second]
            except (KeyError, TypeError):
                raise Unresolved(f"Fn::FindInMap {map_name}/{top}/{second} not found") from None
        if name == "Fn::If":
            condition, when_true, when_false = args
            return self.resolve(when_true if self.condition(str(condition)) else when_false)
        if name == "Fn::ImportValue":
            # The exported value is unknown. An IAM role ARN is the one placeholder shape
            # that Access Analyzer accepts as principal, ArnEquals value, string and
            # inside resource ARNs (checked against the live API).
            return f"arn:aws:iam::{ACCOUNT_ID}:role/imported-{self._scalar(self.resolve(args))}"
        if name == "Fn::ToJsonString":
            return json.dumps(self.resolve(args))
        raise Unresolved(f"unsupported intrinsic {name}")

    @staticmethod
    def _scalar(value: Any) -> str:
        if isinstance(value, (dict, list)):
            raise Unresolved("a list or object cannot be used as text")
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    def _sub(self, args: Any) -> str:
        local: Dict[str, Any] = {}
        if isinstance(args, list):
            template = args[0]
            if len(args) > 1 and isinstance(args[1], dict):
                local = {k: self.resolve(v) for k, v in args[1].items()}
        else:
            template = args
        if not isinstance(template, str):
            raise Unresolved("Fn::Sub needs a string")

        def replace(match: "re.Match[str]") -> str:
            variable = match.group(1)
            if variable.startswith("!"):
                return "${" + variable[1:] + "}"
            if variable in local:
                return self._scalar(local[variable])
            if "." in variable and not variable.startswith("AWS::"):
                resource, attribute = variable.split(".", 1)
                return self._scalar(self._get_att(resource, attribute))
            return self._scalar(self._ref(variable))

        return _SUB_VARIABLE.sub(replace, template)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def _navigate(
    resolver: Resolver,
    raw: Any,
    parts: List[str],
    indices: Tuple[int, ...] = (),
    list_key: Optional[str] = None,
) -> Iterator[Tuple[Tuple[int, ...], Optional[str], Any, Optional[str]]]:
    """Walk a path in the raw template, resolving as late as possible.

    Yields ``(indices, list_key, value, error)``. ``error`` is set when part of the
    path could not be resolved; the other documents of the resource are unaffected.
    """
    try:
        if resolver.is_intrinsic(raw):
            raw = resolver.resolve(raw)
        if not parts:
            value = resolver.resolve(raw)
            if value is not NO_VALUE and value is not None:
                yield indices, list_key, value, None
            return
        if not isinstance(raw, dict):
            return
        part, rest = parts[0], parts[1:]
        fan_out = part.endswith("[*]")
        key = part[:-3] if fan_out else part
        child = raw.get(key)
        if child is None:
            return
        if not fan_out:
            yield from _navigate(resolver, child, rest, indices, list_key)
            return
        if resolver.is_intrinsic(child):
            child = resolver.resolve(child)
        if not isinstance(child, list):
            return
        for index, item in enumerate(child):
            yield from _navigate(resolver, item, rest, indices + (index,), key)
    except Unresolved as error:
        yield indices, list_key, None, str(error)


def extract_cloudformation(
    template: Dict[str, Any], file: str, options: Optional[ExtractOptions] = None
) -> ExtractionResult:
    """Extract policy documents from a parsed CloudFormation template."""
    options = options or ExtractOptions()
    result = ExtractionResult()
    resolver = Resolver(template, options)

    if "Transform" in template:
        logger.warning(
            f"{file}: the template uses Transform {template['Transform']!r}, which is not "
            "expanded. Policies created by the transform are not validated."
        )

    for logical_id, resource in (template.get("Resources") or {}).items():
        if not isinstance(resource, dict):
            continue
        resource_type = str(resource.get("Type", ""))
        entries: List[MapEntry] = [e for e in CLOUDFORMATION_MAP if e.iac_type == resource_type]
        if not entries:
            continue

        condition = resource.get("Condition")
        if condition:
            try:
                if not resolver.condition(str(condition)):
                    logger.debug(f"Skipping {logical_id}: condition {condition} is false")
                    continue
            except Unresolved:
                pass  # keep the resource when the condition cannot be evaluated

        for entry in entries:
            policy_type: str = entry.policy_type
            if entry.type_path:
                type_parts = entry.type_path.split(".")
                declared = next(
                    (value for _i, _k, value, _e in _navigate(resolver, resource, type_parts)),
                    None,
                )
                mapped_type = ORGANIZATION_POLICY_TYPES.get(str(declared))
                if mapped_type is None:
                    logger.info(f"Skipping {logical_id}: policy type {declared} is not validated")
                    continue
                policy_type = mapped_type

            for indices, list_key, value, error in _navigate(
                resolver, resource, entry.path.split(".")
            ):
                policy_id = document_id(logical_id, entry, indices, list_key)
                if error is not None:
                    result.skipped.append(SkippedPolicy(policy_id, error, file, resource_type))
                    continue
                text = policy_text(value)
                if text is None:
                    continue
                result.documents.append(
                    PolicyDocument(
                        id=policy_id,
                        text=text,
                        policy_type=policy_type,
                        resource_type=entry.resource_type,
                        source_type=CLOUDFORMATION,
                        file=file,
                        iac_type=resource_type,
                    )
                )
    return result
