"""Use boto3 and IAM access Analyzer API."""
import boto3
from colorama import Fore

from ..ops.ops import read_policies, validate_findings


def validate_policies(list_policies, policies_path):
    """
    Validate policies using the IAM Access Analyzer.

    :param list_policies: list of policies to validate
    :param policies_path: path to the policies
    :return:
    """
    report = []
    client = boto3.client("accessanalyzer")
    paginator = client.get_paginator("validate_policy")

    for f in list_policies:
        print(Fore.GREEN + f"Validating {f}  ..." + Fore.RESET)

        policies = read_policies(f"{policies_path}/{f}")
        response_iterator = paginator.paginate(
            policyDocument=policies,
            policyType="IDENTITY_POLICY",  # 'RESOURCE_POLICY'|'SERVICE_CONTROL_POLICY',
            locale="EN",
            PaginationConfig={
                "MaxItems": 100,
                "PageSize": 20,
            },
        )

        findings = []
        for page in response_iterator:
            findings.extend(page.get("findings", []))

        report.append(validate_findings(f, findings))

    return report
