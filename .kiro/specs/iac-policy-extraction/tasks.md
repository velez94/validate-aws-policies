# Implementation Plan: IaC Policy Extraction

## Overview

Build the extraction layer and plug it into the existing pipeline. Terraform first, then CloudFormation, then Pulumi. Every task keeps the 3.x compatibility contract.

## Tasks

- [x] 1. Core model and pipeline refactor
  - [x] 1.1 Create `sources/base.py` (`PolicyDocument`, `SkippedPolicy`, `ExtractionResult`, `ExtractOptions`, `SourceError`, path resolver with `[*]`)
    - _Requirements: 1, 5, 7_
  - [x] 1.2 Refactor `iam_access_analyzer.py`: shared setup helper, per-document call, `validate_policy_documents()`; keep `validate_policies()` unchanged
    - _Requirements: 6.1_
  - [x] 1.3 Let `run_policy_checks()` take `documents` and `reference_documents`
    - _Requirements: 6.3, 6.4_
  - [x] 1.4 Tests: documents are sent with the right type, checks run without a directory, existing tests untouched
    - _Requirements: 6_

- [x] 2. Terraform and OpenTofu extractor
  - [x] 2.1 Generate real plan fixtures with Terraform and OpenTofu (project committed under `tests/fixtures/iac/terraform/`)
    - _Requirements: 7.5_
  - [x] 2.2 `resource_maps.py` Terraform table
    - _Requirements: 2.3_
  - [x] 2.3 `terraform.py`: plan and state walking, delete and only-changed rules, configuration lookup for computed attributes
    - _Requirements: 2.1, 2.2, 2.4-2.7_
  - [x]* 2.4 Tests against the real fixtures and edge cases (count and for_each addresses, nested modules, replace actions)
    - _Requirements: 2_

- [x] 3. CLI, config and pipeline integration
  - [x] 3.1 Flags `--input`, `--source`, `--reference-input`, `--param`, `--unknown-values`, `--only-changed`; relax the `-d` requirement
    - _Requirements: 1, 5.2, 6.4_
  - [x] 3.2 `merge_config`, config validation, conflict rules
    - _Requirements: 1.5, 1.7, 7.4_
  - [x] 3.3 `PolicyValidator._run_iac()` with grouping, baseline, skipped list and shared tail
    - _Requirements: 6_
  - [x] 3.4 SARIF and HTML use `source`; report header lists skipped policies
    - _Requirements: 6.5-6.7_
  - [x]* 3.5 Tests: detection, error exits, grouping, baseline matching, strict references, `--unknown-values fail`
    - _Requirements: 1, 5, 6_

- [x] 4. CloudFormation extractor
  - [x] 4.1 YAML loader with short-form tags
    - _Requirements: 3.1_
  - [x] 4.2 Intrinsic resolver and conditions
    - _Requirements: 3.3-3.5_
  - [x] 4.3 CloudFormation table and extractor
    - _Requirements: 3.2, 3.6_
  - [x]* 4.4 Tests for every construct and mapped resource, JSON and YAML, CDK-style output
    - _Requirements: 3_

- [x] 5. Pulumi extractor
  - [x] 5.1 Pulumi table and extractor for stack export and preview
    - _Requirements: 4_
  - [x]* 5.2 Tests with documented-format fixtures, unknown marker, delete steps, object values
    - _Requirements: 4_

- [x] 6. Verification
  - [x] 6.1 Run the Terraform fixture against the live Access Analyzer API (validation only) and check findings and exit codes
  - [x] 6.2 Python 3.8 with boto3 1.34.138: full test run and one live run
  - [x] 6.3 Coverage stays above 80%, `ruff` and `mypy` clean

- [x] 7. Documentation
  - [x] 7.1 New docs page `iac.md` (per-tool commands, mapping tables, unknown values, baseline, CI examples) and nav entry
  - [x] 7.2 Update README, usage, configuration, API reference, examples, CHANGELOG (Unreleased)
  - [x] 7.3 Update steering docs (structure, tech, product)
  - [x] 7.4 the docs build in strict mode passes (`zensical build --strict` since the move from MkDocs)

## Out of scope

- Expanding SAM transforms, CloudFormation macros, or `Fn::Transform`
- Resolving Terraform module variables from source (the plan already holds resolved values)
- Pulumi `aws-native` resources and non-AWS providers
- Mapping validation findings back to lines in `.tf` or template source files
- Kubernetes manifests (ACK) and Crossplane

## Implementation notes

- Verified against the live Access Analyzer API with Terraform 1.14 and OpenTofu 1.13 plans, a CloudFormation template and Pulumi fixtures. Python 3.8 with boto3 1.34.138 passes the tests and a live run.
- The live run found one design flaw: the `Fn::ImportValue` placeholder had to become an IAM-role-shaped ARN (see design).
- Pulumi support follows the documented formats and has not been run against a live Pulumi stack.
- Added during implementation: `cdk.out`-style directory handling and the strict resource-type rule for the public-access check.
