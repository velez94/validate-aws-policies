# Installation

## Install

=== "pip"

    ```bash
    pip install --upgrade validate-aws-policies
    ```

=== "pipx"

    ```bash
    pipx install validate-aws-policies
    ```

=== "From source"

    ```bash
    git clone https://github.com/velez94/validate-aws-policies.git
    cd validate-aws-policies
    pip install -e .
    ```

Check the installation:

```bash
validate-aws-policies --version
```

### Python and boto3 versions

- Python 3.9 or newer (tested on 3.9 to 3.14).
- boto3 1.36.0 or newer (installed automatically). On Python 3.9 pip installs the newest boto3
  that still supports 3.9.

boto3 1.36.0 knows resource control policies and the three custom policy checks. Access Analyzer
may add resource types later. If a requested value is newer than your boto3, the tool exits with
code 2 and tells you what to upgrade:

```bash
pip install --upgrade boto3 botocore
```

### Private package repositories

=== "AWS CodeArtifact"

    ```bash
    aws codeartifact login --tool pip --repository <repository> --domain <domain> \
      --domain-owner <account-id> --profile <profile> --region <region>
    pip install --upgrade validate-aws-policies
    ```

=== "Azure Artifacts"

    Install the Azure Artifacts keyring, then add this to `pip.conf` (Linux, macOS) or
    `pip.ini` (Windows) in your virtualenv:

    ```ini
    [global]
    index-url=https://pkgs.dev.azure.com/<organization>/.../_packaging/<feed>/pypi/simple/
    ```

## Development install

```bash
git clone https://github.com/velez94/validate-aws-policies.git
cd validate-aws-policies
pip install -e ".[dev]"      # tests, ruff, mypy
pip install -e ".[docs]"     # zensical, to build this site
```

## AWS prerequisites

### Credentials

Use any method the AWS SDK supports. With named profiles:

```bash
aws configure sso                       # IAM Identity Center
aws configure --profile my-profile      # access keys
validate-aws-policies -d ./policies -p my-profile
```

Profile resolution follows boto3: `--profile`, then `profile` in a config file, then
`AWS_PROFILE`, then the default credential chain. The region comes from the profile or
`AWS_REGION`.

### IAM permissions

Policy validation is free. Grant only what you use:

| Feature | Permissions |
|---|---|
| Validation (always) | `access-analyzer:ValidatePolicy` |
| `--check-no-new-access` | `access-analyzer:CheckNoNewAccess` |
| `--check-access-not-granted` | `access-analyzer:CheckAccessNotGranted` |
| `--check-no-public-access` | `access-analyzer:CheckNoPublicAccess` |
| `--upload` | `s3:PutObject` on the reports bucket |

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "access-analyzer:ValidatePolicy",
        "access-analyzer:CheckNoNewAccess",
        "access-analyzer:CheckAccessNotGranted",
        "access-analyzer:CheckNoPublicAccess"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-reports-bucket/AccessAnalyzer/*"
    }
  ]
}
```

!!! note "Cost"
    Custom policy checks are billed per API call. See the
    [Access Analyzer pricing page](https://aws.amazon.com/iam/access-analyzer/pricing/).

## Shell completion

The tool uses `argcomplete`.

```bash
activate-global-python-argcomplete
echo 'eval "$(register-python-argcomplete validate-aws-policies)"' >> ~/.bashrc   # bash
echo 'eval "$(register-python-argcomplete validate-aws-policies)"' >> ~/.zshrc    # zsh
```
