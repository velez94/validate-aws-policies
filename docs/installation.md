# Installation

## From PyPI (Recommended)

```bash
pip install validate-aws-policies
```

## Using pipx (Isolated Environment)

```bash
pipx install validate-aws-policies
```

## From Source

```bash
git clone https://github.com/velez94/validate-aws-policies.git
cd validate-aws-policies
pip install -e .
```

## Development Installation

```bash
git clone https://github.com/velez94/validate-aws-policies.git
cd validate-aws-policies
pip install -e ".[dev]"
```

## Verify Installation

```bash
validate-aws-policies --version
```

## AWS Prerequisites

### IAM Permissions

Your AWS credentials need the following permission:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "access-analyzer:ValidatePolicy",
      "Resource": "*"
    }
  ]
}
```

### Configure AWS CLI

#### Using SSO

```bash
aws configure sso
```

#### Using IAM Credentials

```bash
aws configure
```

#### Using Named Profiles

```bash
aws configure --profile my-profile
```

Then use with:

```bash
validate-aws-policies --policies-path ./policies -p my-profile
```

## Shell Completion (Optional)

### Bash

```bash
activate-global-python-argcomplete
echo 'eval "$(register-python-argcomplete validate-aws-policies)"' >> ~/.bashrc
source ~/.bashrc
```

### Zsh

```bash
activate-global-python-argcomplete
echo 'eval "$(register-python-argcomplete validate-aws-policies)"' >> ~/.zshrc
source ~/.zshrc
```
