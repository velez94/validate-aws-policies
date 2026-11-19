terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "mock"
  secret_key                  = "mock"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

# Identity policy built with jsonencode: fully known at plan time
resource "aws_iam_policy" "deploy" {
  name = "deploy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "arn:aws:s3:::example-bucket/*"
    }]
  })
}

# Identity policy with wildcard actions: produces findings
resource "aws_iam_policy" "too_broad" {
  name = "too-broad"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*", "ec2:*", "iam:*"]
      Resource = "*"
    }]
  })
}

# Rendered by a data source
data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "app" {
  name               = "app"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "app_inline" {
  name = "inline"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sqs:SendMessage"
      Resource = "*"
    }]
  })
}

# Bucket policy that references the bucket ARN: unknown until apply
resource "aws_s3_bucket" "logs" {
  bucket = "example-logs-bucket"
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.logs.arn}/*"
    }]
  })
}

# Bucket policy with no references: known at plan time
resource "aws_s3_bucket" "public" {
  bucket = "example-public-bucket"
}

resource "aws_s3_bucket_policy" "public" {
  bucket = aws_s3_bucket.public.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::example-public-bucket/*"
    }]
  })
}

resource "aws_organizations_policy" "deny_regions" {
  name = "deny-regions"
  type = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Deny"
      Action    = "ec2:*"
      Resource  = "*"
      Condition = { StringNotEquals = { "aws:RequestedRegion" = ["us-east-1"] } }
    }]
  })
}

module "queue" {
  source = "./modules/queue"
}
