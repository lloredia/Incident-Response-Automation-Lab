data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  trail_arn  = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${var.trail_name}"
}

data "aws_iam_policy_document" "key" {
  #checkov:skip=CKV_AWS_109:kms:* is granted only to the account root so the key cannot be locked out.
  #checkov:skip=CKV_AWS_111:Service use is limited by encryption context or source account. Key policies require Resource *.
  #checkov:skip=CKV_AWS_356:A KMS key policy Resource entry is * because the resource is the key itself.

  statement {
    sid = "EnableRootPermissions"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid = "AllowCloudWatchLogs"
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${local.region}:${local.account_id}:*"]
    }
  }

  statement {
    sid = "AllowNotificationAndComputeServices"
    principals {
      type = "Service"
      identifiers = [
        "sns.amazonaws.com",
        "sqs.amazonaws.com",
        "events.amazonaws.com",
        "lambda.amazonaws.com",
        "cloudwatch.amazonaws.com",
      ]
    }
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid = "AllowCloudTrailEncrypt"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "Encrypts ${var.project_name} incident-response evidence, logs, and notifications."
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.key.json
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.project_name}-incident-response"
  target_key_id = aws_kms_key.this.key_id
}
