data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    sid     = "LambdaAssume"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "common" {
  statement {
    sid       = "WriteEvidence"
    actions   = ["s3:PutObject"]
    resources = ["${var.evidence_bucket_arn}/evidence/*"]
  }

  statement {
    sid = "EncryptEvidenceAndMessages"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = [var.kms_key_arn]
  }

  statement {
    sid       = "PublishAlert"
    actions   = ["sns:Publish"]
    resources = [var.sns_topic_arn]
  }

  statement {
    sid       = "SendToDeadLetterQueue"
    actions   = ["sqs:SendMessage"]
    resources = [var.dlq_arn]
  }

  dynamic "statement" {
    for_each = var.slack_parameter_arn == "" ? [] : [var.slack_parameter_arn]
    content {
      sid       = "ReadSlackWebhook"
      actions   = ["ssm:GetParameter"]
      resources = [statement.value]
    }
  }

  statement {
    sid = "WriteTraces"
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
      "xray:GetSamplingRules",
      "xray:GetSamplingTargets",
    ]
    # X-Ray write APIs do not support resource-level permissions.
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "logs" {
  for_each = local.playbooks

  statement {
    sid = "WritePlaybookLogs"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.playbook[each.key].arn}:*"]
  }
}

data "aws_iam_policy_document" "ec2" {
  statement {
    sid = "DescribeInstancesAndGroups"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSnapshots",
    ]
    # Describe calls do not support resource-level permissions.
    resources = ["*"]
  }

  statement {
    sid     = "ReplaceInstanceSecurityGroups"
    actions = ["ec2:ModifyInstanceAttribute"]
    resources = [
      "arn:aws:ec2:${local.region}:${local.account_id}:instance/*",
    ]
  }

  statement {
    sid = "ManageQuarantineSecurityGroup"
    actions = [
      "ec2:CreateSecurityGroup",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
    ]
    resources = [
      "arn:aws:ec2:${local.region}:${local.account_id}:security-group/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:vpc/*",
    ]
  }

  statement {
    sid = "TagQuarantineResources"
    actions = [
      "ec2:CreateTags",
    ]
    resources = [
      "arn:aws:ec2:${local.region}:${local.account_id}:instance/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:security-group/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:snapshot/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/IR-Managed"
      values   = ["true"]
    }
  }

  statement {
    sid     = "SnapshotCompromisedVolumes"
    actions = ["ec2:CreateSnapshot"]
    resources = [
      "arn:aws:ec2:${local.region}:${local.account_id}:volume/*",
      "arn:aws:ec2:${local.region}:${local.account_id}:snapshot/*",
    ]
  }
}

data "aws_iam_policy_document" "iam" {
  statement {
    sid = "InspectAndDeactivateAccessKey"
    actions = [
      "iam:GetUser",
      "iam:ListAccessKeys",
      "iam:UpdateAccessKey",
      "iam:ListAttachedUserPolicies",
    ]
    resources = ["arn:aws:iam::${local.account_id}:user/*"]
  }

  statement {
    sid       = "AttachDenyAllOnly"
    actions   = ["iam:AttachUserPolicy"]
    resources = ["arn:aws:iam::${local.account_id}:user/*"]
    condition {
      test     = "ArnEquals"
      variable = "iam:PolicyARN"
      values   = [aws_iam_policy.deny_all.arn]
    }
  }
}

data "aws_iam_policy_document" "s3" {
  statement {
    sid = "BlockPublicAccessOnReportedBucket"
    actions = [
      "s3:GetBucketLocation",
      "s3:GetBucketPublicAccessBlock",
      "s3:PutBucketPublicAccessBlock",
      "s3:GetBucketTagging",
      "s3:PutBucketTagging",
    ]
    resources = ["arn:aws:s3:::*"]
  }

  statement {
    sid    = "DenyChangesToLabBuckets"
    effect = "Deny"
    actions = [
      "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketTagging",
    ]
    resources = var.protected_bucket_arns
  }
}

resource "aws_iam_role" "playbook" {
  for_each           = local.playbooks
  name               = "${var.project_name}-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  description        = each.value.description
}

resource "aws_iam_role_policy" "common" {
  for_each = aws_iam_role.playbook
  name     = "shared-evidence-and-notify"
  role     = each.value.id
  policy   = data.aws_iam_policy_document.common.json
}

resource "aws_iam_role_policy" "logs" {
  for_each = aws_iam_role.playbook
  name     = "cloudwatch-logs"
  role     = each.value.id
  policy   = data.aws_iam_policy_document.logs[each.key].json
}

resource "aws_iam_role_policy" "ec2" {
  name   = "ec2-containment"
  role   = aws_iam_role.playbook["ec2_compromise"].id
  policy = data.aws_iam_policy_document.ec2.json
}

resource "aws_iam_role_policy" "iam" {
  name   = "iam-containment"
  role   = aws_iam_role.playbook["iam_compromise"].id
  policy = data.aws_iam_policy_document.iam.json
}

resource "aws_iam_role_policy" "s3" {
  name   = "s3-containment"
  role   = aws_iam_role.playbook["s3_exfiltration"].id
  policy = data.aws_iam_policy_document.s3.json
}

resource "aws_iam_policy" "deny_all" {
  name        = "${var.project_name}-deny-all"
  description = "Explicit deny attached only to an IAM user named in a GuardDuty finding."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyAllActions"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
