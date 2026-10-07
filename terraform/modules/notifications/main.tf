data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

resource "aws_sns_topic" "alerts" {
  name              = "${var.project_name}-incident-alerts"
  kms_master_key_id = var.kms_key_arn
  display_name      = "Incident response alerts"
}

data "aws_iam_policy_document" "alerts" {
  statement {
    sid     = "AllowAccountPublish"
    actions = ["sns:Publish"]
    resources = [
      aws_sns_topic.alerts.arn,
    ]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid     = "AllowCloudWatchAlarms"
    actions = ["sns:Publish"]
    resources = [
      aws_sns_topic.alerts.arn,
    ]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudwatch:${local.region}:${local.account_id}:alarm:${var.project_name}-*"]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts.json
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_sqs_queue" "dlq" {
  name                              = "${var.project_name}-playbook-dlq"
  kms_master_key_id                 = var.kms_key_arn
  kms_data_key_reuse_period_seconds = 300
  message_retention_seconds         = 1209600
}

resource "aws_cloudwatch_metric_alarm" "dlq_not_empty" {
  alarm_name          = "${var.project_name}-playbook-dlq-not-empty"
  alarm_description   = "EventBridge or a playbook Lambda could not deliver an incident event."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    QueueName = aws_sqs_queue.dlq.name
  }
}

resource "aws_ssm_parameter" "slack_webhook" {
  count       = var.slack_webhook_url == "" ? 0 : 1
  name        = "/${var.project_name}/slack-webhook"
  description = "Slack incoming webhook used by incident response playbooks."
  type        = "SecureString"
  value       = var.slack_webhook_url
  key_id      = var.kms_key_arn
}
