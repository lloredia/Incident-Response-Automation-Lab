locals {
  families = {
    ec2 = var.ec2_finding_prefixes
    iam = var.iam_finding_prefixes
    s3  = var.s3_finding_prefixes
  }
}

resource "aws_cloudwatch_event_rule" "playbook" {
  for_each    = local.families
  name        = "${var.project_name}-gd-${each.key}"
  description = "Route GuardDuty ${each.key} findings at or above severity ${var.min_severity}."
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.min_severity] }]
      type     = [for prefix in each.value : { prefix = prefix }]
    }
  })
}

data "aws_iam_policy_document" "events_assume" {
  statement {
    sid     = "EventsAssume"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "start_execution" {
  statement {
    sid       = "StartIncidentResponse"
    actions   = ["states:StartExecution"]
    resources = [var.state_machine_arn]
  }
}

resource "aws_iam_role" "events" {
  name               = "${var.project_name}-start-incident-response"
  assume_role_policy = data.aws_iam_policy_document.events_assume.json
  description        = "Allows EventBridge to start the incident-response state machine."
}

resource "aws_iam_role_policy" "events" {
  name   = "start-execution"
  role   = aws_iam_role.events.id
  policy = data.aws_iam_policy_document.start_execution.json
}

resource "aws_cloudwatch_event_target" "playbook" {
  for_each  = aws_cloudwatch_event_rule.playbook
  rule      = each.value.name
  target_id = "incident-response"
  arn       = var.state_machine_arn
  role_arn  = aws_iam_role.events.arn

  dead_letter_config {
    arn = var.dlq_arn
  }

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }
}

data "aws_iam_policy_document" "dlq" {
  statement {
    sid       = "AllowEventBridgeDelivery"
    actions   = ["sqs:SendMessage"]
    resources = [var.dlq_arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [for rule in aws_cloudwatch_event_rule.playbook : rule.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = var.dlq_url
  policy    = data.aws_iam_policy_document.dlq.json
}
