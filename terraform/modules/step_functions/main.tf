locals {
  definition = templatefile("${path.module}/definition.asl.json.tftpl", {
    ec2_lambda_arn    = var.ec2_lambda_arn
    iam_lambda_arn    = var.iam_lambda_arn
    s3_lambda_arn     = var.s3_lambda_arn
    notify_lambda_arn = var.notify_lambda_arn
  })
}

resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/vendedlogs/states/${var.project_name}-incident-response"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

data "aws_iam_policy_document" "assume" {
  statement {
    sid     = "StatesAssume"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "sfn" {
  #checkov:skip=CKV_AWS_111:Log delivery and X-Ray do not support resource-level permissions. Lambda invoke lists the four playbooks.
  #checkov:skip=CKV_AWS_356:Log delivery and X-Ray require Resource *. InvokeFunction is limited to the playbook ARNs.

  statement {
    sid     = "InvokePlaybooks"
    actions = ["lambda:InvokeFunction"]
    resources = [
      var.ec2_lambda_arn,
      var.iam_lambda_arn,
      var.s3_lambda_arn,
      var.notify_lambda_arn,
    ]
  }

  statement {
    sid = "WriteExecutionLogs"
    actions = [
      "logs:CreateLogDelivery",
      "logs:GetLogDelivery",
      "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries",
      "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies",
      "logs:DescribeLogGroups",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    # Step Functions log-delivery APIs do not support resource-level permissions.
    resources = ["*"]
  }

  statement {
    sid = "WriteTraces"
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
      "xray:GetSamplingRules",
      "xray:GetSamplingTargets",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "sfn" {
  name               = "${var.project_name}-incident-response"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  description        = "Starts containment playbooks and writes Step Functions execution logs."
}

resource "aws_iam_role_policy" "sfn" {
  name   = "invoke-playbooks"
  role   = aws_iam_role.sfn.id
  policy = data.aws_iam_policy_document.sfn.json
}

resource "aws_sfn_state_machine" "this" {
  name       = "${var.project_name}-incident-response"
  role_arn   = aws_iam_role.sfn.arn
  definition = local.definition
  type       = "STANDARD"

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  tracing_configuration {
    enabled = true
  }

  depends_on = [aws_iam_role_policy.sfn]
}
