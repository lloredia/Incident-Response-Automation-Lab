locals {
  playbooks = {
    ec2_compromise = {
      handler     = "ir_automation.handlers.ec2_compromise.handler"
      timeout     = 60
      description = "Quarantine a compromised EC2 instance and snapshot attached volumes."
    }
    iam_compromise = {
      handler     = "ir_automation.handlers.iam_compromise.handler"
      timeout     = 30
      description = "Deactivate a compromised access key and attach the deny-all policy."
    }
    s3_exfiltration = {
      handler     = "ir_automation.handlers.s3_exfiltration.handler"
      timeout     = 30
      description = "Block public access on an S3 bucket named by a GuardDuty finding."
    }
    failure_notify = {
      handler     = "ir_automation.handlers.failure_notify.handler"
      timeout     = 30
      description = "Notify responders when containment fails or no playbook matches."
    }
  }
}

resource "aws_cloudwatch_log_group" "playbook" {
  for_each          = local.playbooks
  name              = "/aws/lambda/${var.project_name}-${each.key}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_lambda_function" "playbook" {
  for_each = local.playbooks

  function_name                  = "${var.project_name}-${each.key}"
  role                           = aws_iam_role.playbook[each.key].arn
  runtime                        = "python3.12"
  architectures                  = ["arm64"]
  handler                        = each.value.handler
  filename                       = data.archive_file.playbooks.output_path
  source_code_hash               = data.archive_file.playbooks.output_base64sha256
  timeout                        = each.value.timeout
  memory_size                    = 256
  reserved_concurrent_executions = var.reserved_concurrency
  kms_key_arn                    = var.kms_key_arn
  description                    = each.value.description

  #checkov:skip=CKV_AWS_117:Playbooks call public AWS APIs and are not placed in the isolated forensics VPC.
  #checkov:skip=CKV_AWS_272:Lab functions are deployed from this Terraform source tree, not a code-signing pipeline.

  dead_letter_config {
    target_arn = var.dlq_arn
  }

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      EVIDENCE_BUCKET             = var.evidence_bucket_name
      EVIDENCE_KMS_KEY_ID         = var.kms_key_arn
      SNS_TOPIC_ARN               = var.sns_topic_arn
      CONTAINMENT_MODE            = var.containment_mode
      MIN_SEVERITY                = tostring(var.min_severity)
      PROJECT_NAME                = var.project_name
      QUARANTINE_SSH_CIDR         = var.quarantine_ssh_cidr
      DENY_ALL_POLICY_ARN         = aws_iam_policy.deny_all.arn
      SLACK_WEBHOOK_SSM_PARAMETER = var.slack_parameter_name
      PROTECTED_BUCKETS           = join(",", var.protected_bucket_names)
      ALLOWED_ACCOUNT_ID          = var.allowed_account_id
      PLAYBOOK_NAME               = each.key
      LOG_LEVEL                   = "INFO"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.playbook,
    aws_iam_role_policy.common,
    aws_iam_role_policy.logs,
    aws_iam_role_policy.ec2,
    aws_iam_role_policy.iam,
    aws_iam_role_policy.s3,
  ]
}
