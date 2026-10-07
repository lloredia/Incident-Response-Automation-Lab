output "aws_region" {
  description = "Region where the lab was deployed."
  value       = var.aws_region
}

output "guardduty_detector_id" {
  description = "GuardDuty detector that produces findings for this lab."
  value       = module.guardduty.detector_id
}

output "state_machine_arn" {
  description = "Step Functions state machine that routes findings to playbooks."
  value       = module.step_functions.state_machine_arn
}

output "sns_topic_arn" {
  description = "SNS topic for containment notifications."
  value       = module.notifications.topic_arn
}

output "evidence_bucket_name" {
  description = "Bucket containing JSON evidence of each playbook run."
  value       = module.storage.evidence_bucket_name
}

output "dead_letter_queue_url" {
  description = "Queue that receives events the state machine could not start."
  value       = module.notifications.dlq_url
}

output "eventbridge_rule_arns" {
  description = "EventBridge rules keyed by EC2, IAM, and S3."
  value       = module.eventbridge.rule_arns
}

output "playbook_function_names" {
  description = "Lambda function names for the three containment playbooks and the failure notifier."
  value = {
    ec2    = module.lambdas.ec2_function_name
    iam    = module.lambdas.iam_function_name
    s3     = module.lambdas.s3_function_name
    notify = module.lambdas.notify_function_name
  }
}

output "deny_all_policy_arn" {
  description = "Policy the IAM playbook attaches to a compromised user."
  value       = module.lambdas.deny_all_policy_arn
}

output "forensics_vpc_id" {
  description = "Isolated forensics VPC ID, or null when the VPC is disabled."
  value       = try(module.forensics_vpc[0].vpc_id, null)
}

output "cloudtrail_arn" {
  description = "CloudTrail trail ARN, or null when the trail is disabled."
  value       = try(module.logging[0].trail_arn, null)
}

output "sample_findings_command" {
  description = "Command that asks GuardDuty for safe sample findings."
  value       = "AWS_REGION=${var.aws_region} ./scripts/generate_sample_findings.sh"
}
