output "topic_arn" {
  description = "SNS topic that receives playbook notifications."
  value       = aws_sns_topic.alerts.arn
}

output "dlq_arn" {
  description = "Dead-letter queue for EventBridge delivery and asynchronous Lambda failures."
  value       = aws_sqs_queue.dlq.arn
}

output "dlq_url" {
  description = "URL of the dead-letter queue."
  value       = aws_sqs_queue.dlq.url
}

output "slack_parameter_name" {
  description = "SSM parameter name for the Slack webhook, or an empty string."
  value       = try(aws_ssm_parameter.slack_webhook[0].name, "")
}

output "slack_parameter_arn" {
  description = "SSM parameter ARN for the Slack webhook, or an empty string."
  value       = try(aws_ssm_parameter.slack_webhook[0].arn, "")
}
