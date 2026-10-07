output "rule_arns" {
  description = "EventBridge rule ARNs keyed by playbook family."
  value       = { for key, rule in aws_cloudwatch_event_rule.playbook : key => rule.arn }
}
