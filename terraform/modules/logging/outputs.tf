output "trail_arn" {
  description = "ARN of the multi-region CloudTrail trail."
  value       = aws_cloudtrail.this.arn
}

output "trail_name" {
  description = "Name of the CloudTrail trail."
  value       = aws_cloudtrail.this.name
}

output "log_group_name" {
  description = "CloudWatch log group that receives CloudTrail events."
  value       = aws_cloudwatch_log_group.trail.name
}
