output "ec2_function_arn" {
  description = "ARN of the EC2 compromise playbook."
  value       = aws_lambda_function.playbook["ec2_compromise"].arn
}

output "iam_function_arn" {
  description = "ARN of the IAM credential playbook."
  value       = aws_lambda_function.playbook["iam_compromise"].arn
}

output "s3_function_arn" {
  description = "ARN of the S3 exfiltration playbook."
  value       = aws_lambda_function.playbook["s3_exfiltration"].arn
}

output "notify_function_arn" {
  description = "ARN of the failure and unmatched-finding notifier."
  value       = aws_lambda_function.playbook["failure_notify"].arn
}

output "ec2_function_name" {
  description = "Name of the EC2 compromise playbook."
  value       = aws_lambda_function.playbook["ec2_compromise"].function_name
}

output "iam_function_name" {
  description = "Name of the IAM credential playbook."
  value       = aws_lambda_function.playbook["iam_compromise"].function_name
}

output "s3_function_name" {
  description = "Name of the S3 exfiltration playbook."
  value       = aws_lambda_function.playbook["s3_exfiltration"].function_name
}

output "notify_function_name" {
  description = "Name of the failure notifier."
  value       = aws_lambda_function.playbook["failure_notify"].function_name
}

output "deny_all_policy_arn" {
  description = "Deny-all policy attached only to an IAM user named by a finding."
  value       = aws_iam_policy.deny_all.arn
}
