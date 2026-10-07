variable "project_name" {
  description = "Prefix for the state machine and its log group."
  type        = string
}

variable "kms_key_arn" {
  description = "Customer managed key for Step Functions execution logs."
  type        = string
}

variable "log_retention_days" {
  description = "Retention for Step Functions execution logs."
  type        = number
}

variable "ec2_lambda_arn" {
  description = "EC2 playbook Lambda ARN."
  type        = string
}

variable "iam_lambda_arn" {
  description = "IAM playbook Lambda ARN."
  type        = string
}

variable "s3_lambda_arn" {
  description = "S3 playbook Lambda ARN."
  type        = string
}

variable "notify_lambda_arn" {
  description = "Failure notifier Lambda ARN."
  type        = string
}
