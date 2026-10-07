variable "project_name" {
  description = "Prefix for function, role, and log group names."
  type        = string
}

variable "kms_key_arn" {
  description = "Key that encrypts environment variables, logs, and evidence objects."
  type        = string
}

variable "evidence_bucket_name" {
  description = "Bucket where playbooks write JSON evidence."
  type        = string
}

variable "evidence_bucket_arn" {
  description = "ARN of the evidence bucket."
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS topic playbooks publish to."
  type        = string
}

variable "dlq_arn" {
  description = "Dead-letter queue for asynchronous Lambda invocations."
  type        = string
}

variable "containment_mode" {
  description = "enforce mutates resources. notify_only records the action it would take."
  type        = string
}

variable "min_severity" {
  description = "Findings below this GuardDuty severity are recorded and not contained."
  type        = number
}

variable "quarantine_ssh_cidr" {
  description = "Optional CIDR allowed to SSH to a quarantined instance."
  type        = string
}

variable "protected_bucket_names" {
  description = "Bucket names the S3 playbook must refuse to modify."
  type        = list(string)
}

variable "protected_bucket_arns" {
  description = "Bucket ARNs the S3 role is explicitly denied from changing."
  type        = list(string)
}

variable "slack_parameter_name" {
  description = "SSM parameter name of the Slack webhook. Empty disables Slack."
  type        = string
}

variable "slack_parameter_arn" {
  description = "SSM parameter ARN of the Slack webhook. Empty omits the read permission."
  type        = string
}

variable "allowed_account_id" {
  description = "When set, playbooks ignore findings from any other account."
  type        = string
}

variable "log_retention_days" {
  description = "Retention for playbook CloudWatch log groups."
  type        = number
}

variable "reserved_concurrency" {
  description = "Maximum concurrent executions for each playbook."
  type        = number
}

variable "source_dir" {
  description = "Directory packaged into the Lambda deployment zip."
  type        = string
}
