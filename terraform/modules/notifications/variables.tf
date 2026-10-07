variable "project_name" {
  description = "Prefix for the topic, queue, and alarm names."
  type        = string
}

variable "kms_key_arn" {
  description = "Customer managed key for SNS, SQS, and the Slack parameter."
  type        = string
}

variable "notification_email" {
  description = "Email address subscribed to the alert topic. Empty skips the subscription."
  type        = string
}

variable "slack_webhook_url" {
  description = "Optional Slack incoming webhook. Stored only as a SecureString parameter."
  type        = string
  sensitive   = true
}
