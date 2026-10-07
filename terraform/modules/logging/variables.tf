variable "project_name" {
  description = "Prefix for the trail and log group names."
  type        = string
}

variable "kms_key_arn" {
  description = "Customer managed key for CloudTrail and its CloudWatch log group."
  type        = string
}

variable "cloudtrail_bucket_name" {
  description = "Bucket that receives CloudTrail log files."
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the CloudTrail log group."
  type        = number
}

variable "trail_name" {
  description = "Name of the CloudTrail trail."
  type        = string
}

variable "cloudtrail_bucket_policy_id" {
  description = "ID of the CloudTrail bucket policy. Referenced so the trail waits for that policy."
  type        = string
}
