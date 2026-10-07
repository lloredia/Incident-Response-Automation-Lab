variable "project_name" {
  description = "Prefix used for bucket name prefixes."
  type        = string
}

variable "kms_key_arn" {
  description = "Customer managed key used for bucket encryption."
  type        = string
}

variable "trail_name" {
  description = "CloudTrail trail name used in the trail bucket policy."
  type        = string
}

variable "enable_cloudtrail" {
  description = "Create the CloudTrail log bucket when the trail is enabled."
  type        = bool
}

variable "evidence_expiration_days" {
  description = "Days before evidence objects expire."
  type        = number
}

variable "cloudtrail_expiration_days" {
  description = "Days before CloudTrail log objects expire."
  type        = number
}
