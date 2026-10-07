variable "project_name" {
  description = "Prefix for EventBridge rule names."
  type        = string
}

variable "state_machine_arn" {
  description = "State machine that receives matching GuardDuty findings."
  type        = string
}

variable "dlq_arn" {
  description = "Queue that receives events Step Functions could not start."
  type        = string
}

variable "dlq_url" {
  description = "URL of the dead-letter queue. Required to attach its queue policy."
  type        = string
}

variable "min_severity" {
  description = "Minimum GuardDuty severity included in each rule."
  type        = number
}

variable "ec2_finding_prefixes" {
  description = "GuardDuty finding type prefixes routed as EC2 compromise."
  type        = list(string)
}

variable "iam_finding_prefixes" {
  description = "GuardDuty finding type prefixes routed as IAM compromise."
  type        = list(string)
}

variable "s3_finding_prefixes" {
  description = "GuardDuty finding type prefixes routed as S3 exposure or exfiltration."
  type        = list(string)
}
