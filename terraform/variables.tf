variable "aws_region" {
  description = "Region where the lab is deployed. Playbooks only contain resources in this region."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment tag applied to every resource."
  type        = string
  default     = "lab"
}

variable "project_name" {
  description = "Short prefix for resource names. Lowercase letters, numbers, and hyphens."
  type        = string
  default     = "ir-lab"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,18}[a-z0-9]$", var.project_name))
    error_message = "project_name must be 3-20 characters, start with a letter, and use lowercase letters, numbers, and hyphens."
  }
}

variable "min_severity" {
  description = "GuardDuty findings below this numeric severity are ignored. Use 1 so sample findings of every severity match."
  type        = number
  default     = 1

  validation {
    condition     = var.min_severity >= 0.1 && var.min_severity <= 10
    error_message = "min_severity must be between 0.1 and 10."
  }
}

variable "containment_mode" {
  description = "enforce performs containment. notify_only records what would happen."
  type        = string
  default     = "enforce"

  validation {
    condition     = contains(["enforce", "notify_only"], var.containment_mode)
    error_message = "containment_mode must be enforce or notify_only."
  }
}

variable "notification_email" {
  description = "Email subscribed to the alert topic. Leave empty to skip the subscription."
  type        = string
  default     = ""

  validation {
    condition     = var.notification_email == "" || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.notification_email))
    error_message = "notification_email must be empty or a single email address."
  }
}

variable "slack_webhook_url" {
  description = "Optional Slack incoming webhook. Stored in SSM and in Terraform state. Do not commit it."
  type        = string
  default     = ""
  sensitive   = true
}

variable "quarantine_ssh_cidr" {
  description = "Optional IPv4 CIDR allowed to SSH to a quarantined instance. Empty blocks all traffic."
  type        = string
  default     = ""

  validation {
    condition     = var.quarantine_ssh_cidr == "" || can(cidrnetmask(var.quarantine_ssh_cidr))
    error_message = "quarantine_ssh_cidr must be empty or a valid IPv4 CIDR."
  }
}

variable "enable_cloudtrail" {
  description = "Create a multi-region CloudTrail trail. Disable this when the account already has the trail you want to keep."
  type        = bool
  default     = true
}

variable "enable_forensics_vpc" {
  description = "Create an isolated VPC for manual snapshot analysis."
  type        = bool
  default     = true
}

variable "enable_s3_data_events" {
  description = "Enable GuardDuty S3 data-event protection."
  type        = bool
  default     = true
}

variable "create_guardduty_detector" {
  description = "Create a detector. Set false and pass existing_detector_id when GuardDuty is already enabled."
  type        = bool
  default     = true
}

variable "existing_detector_id" {
  description = "Detector ID used when create_guardduty_detector is false."
  type        = string
  default     = ""
}

variable "finding_publishing_frequency" {
  description = "GuardDuty publishing frequency."
  type        = string
  default     = "FIFTEEN_MINUTES"

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.finding_publishing_frequency)
    error_message = "finding_publishing_frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "restrict_to_account" {
  description = "When true, playbooks ignore findings whose account ID is not this account."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for playbooks, CloudTrail, flow logs, and Step Functions."
  type        = number
  default     = 365

  validation {
    condition     = contains([90, 180, 365, 731], var.log_retention_days)
    error_message = "log_retention_days must be 90, 180, 365, or 731."
  }
}

variable "reserved_concurrency" {
  description = "Reserved concurrent executions for each playbook Lambda."
  type        = number
  default     = 5
}

variable "evidence_expiration_days" {
  description = "Days before evidence objects expire."
  type        = number
  default     = 365
}

variable "cloudtrail_expiration_days" {
  description = "Days before CloudTrail objects expire."
  type        = number
  default     = 365
}

variable "forensics_vpc_cidr" {
  description = "CIDR for the forensics VPC."
  type        = string
  default     = "10.70.0.0/16"
}

variable "forensics_subnet_cidr" {
  description = "CIDR for the forensics analysis subnet."
  type        = string
  default     = "10.70.1.0/24"
}

variable "ec2_finding_prefixes" {
  description = "GuardDuty type prefixes that start the EC2 playbook."
  type        = list(string)
  default = [
    "AttackSequence:EC2/",
    "Backdoor:EC2/",
    "Behavior:EC2/",
    "CryptoCurrency:EC2/",
    "DefenseEvasion:EC2/",
    "Discovery:EC2/",
    "Execution:EC2/",
    "Impact:EC2/",
    "Persistence:EC2/",
    "Policy:EC2/",
    "PrivilegeEscalation:EC2/",
    "Recon:EC2/",
    "Stealth:EC2/",
    "Trojan:EC2/",
    "UnauthorizedAccess:EC2/",
  ]
}

variable "iam_finding_prefixes" {
  description = "GuardDuty type prefixes that start the IAM playbook."
  type        = list(string)
  default = [
    "CredentialAccess:IAMUser/",
    "DefenseEvasion:IAMUser/",
    "Discovery:IAMUser/",
    "Exfiltration:IAMUser/",
    "Impact:IAMUser/",
    "InitialAccess:IAMUser/",
    "PenTest:IAMUser/",
    "Persistence:IAMUser/",
    "Policy:IAMUser/",
    "PrivilegeEscalation:IAMUser/",
    "Recon:IAMUser/",
    "Stealth:IAMUser/",
    "UnauthorizedAccess:IAMUser/",
  ]
}

variable "s3_finding_prefixes" {
  description = "GuardDuty type prefixes that start the S3 playbook."
  type        = list(string)
  default = [
    "AttackSequence:S3/",
    "Discovery:S3/",
    "Exfiltration:S3/",
    "Impact:S3/",
    "Object:S3/",
    "PenTest:S3/",
    "Policy:S3/",
    "Stealth:S3/",
    "UnauthorizedAccess:S3/",
  ]
}
