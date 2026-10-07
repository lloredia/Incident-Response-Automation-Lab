variable "project_name" {
  description = "Prefix for forensics network resource names."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the isolated forensics VPC."
  type        = string
}

variable "subnet_cidr" {
  description = "CIDR block for the forensics analysis subnet."
  type        = string
}

variable "kms_key_arn" {
  description = "Customer managed key for VPC flow logs."
  type        = string
}

variable "log_retention_days" {
  description = "Retention for the forensics VPC flow log group."
  type        = number
}
