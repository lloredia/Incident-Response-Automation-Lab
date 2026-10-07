data "aws_caller_identity" "current" {}

locals {
  trail_name = "${var.project_name}-trail"
}

module "kms" {
  source       = "./modules/kms"
  project_name = var.project_name
  trail_name   = local.trail_name
}

module "storage" {
  source                     = "./modules/storage"
  project_name               = var.project_name
  kms_key_arn                = module.kms.key_arn
  trail_name                 = local.trail_name
  enable_cloudtrail          = var.enable_cloudtrail
  evidence_expiration_days   = var.evidence_expiration_days
  cloudtrail_expiration_days = var.cloudtrail_expiration_days
}

module "logging" {
  count                       = var.enable_cloudtrail ? 1 : 0
  source                      = "./modules/logging"
  project_name                = var.project_name
  kms_key_arn                 = module.kms.key_arn
  cloudtrail_bucket_name      = module.storage.cloudtrail_bucket_name
  cloudtrail_bucket_policy_id = module.storage.cloudtrail_bucket_policy_id
  log_retention_days          = var.log_retention_days
  trail_name                  = local.trail_name
}

module "notifications" {
  source             = "./modules/notifications"
  project_name       = var.project_name
  kms_key_arn        = module.kms.key_arn
  notification_email = var.notification_email
  slack_webhook_url  = var.slack_webhook_url
}

module "guardduty" {
  source                       = "./modules/guardduty"
  create_detector              = var.create_guardduty_detector
  existing_detector_id         = var.existing_detector_id
  finding_publishing_frequency = var.finding_publishing_frequency
  enable_s3_data_events        = var.enable_s3_data_events
}

module "forensics_vpc" {
  count              = var.enable_forensics_vpc ? 1 : 0
  source             = "./modules/forensics_vpc"
  project_name       = var.project_name
  vpc_cidr           = var.forensics_vpc_cidr
  subnet_cidr        = var.forensics_subnet_cidr
  kms_key_arn        = module.kms.key_arn
  log_retention_days = var.log_retention_days
}

module "lambdas" {
  source                 = "./modules/lambdas"
  project_name           = var.project_name
  kms_key_arn            = module.kms.key_arn
  evidence_bucket_name   = module.storage.evidence_bucket_name
  evidence_bucket_arn    = module.storage.evidence_bucket_arn
  sns_topic_arn          = module.notifications.topic_arn
  dlq_arn                = module.notifications.dlq_arn
  containment_mode       = var.containment_mode
  min_severity           = var.min_severity
  quarantine_ssh_cidr    = var.quarantine_ssh_cidr
  protected_bucket_names = module.storage.protected_bucket_names
  protected_bucket_arns  = module.storage.protected_bucket_arns
  slack_parameter_name   = module.notifications.slack_parameter_name
  slack_parameter_arn    = module.notifications.slack_parameter_arn
  allowed_account_id     = var.restrict_to_account ? data.aws_caller_identity.current.account_id : ""
  log_retention_days     = var.log_retention_days
  reserved_concurrency   = var.reserved_concurrency
  source_dir             = abspath("${path.root}/../lambdas/src")
}

module "step_functions" {
  source             = "./modules/step_functions"
  project_name       = var.project_name
  kms_key_arn        = module.kms.key_arn
  log_retention_days = var.log_retention_days
  ec2_lambda_arn     = module.lambdas.ec2_function_arn
  iam_lambda_arn     = module.lambdas.iam_function_arn
  s3_lambda_arn      = module.lambdas.s3_function_arn
  notify_lambda_arn  = module.lambdas.notify_function_arn
}

module "eventbridge" {
  source               = "./modules/eventbridge"
  project_name         = var.project_name
  state_machine_arn    = module.step_functions.state_machine_arn
  dlq_arn              = module.notifications.dlq_arn
  dlq_url              = module.notifications.dlq_url
  min_severity         = var.min_severity
  ec2_finding_prefixes = var.ec2_finding_prefixes
  iam_finding_prefixes = var.iam_finding_prefixes
  s3_finding_prefixes  = var.s3_finding_prefixes
}
