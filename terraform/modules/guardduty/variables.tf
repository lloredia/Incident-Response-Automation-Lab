variable "create_detector" {
  description = "Create a GuardDuty detector. Set false when this region already has one."
  type        = bool
}

variable "existing_detector_id" {
  description = "Detector ID to reuse when create_detector is false."
  type        = string
}

variable "finding_publishing_frequency" {
  description = "How often GuardDuty publishes findings. FIFTEEN_MINUTES keeps the lab responsive."
  type        = string
}

variable "enable_s3_data_events" {
  description = "Enable GuardDuty S3 protection so data-event findings can be produced."
  type        = bool
}
