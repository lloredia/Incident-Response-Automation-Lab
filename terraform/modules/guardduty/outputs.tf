output "detector_id" {
  description = "GuardDuty detector ID in this region."
  value       = var.create_detector ? aws_guardduty_detector.this[0].id : var.existing_detector_id
}
