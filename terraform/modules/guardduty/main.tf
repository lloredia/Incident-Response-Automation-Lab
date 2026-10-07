resource "aws_guardduty_detector" "this" {
  #checkov:skip=CKV2_AWS_3:The lab enables a detector in the deployment region. Organization admin delegation is an account-wide control.
  count                        = var.create_detector ? 1 : 0
  enable                       = true
  finding_publishing_frequency = var.finding_publishing_frequency
}

resource "aws_guardduty_detector_feature" "s3_data_events" {
  count       = var.create_detector && var.enable_s3_data_events ? 1 : 0
  detector_id = aws_guardduty_detector.this[0].id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}
