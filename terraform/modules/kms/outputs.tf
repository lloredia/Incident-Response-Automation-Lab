output "key_arn" {
  description = "ARN of the incident-response customer managed key."
  value       = aws_kms_key.this.arn
}

output "key_id" {
  description = "ID of the incident-response customer managed key."
  value       = aws_kms_key.this.key_id
}
