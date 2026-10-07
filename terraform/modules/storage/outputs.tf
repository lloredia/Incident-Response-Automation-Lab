output "evidence_bucket_name" {
  description = "Bucket that stores playbook evidence JSON."
  value       = aws_s3_bucket.evidence.bucket
}

output "evidence_bucket_arn" {
  description = "ARN of the evidence bucket."
  value       = aws_s3_bucket.evidence.arn
}

output "access_logs_bucket_name" {
  description = "Bucket that receives S3 server access logs."
  value       = aws_s3_bucket.access_logs.bucket
}

output "access_logs_bucket_arn" {
  description = "ARN of the access log bucket."
  value       = aws_s3_bucket.access_logs.arn
}

output "cloudtrail_bucket_name" {
  description = "CloudTrail log bucket name, or null when CloudTrail is disabled."
  value       = try(aws_s3_bucket.cloudtrail[0].bucket, null)
}

output "cloudtrail_bucket_arn" {
  description = "CloudTrail log bucket ARN, or null when CloudTrail is disabled."
  value       = try(aws_s3_bucket.cloudtrail[0].arn, null)
}

output "protected_bucket_names" {
  description = "Lab buckets the S3 playbook must not modify."
  value = compact([
    aws_s3_bucket.evidence.bucket,
    aws_s3_bucket.access_logs.bucket,
    try(aws_s3_bucket.cloudtrail[0].bucket, ""),
  ])
}

output "cloudtrail_bucket_policy_id" {
  description = "CloudTrail bucket policy ID, used so the trail is created after the policy."
  value       = try(aws_s3_bucket_policy.cloudtrail[0].id, null)
}

output "protected_bucket_arns" {
  description = "ARNs of lab buckets the S3 playbook is denied from changing."
  value = compact([
    aws_s3_bucket.evidence.arn,
    aws_s3_bucket.access_logs.arn,
    try(aws_s3_bucket.cloudtrail[0].arn, ""),
  ])
}
