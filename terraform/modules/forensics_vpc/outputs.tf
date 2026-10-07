output "vpc_id" {
  description = "ID of the isolated forensics VPC."
  value       = aws_vpc.forensics.id
}

output "subnet_id" {
  description = "ID of the private forensics subnet."
  value       = aws_subnet.analysis.id
}

output "security_group_id" {
  description = "Security group with no rules, used for manual analysis instances."
  value       = aws_security_group.analysis.id
}
