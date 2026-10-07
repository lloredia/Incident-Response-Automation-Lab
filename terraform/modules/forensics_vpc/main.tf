resource "aws_vpc" "forensics" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-forensics"
  }
}

resource "aws_default_security_group" "forensics" {
  vpc_id = aws_vpc.forensics.id
}

resource "aws_default_route_table" "forensics" {
  default_route_table_id = aws_vpc.forensics.default_route_table_id

  tags = {
    Name = "${var.project_name}-forensics-default"
  }
}

resource "aws_subnet" "analysis" {
  vpc_id                  = aws_vpc.forensics.id
  cidr_block              = var.subnet_cidr
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project_name}-forensics-analysis"
  }
}

resource "aws_network_acl" "analysis" {
  vpc_id     = aws_vpc.forensics.id
  subnet_ids = [aws_subnet.analysis.id]

  # A custom network ACL with no allow rules denies all traffic.
  tags = {
    Name = "${var.project_name}-forensics-analysis"
  }
}

resource "aws_security_group" "analysis" {
  #checkov:skip=CKV2_AWS_5:Attached by an analyst when a forensic instance is launched from a snapshot. This lab does not launch instances.
  name        = "${var.project_name}-forensic-analysis"
  description = "Forensic analysis instances. Add rules only during an investigation."
  vpc_id      = aws_vpc.forensics.id

  tags = {
    Name = "${var.project_name}-forensic-analysis"
  }
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/aws/vpc/flow-logs/${var.project_name}-forensics"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

data "aws_iam_policy_document" "flow_assume" {
  statement {
    sid     = "VpcFlowLogsAssume"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "flow" {
  statement {
    sid = "WriteFlowLogs"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.flow.arn}:*"]
  }
}

resource "aws_iam_role" "flow" {
  name               = "${var.project_name}-forensics-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_assume.json
  description        = "Publishes forensics VPC flow logs to CloudWatch Logs."
}

resource "aws_iam_role_policy" "flow" {
  name   = "cloudwatch-logs"
  role   = aws_iam_role.flow.id
  policy = data.aws_iam_policy_document.flow.json
}

resource "aws_flow_log" "forensics" {
  vpc_id               = aws_vpc.forensics.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow.arn
  iam_role_arn         = aws_iam_role.flow.arn
}
