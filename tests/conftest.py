"""Shared fixtures for playbook tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import boto3
import pytest
from moto import mock_aws

from ir_automation.config import Settings

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("CONTAINMENT_MODE", "enforce")
    monkeypatch.setenv("MIN_SEVERITY", "1")
    monkeypatch.setenv("PROJECT_NAME", "ir-lab")
    monkeypatch.setenv("QUARANTINE_SSH_CIDR", "")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "")
    monkeypatch.setenv("SLACK_WEBHOOK_SSM_PARAMETER", "")
    monkeypatch.setenv("EVIDENCE_KMS_KEY_ID", "")
    monkeypatch.setenv("PROTECTED_BUCKETS", "ir-lab-evidence,ir-lab-cloudtrail")
    monkeypatch.setenv("ALLOWED_ACCOUNT_ID", "")
    monkeypatch.setenv("DENY_ALL_POLICY_ARN", "")
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:ir-lab")
    monkeypatch.setenv("EVIDENCE_BUCKET", "evidence-bucket")


@pytest.fixture
def settings() -> Settings:
    return Settings.from_env()


class RecordingSns:
    """Captures SNS publish calls without standing up the SNS API."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def publish(self, **kwargs: Any) -> dict[str, str]:
        self.calls.append(kwargs)
        return {"MessageId": "msg-1"}


@pytest.fixture
def sns() -> RecordingSns:
    return RecordingSns()


@pytest.fixture
def aws() -> Any:
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="evidence-bucket")
        yield {
            "s3": s3,
            "ec2": boto3.client("ec2", region_name="us-east-1"),
            "iam": boto3.client("iam", region_name="us-east-1"),
            "ssm": boto3.client("ssm", region_name="us-east-1"),
        }


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def launch_instance(ec2: Any) -> dict[str, Any]:
    vpc_id = ec2.create_vpc(CidrBlock="10.50.0.0/16")["Vpc"]["VpcId"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.50.1.0/24")["Subnet"]["SubnetId"]
    group_id = ec2.create_security_group(
        GroupName="web",
        Description="Application security group replaced during quarantine.",
        VpcId=vpc_id,
    )["GroupId"]
    instance_id = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        SecurityGroupIds=[group_id],
    )["Instances"][0]["InstanceId"]
    return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]


def deny_all_policy(iam: Any) -> str:
    document = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "DenyAll", "Effect": "Deny", "Action": "*", "Resource": "*"}],
    }
    return iam.create_policy(
        PolicyName="IncidentResponseDenyAll",
        PolicyDocument=json.dumps(document),
    )["Policy"]["Arn"]
