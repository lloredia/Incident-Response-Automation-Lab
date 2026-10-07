"""EC2 quarantine, snapshot, and tagging behavior."""

from __future__ import annotations

import json

import boto3
from tests.conftest import launch_instance

from ir_automation.config import Settings
from ir_automation.handlers.ec2_compromise import handler
from ir_automation.playbooks.ec2 import contain_ec2
from ir_automation.simulation import build_event


def _event(instance_id: str, finding_id: str = "finding-ec2", severity: float = 8) -> dict:
    return build_event(
        finding_type="CryptoCurrency:EC2/BitcoinTool.B",
        severity=severity,
        account_id="123456789012",
        region="us-east-1",
        instance_id=instance_id,
        finding_id=finding_id,
    )


def test_ec2_quarantines_snapshots_and_tags(aws, settings, sns) -> None:
    instance = launch_instance(aws["ec2"])
    original_group = instance["SecurityGroups"][0]["GroupId"]
    event = _event(instance["InstanceId"])

    result = contain_ec2(event, settings, aws["ec2"], aws["s3"], sns)

    assert result["status"] == "contained"
    described = aws["ec2"].describe_instances(InstanceIds=[instance["InstanceId"]])
    updated = described["Reservations"][0]["Instances"][0]
    groups = [group["GroupId"] for group in updated["SecurityGroups"]]
    assert groups != [original_group]
    assert len(groups) == 1
    quarantine = aws["ec2"].describe_security_groups(GroupIds=groups)["SecurityGroups"][0]
    assert quarantine["IpPermissions"] == []
    assert quarantine["IpPermissionsEgress"] == []
    tags = {tag["Key"]: tag["Value"] for tag in updated["Tags"]}
    assert tags["IR-Status"] == "quarantined"
    assert tags["IR-Managed"] == "true"
    assert tags["IR-OriginalSecurityGroups"] == original_group
    snapshots = aws["ec2"].describe_snapshots(Filters=[{"Name": "tag:IR-FindingId", "Values": ["finding-ec2"]}])[
        "Snapshots"
    ]
    assert len(snapshots) == 1
    evidence = json.loads(aws["s3"].get_object(Bucket="evidence-bucket", Key=result["evidence_key"])["Body"].read())
    assert evidence["status"] == "contained"
    assert evidence["raw_finding"]["id"] == "finding-ec2"
    assert sns.calls
    message = json.loads(sns.calls[0]["Message"])
    assert message["status"] == "contained"


def test_ec2_second_run_is_idempotent(aws, settings, sns) -> None:
    instance = launch_instance(aws["ec2"])
    event = _event(instance["InstanceId"])
    first = contain_ec2(event, settings, aws["ec2"], aws["s3"], sns)
    second = contain_ec2(event, settings, aws["ec2"], aws["s3"], sns)

    assert first["status"] == "contained"
    assert second["status"] == "contained"
    assert any("already quarantined" in action for action in second["actions"])
    described = aws["ec2"].describe_instances(InstanceIds=[instance["InstanceId"]])
    updated = described["Reservations"][0]["Instances"][0]
    tags = {tag["Key"]: tag["Value"] for tag in updated["Tags"]}
    assert tags["IR-OriginalSecurityGroups"] == first["details"]["original_security_groups"]
    snapshots = aws["ec2"].describe_snapshots(Filters=[{"Name": "tag:IR-FindingId", "Values": ["finding-ec2"]}])[
        "Snapshots"
    ]
    assert len(snapshots) == 1
    groups = aws["ec2"].describe_security_groups(
        Filters=[{"Name": "group-name", "Values": [f"ir-lab-quarantine-{updated['VpcId']}"]}]
    )["SecurityGroups"]
    assert len(groups) == 1


def test_ec2_missing_instance_notifies_without_changes(aws, settings, sns) -> None:
    result = contain_ec2(_event("i-99999999"), settings, aws["ec2"], aws["s3"], sns)

    assert result["status"] == "resource_not_found"
    assert sns.calls
    assert aws["ec2"].describe_snapshots(Filters=[{"Name": "tag:IR-Managed", "Values": ["true"]}])["Snapshots"] == []


def test_ec2_notify_only_does_not_mutate(aws, settings, sns, monkeypatch) -> None:
    monkeypatch.setenv("CONTAINMENT_MODE", "notify_only")
    instance = launch_instance(aws["ec2"])
    original_group = instance["SecurityGroups"][0]["GroupId"]

    result = contain_ec2(_event(instance["InstanceId"]), Settings.from_env(), aws["ec2"], aws["s3"], sns)

    assert result["status"] == "notify_only"
    described = aws["ec2"].describe_instances(InstanceIds=[instance["InstanceId"]])
    updated = described["Reservations"][0]["Instances"][0]
    assert [group["GroupId"] for group in updated["SecurityGroups"]] == [original_group]
    assert aws["ec2"].describe_snapshots(Filters=[{"Name": "tag:IR-Managed", "Values": ["true"]}])["Snapshots"] == []


def test_ec2_below_severity_records_evidence_without_notification(aws, settings, sns) -> None:
    instance = launch_instance(aws["ec2"])
    result = contain_ec2(
        _event(instance["InstanceId"], severity=0.5),
        settings,
        aws["ec2"],
        aws["s3"],
        sns,
    )

    assert result["status"] == "skipped"
    assert result["evidence_key"]
    assert sns.calls == []


def test_ec2_ssh_cidr_allows_only_that_cidr(aws, sns, monkeypatch) -> None:
    monkeypatch.setenv("QUARANTINE_SSH_CIDR", "203.0.113.10/32")
    instance = launch_instance(aws["ec2"])
    result = contain_ec2(_event(instance["InstanceId"]), Settings.from_env(), aws["ec2"], aws["s3"], sns)

    group_id = result["details"]["quarantine_security_group"]
    group = aws["ec2"].describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
    assert group["IpPermissionsEgress"] == []
    assert group["IpPermissions"][0]["FromPort"] == 22
    assert group["IpPermissions"][0]["IpRanges"][0]["CidrIp"] == "203.0.113.10/32"


def test_ec2_region_mismatch_does_not_quarantine(aws, settings, sns) -> None:
    instance = launch_instance(aws["ec2"])
    event = _event(instance["InstanceId"])
    event["region"] = "us-west-2"
    event["detail"]["region"] = "us-west-2"

    result = contain_ec2(event, settings, aws["ec2"], aws["s3"], sns)

    assert result["status"] == "manual_follow_up"
    described = aws["ec2"].describe_instances(InstanceIds=[instance["InstanceId"]])
    updated = described["Reservations"][0]["Instances"][0]
    assert len(updated["SecurityGroups"]) == 1


def test_ec2_handler_uses_environment(aws, monkeypatch) -> None:
    instance = launch_instance(aws["ec2"])
    topic = boto3.client("sns", region_name="us-east-1").create_topic(Name="ir-lab")["TopicArn"]
    monkeypatch.setenv("SNS_TOPIC_ARN", topic)

    result = handler(_event(instance["InstanceId"]), None)

    assert result["status"] == "contained"
    assert result["notification_id"]
