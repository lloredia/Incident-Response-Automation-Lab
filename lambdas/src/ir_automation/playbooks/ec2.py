"""Quarantine a compromised EC2 instance and snapshot its volumes."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from ir_automation.config import Settings
from ir_automation.finding import Finding, parse_finding
from ir_automation.outcome import error_code, finish, preflight

PLAYBOOK = "ec2-compromise"
NOT_FOUND = {"InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"}


def contain_ec2(
    event: dict[str, Any],
    settings: Settings,
    ec2_client: Any,
    s3_client: Any,
    sns_client: Any,
) -> dict[str, Any]:
    finding = parse_finding(event)
    early = preflight(
        settings=settings,
        finding=finding,
        playbook=PLAYBOOK,
        s3_client=s3_client,
        sns_client=sns_client,
    )
    if early is not None:
        return early
    if not finding.instance_id:
        return finish(
            settings=settings,
            finding=finding,
            playbook=PLAYBOOK,
            status="resource_not_found",
            actions=["finding has no EC2 instance id"],
            details={},
            s3_client=s3_client,
            sns_client=sns_client,
        )

    try:
        reservations = ec2_client.describe_instances(InstanceIds=[finding.instance_id])["Reservations"]
    except ClientError as exc:
        if error_code(exc) in NOT_FOUND:
            return finish(
                settings=settings,
                finding=finding,
                playbook=PLAYBOOK,
                status="resource_not_found",
                actions=[f"instance {finding.instance_id} was not found"],
                details={"instance_id": finding.instance_id},
                s3_client=s3_client,
                sns_client=sns_client,
            )
        raise

    instances = [item for reservation in reservations for item in reservation.get("Instances", [])]
    if not instances:
        return finish(
            settings=settings,
            finding=finding,
            playbook=PLAYBOOK,
            status="resource_not_found",
            actions=[f"instance {finding.instance_id} was not found"],
            details={"instance_id": finding.instance_id},
            s3_client=s3_client,
            sns_client=sns_client,
        )

    instance = instances[0]
    vpc_id = instance.get("VpcId")
    if not vpc_id:
        return finish(
            settings=settings,
            finding=finding,
            playbook=PLAYBOOK,
            status="manual_follow_up",
            actions=[f"instance {finding.instance_id} has no VPC and was not quarantined"],
            details={"instance_id": finding.instance_id},
            s3_client=s3_client,
            sns_client=sns_client,
        )

    current_groups = [group["GroupId"] for group in instance.get("SecurityGroups", [])]
    if settings.containment_mode == "notify_only":
        return finish(
            settings=settings,
            finding=finding,
            playbook=PLAYBOOK,
            status="notify_only",
            actions=[
                f"would replace security groups {current_groups} with a quarantine group in {vpc_id}",
                "would snapshot attached EBS volumes",
                "would tag the instance IR-Status=quarantined",
            ],
            details={"instance_id": finding.instance_id, "vpc_id": vpc_id, "security_groups": current_groups},
            s3_client=s3_client,
            sns_client=sns_client,
        )

    quarantine_group_id = _ensure_quarantine_group(ec2_client, settings, finding, vpc_id)
    actions: list[str] = []
    already_quarantined = current_groups == [quarantine_group_id]
    if already_quarantined:
        actions.append(f"instance already quarantined with {quarantine_group_id}")
    else:
        ec2_client.modify_instance_attribute(InstanceId=finding.instance_id, Groups=[quarantine_group_id])
        actions.append(f"replaced security groups {current_groups} with {quarantine_group_id}")

    original_groups = _original_groups(instance, current_groups, quarantine_group_id) or "none"
    _tag_instance(ec2_client, finding, finding.instance_id, quarantine_group_id, original_groups)
    actions.append("tagged instance IR-Status=quarantined")

    snapshot_ids = _snapshot_volumes(ec2_client, finding, instance)
    if snapshot_ids:
        actions.append("snapshotted volumes " + ", ".join(snapshot_ids))
    else:
        actions.append("no new snapshots were required")

    return finish(
        settings=settings,
        finding=finding,
        playbook=PLAYBOOK,
        status="contained",
        actions=actions,
        details={
            "instance_id": finding.instance_id,
            "vpc_id": vpc_id,
            "quarantine_security_group": quarantine_group_id,
            "original_security_groups": original_groups,
            "snapshot_ids": snapshot_ids,
        },
        s3_client=s3_client,
        sns_client=sns_client,
    )


def _ensure_quarantine_group(ec2_client: Any, settings: Settings, finding: Finding, vpc_id: str) -> str:
    name = f"{settings.project_name}-quarantine-{vpc_id}"
    found = ec2_client.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": [name]},
        ]
    )["SecurityGroups"]
    if found:
        group_id = found[0]["GroupId"]
    else:
        try:
            created = ec2_client.create_security_group(
                GroupName=name,
                Description="Incident response quarantine. No traffic except optional analyst SSH.",
                VpcId=vpc_id,
                TagSpecifications=[
                    {
                        "ResourceType": "security-group",
                        "Tags": _managed_tags(finding, name),
                    }
                ],
            )
        except ClientError as exc:
            if error_code(exc) != "InvalidGroup.Duplicate":
                raise
            found = ec2_client.describe_security_groups(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "group-name", "Values": [name]},
                ]
            )["SecurityGroups"]
            group_id = found[0]["GroupId"]
        else:
            group_id = created["GroupId"]
            _revoke_all_egress(ec2_client, group_id)

    if settings.quarantine_ssh_cidr:
        _ensure_ssh(ec2_client, group_id, settings.quarantine_ssh_cidr)
    return group_id


def _revoke_all_egress(ec2_client: Any, group_id: str) -> None:
    group = ec2_client.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
    permissions = group.get("IpPermissionsEgress") or []
    if permissions:
        ec2_client.revoke_security_group_egress(GroupId=group_id, IpPermissions=permissions)


def _ensure_ssh(ec2_client: Any, group_id: str, cidr: str) -> None:
    group = ec2_client.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
    for permission in group.get("IpPermissions") or []:
        if permission.get("IpProtocol") != "tcp":
            continue
        if permission.get("FromPort") != 22 or permission.get("ToPort") != 22:
            continue
        if any(entry.get("CidrIp") == cidr for entry in permission.get("IpRanges") or []):
            return
    ec2_client.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": cidr, "Description": "IR analyst SSH"}],
            }
        ],
    )


def _original_groups(instance: dict[str, Any], current_groups: list[str], quarantine_group_id: str) -> str:
    existing = {tag["Key"]: tag["Value"] for tag in instance.get("Tags") or []}
    preserved = existing.get("IR-OriginalSecurityGroups")
    if preserved:
        return preserved[:256]
    originals = [group_id for group_id in current_groups if group_id != quarantine_group_id]
    return ",".join(originals)[:256]


def _tag_instance(
    ec2_client: Any,
    finding: Finding,
    instance_id: str,
    quarantine_group_id: str,
    original_groups: str,
) -> None:
    ec2_client.create_tags(
        Resources=[instance_id],
        Tags=[
            *_managed_tags(finding, f"quarantine-{instance_id}"),
            {"Key": "IR-Status", "Value": "quarantined"},
            {"Key": "IR-QuarantineSecurityGroup", "Value": quarantine_group_id},
            {"Key": "IR-OriginalSecurityGroups", "Value": original_groups},
        ],
    )


def _snapshot_volumes(ec2_client: Any, finding: Finding, instance: dict[str, Any]) -> list[str]:
    snapshot_ids: list[str] = []
    for mapping in instance.get("BlockDeviceMappings") or []:
        volume_id = (mapping.get("Ebs") or {}).get("VolumeId")
        if not volume_id:
            continue
        existing = ec2_client.describe_snapshots(
            OwnerIds=["self"],
            Filters=[
                {"Name": "tag:IR-FindingId", "Values": [finding.id]},
                {"Name": "volume-id", "Values": [volume_id]},
            ],
        )["Snapshots"]
        if existing:
            snapshot_ids.append(existing[0]["SnapshotId"])
            continue
        created = ec2_client.create_snapshot(
            VolumeId=volume_id,
            Description=f"IR forensic snapshot {finding.id} {finding.instance_id}",
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [
                        *_managed_tags(finding, f"snapshot-{volume_id}"),
                        {"Key": "IR-VolumeId", "Value": volume_id},
                        {"Key": "IR-Purpose", "Value": "forensics"},
                    ],
                }
            ],
        )
        snapshot_ids.append(created["SnapshotId"])
    return snapshot_ids


def _managed_tags(finding: Finding, name: str) -> list[dict[str, str]]:
    return [
        {"Key": "Name", "Value": name[:256]},
        {"Key": "IR-Managed", "Value": "true"},
        {"Key": "IR-Playbook", "Value": PLAYBOOK},
        {"Key": "IR-FindingId", "Value": finding.id[:256]},
        {"Key": "IR-FindingType", "Value": finding.type[:256]},
    ]
