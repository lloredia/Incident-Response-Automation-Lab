"""Deactivate a compromised IAM access key and attach a deny-all policy."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from ir_automation.config import Settings
from ir_automation.finding import parse_finding
from ir_automation.outcome import error_code, finish, preflight

PLAYBOOK = "iam-compromise"
AUTOMATED_USER_TYPES = {"IAMUser", ""}


def contain_iam(
    event: dict[str, Any],
    settings: Settings,
    iam_client: Any,
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

    if not finding.user_name and not finding.access_key_id:
        return finish(
            settings=settings,
            finding=finding,
            playbook=PLAYBOOK,
            status="resource_not_found",
            actions=["finding has no IAM user or access key"],
            details={},
            s3_client=s3_client,
            sns_client=sns_client,
        )

    user_type = finding.user_type or ""
    if user_type == "Root":
        return finish(
            settings=settings,
            finding=finding,
            playbook=PLAYBOOK,
            status="manual_follow_up",
            actions=["root credentials cannot be contained with an IAM deny policy"],
            details={"user_type": user_type},
            s3_client=s3_client,
            sns_client=sns_client,
        )
    if user_type not in AUTOMATED_USER_TYPES:
        actions = [f"principal type {user_type} is not an IAM user; automatic containment skipped"]
        if finding.instance_id:
            actions.append(f"follow up with the EC2 playbook for instance {finding.instance_id}")
        return finish(
            settings=settings,
            finding=finding,
            playbook=PLAYBOOK,
            status="manual_follow_up",
            actions=actions,
            details={"user_type": user_type, "instance_id": finding.instance_id},
            s3_client=s3_client,
            sns_client=sns_client,
        )

    if settings.containment_mode == "notify_only":
        actions = []
        if finding.access_key_id:
            actions.append(f"would deactivate access key {finding.access_key_id}")
        if finding.user_name:
            actions.append(f"would attach the deny-all policy to {finding.user_name}")
        return finish(
            settings=settings,
            finding=finding,
            playbook=PLAYBOOK,
            status="notify_only",
            actions=actions,
            details={"user_name": finding.user_name, "access_key_id": finding.access_key_id},
            s3_client=s3_client,
            sns_client=sns_client,
        )

    actions = []
    contained = False
    missing = False
    if finding.user_name and finding.access_key_id:
        try:
            iam_client.update_access_key(
                UserName=finding.user_name,
                AccessKeyId=finding.access_key_id,
                Status="Inactive",
            )
        except ClientError as exc:
            if error_code(exc) != "NoSuchEntity":
                raise
            actions.append(f"access key {finding.access_key_id} or user {finding.user_name} was not found")
            missing = True
        else:
            actions.append(f"deactivated access key {finding.access_key_id}")
            contained = True
    elif finding.access_key_id:
        actions.append("access key was present without a user name and was not changed")

    if finding.user_name and settings.deny_all_policy_arn:
        try:
            attached = iam_client.list_attached_user_policies(UserName=finding.user_name)
        except ClientError as exc:
            if error_code(exc) != "NoSuchEntity":
                raise
            actions.append(f"IAM user {finding.user_name} was not found")
            missing = True
        else:
            attached_arns = {item["PolicyArn"] for item in attached.get("AttachedPolicies", [])}
            if settings.deny_all_policy_arn in attached_arns:
                actions.append(f"deny-all policy already attached to {finding.user_name}")
            else:
                iam_client.attach_user_policy(
                    UserName=finding.user_name,
                    PolicyArn=settings.deny_all_policy_arn,
                )
                actions.append(f"attached deny-all policy to {finding.user_name}")
            contained = True
    elif finding.user_name:
        actions.append("DENY_ALL_POLICY_ARN is not configured; user policy was not changed")

    status = "contained" if contained else "resource_not_found"
    if missing and not contained:
        status = "resource_not_found"
    return finish(
        settings=settings,
        finding=finding,
        playbook=PLAYBOOK,
        status=status,
        actions=actions,
        details={"user_name": finding.user_name, "access_key_id": finding.access_key_id},
        s3_client=s3_client,
        sns_client=sns_client,
    )
