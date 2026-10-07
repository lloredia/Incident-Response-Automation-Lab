"""Block public access on an S3 bucket named by a GuardDuty finding."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from ir_automation.config import Settings
from ir_automation.finding import Finding, parse_finding
from ir_automation.outcome import error_code, finish, preflight

PLAYBOOK = "s3-exfiltration"
PUBLIC_ACCESS_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}
MISSING = {"NoSuchBucket"}


def contain_s3(
    event: dict[str, Any],
    settings: Settings,
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
    if not finding.bucket_names:
        return finish(
            settings=settings,
            finding=finding,
            playbook=PLAYBOOK,
            status="resource_not_found",
            actions=["finding has no S3 bucket name"],
            details={},
            s3_client=s3_client,
            sns_client=sns_client,
        )

    actions: list[str] = []
    blocked: list[str] = []
    skipped: list[str] = []
    missing: list[str] = []
    for bucket in finding.bucket_names:
        outcome = _contain_bucket(s3_client, settings, finding, bucket)
        actions.append(outcome["action"])
        if outcome["state"] == "blocked":
            blocked.append(bucket)
        elif outcome["state"] == "protected":
            skipped.append(bucket)
        elif outcome["state"] == "missing":
            missing.append(bucket)

    if blocked:
        status = "notify_only" if settings.containment_mode == "notify_only" else "contained"
    elif missing and not skipped:
        status = "resource_not_found"
    elif skipped and not missing:
        status = "manual_follow_up"
    else:
        status = "resource_not_found"
    return finish(
        settings=settings,
        finding=finding,
        playbook=PLAYBOOK,
        status=status,
        actions=actions,
        details={"blocked": blocked, "protected": skipped, "missing": missing},
        s3_client=s3_client,
        sns_client=sns_client,
    )


def _contain_bucket(
    s3_client: Any,
    settings: Settings,
    finding: Finding,
    bucket: str,
) -> dict[str, str]:
    if bucket.lower() in settings.protected_buckets:
        return {
            "state": "protected",
            "action": f"refused to modify protected bucket {bucket}",
        }
    try:
        s3_client.get_bucket_location(Bucket=bucket)
    except ClientError as exc:
        if error_code(exc) in MISSING:
            return {"state": "missing", "action": f"bucket {bucket} was not found"}
        raise

    if settings.containment_mode == "notify_only":
        return {
            "state": "blocked",
            "action": f"would enable all public access blocks on {bucket}",
        }

    s3_client.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration=PUBLIC_ACCESS_BLOCK,
    )
    _tag_bucket(s3_client, finding, bucket)
    return {
        "state": "blocked",
        "action": f"enabled all public access blocks on {bucket}",
    }


def _tag_bucket(s3_client: Any, finding: Finding, bucket: str) -> None:
    try:
        existing = s3_client.get_bucket_tagging(Bucket=bucket).get("TagSet", [])
    except ClientError as exc:
        if error_code(exc) not in {"NoSuchTagSet", "NoSuchBucket"}:
            raise
        existing = []

    managed = {
        "IR-Managed": "true",
        "IR-Playbook": PLAYBOOK,
        "IR-Status": "public-access-blocked",
        "IR-FindingId": finding.id[:256],
        "IR-FindingType": finding.type[:256],
    }
    merged = [tag for tag in existing if tag.get("Key") not in managed]
    merged.extend({"Key": key, "Value": value} for key, value in managed.items())
    s3_client.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": merged})
