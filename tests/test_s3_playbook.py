"""S3 public-access containment."""

from __future__ import annotations

import pytest
from botocore.exceptions import ClientError

from ir_automation.config import Settings
from ir_automation.playbooks.s3 import contain_s3
from ir_automation.simulation import build_event


def _event(buckets: list[str], severity: float = 8) -> dict:
    return build_event(
        finding_type="Policy:S3/BucketAnonymousAccessGranted",
        severity=severity,
        account_id="123456789012",
        region="us-east-1",
        bucket_names=buckets,
        finding_id="finding-s3",
    )


def _public_block(s3, bucket: str) -> dict:
    return s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]


def test_s3_blocks_public_access_and_preserves_existing_tags(aws, settings, sns) -> None:
    aws["s3"].create_bucket(Bucket="customer-data")
    aws["s3"].put_bucket_tagging(
        Bucket="customer-data",
        Tagging={"TagSet": [{"Key": "Application", "Value": "billing"}]},
    )

    result = contain_s3(_event(["customer-data"]), settings, aws["s3"], sns)

    assert result["status"] == "contained"
    block = _public_block(aws["s3"], "customer-data")
    assert block == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    tags = {tag["Key"]: tag["Value"] for tag in aws["s3"].get_bucket_tagging(Bucket="customer-data")["TagSet"]}
    assert tags["Application"] == "billing"
    assert tags["IR-Status"] == "public-access-blocked"
    assert sns.calls


def test_s3_refuses_protected_buckets(aws, settings, sns) -> None:
    aws["s3"].create_bucket(Bucket="ir-lab-evidence")
    aws["s3"].create_bucket(Bucket="customer-data")

    result = contain_s3(_event(["ir-lab-evidence", "customer-data"]), settings, aws["s3"], sns)

    assert result["status"] == "contained"
    assert any("refused" in action for action in result["actions"])
    with pytest.raises(ClientError):
        _public_block(aws["s3"], "ir-lab-evidence")
    assert _public_block(aws["s3"], "customer-data")["BlockPublicPolicy"] is True


def test_s3_missing_bucket(aws, settings, sns) -> None:
    result = contain_s3(_event(["does-not-exist-ir-lab"]), settings, aws["s3"], sns)

    assert result["status"] == "resource_not_found"
    assert sns.calls


def test_s3_notify_only_does_not_change_bucket(aws, sns, monkeypatch) -> None:
    monkeypatch.setenv("CONTAINMENT_MODE", "notify_only")
    aws["s3"].create_bucket(Bucket="customer-data")
    result = contain_s3(_event(["customer-data"]), Settings.from_env(), aws["s3"], sns)

    assert result["status"] == "notify_only"
    with pytest.raises(ClientError):
        _public_block(aws["s3"], "customer-data")
