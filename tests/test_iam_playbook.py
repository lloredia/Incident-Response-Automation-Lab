"""IAM access-key and deny-policy containment."""

from __future__ import annotations

from tests.conftest import deny_all_policy

from ir_automation.config import Settings
from ir_automation.playbooks.iam import contain_iam
from ir_automation.simulation import build_event


def _event(
    user_name: str | None = "compromised",
    access_key_id: str | None = "AKIAIOSFODNN7EXAMPLE",
    user_type: str = "IAMUser",
    instance_id: str | None = None,
) -> dict:
    return build_event(
        finding_type="UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
        severity=5,
        account_id="123456789012",
        region="us-east-1",
        user_name=user_name,
        access_key_id=access_key_id,
        user_type=user_type,
        instance_id=instance_id,
        finding_id="finding-iam",
    )


def _user_with_key(iam):
    iam.create_user(UserName="compromised")
    key_id = iam.create_access_key(UserName="compromised")["AccessKey"]["AccessKeyId"]
    return key_id


def test_iam_deactivates_key_and_attaches_deny(aws, settings, sns, monkeypatch) -> None:
    key_id = _user_with_key(aws["iam"])
    policy_arn = deny_all_policy(aws["iam"])
    monkeypatch.setenv("DENY_ALL_POLICY_ARN", policy_arn)
    result = contain_iam(_event(access_key_id=key_id), Settings.from_env(), aws["iam"], aws["s3"], sns)

    assert result["status"] == "contained"
    keys = aws["iam"].list_access_keys(UserName="compromised")["AccessKeyMetadata"]
    assert keys[0]["Status"] == "Inactive"
    attached = aws["iam"].list_attached_user_policies(UserName="compromised")["AttachedPolicies"]
    assert attached[0]["PolicyArn"] == policy_arn
    assert sns.calls


def test_iam_second_run_reports_existing_containment(aws, sns, monkeypatch) -> None:
    key_id = _user_with_key(aws["iam"])
    policy_arn = deny_all_policy(aws["iam"])
    monkeypatch.setenv("DENY_ALL_POLICY_ARN", policy_arn)
    current = Settings.from_env()
    event = _event(access_key_id=key_id)
    contain_iam(event, current, aws["iam"], aws["s3"], sns)
    second = contain_iam(event, current, aws["iam"], aws["s3"], sns)

    assert second["status"] == "contained"
    assert any("already attached" in action for action in second["actions"])
    assert len(aws["iam"].list_attached_user_policies(UserName="compromised")["AttachedPolicies"]) == 1


def test_iam_unknown_user(aws, settings, sns, monkeypatch) -> None:
    policy_arn = deny_all_policy(aws["iam"])
    monkeypatch.setenv("DENY_ALL_POLICY_ARN", policy_arn)
    result = contain_iam(_event(), Settings.from_env(), aws["iam"], aws["s3"], sns)

    assert result["status"] == "resource_not_found"
    assert sns.calls


def test_iam_root_is_manual(aws, settings, sns) -> None:
    result = contain_iam(_event(user_name="root", user_type="Root"), settings, aws["iam"], aws["s3"], sns)

    assert result["status"] == "manual_follow_up"
    assert any("root" in action for action in result["actions"])


def test_iam_assumed_role_recommends_instance_follow_up(aws, settings, sns) -> None:
    result = contain_iam(
        _event(user_name="role-session", user_type="AssumedRole", instance_id="i-1234567890abcdef0"),
        settings,
        aws["iam"],
        aws["s3"],
        sns,
    )

    assert result["status"] == "manual_follow_up"
    assert any("i-1234567890abcdef0" in action for action in result["actions"])


def test_iam_notify_only_does_not_change_key(aws, sns, monkeypatch) -> None:
    key_id = _user_with_key(aws["iam"])
    policy_arn = deny_all_policy(aws["iam"])
    monkeypatch.setenv("DENY_ALL_POLICY_ARN", policy_arn)
    monkeypatch.setenv("CONTAINMENT_MODE", "notify_only")
    result = contain_iam(_event(access_key_id=key_id), Settings.from_env(), aws["iam"], aws["s3"], sns)

    assert result["status"] == "notify_only"
    keys = aws["iam"].list_access_keys(UserName="compromised")["AccessKeyMetadata"]
    assert keys[0]["Status"] == "Active"
    assert aws["iam"].list_attached_user_policies(UserName="compromised")["AttachedPolicies"] == []


def test_iam_account_restriction_skips(aws, sns, monkeypatch) -> None:
    monkeypatch.setenv("ALLOWED_ACCOUNT_ID", "999999999999")
    result = contain_iam(_event(), Settings.from_env(), aws["iam"], aws["s3"], sns)

    assert result["status"] == "skipped"
    assert sns.calls == []
