"""Notify responders when a playbook fails or no playbook matches."""

from __future__ import annotations

from typing import Any

from ir_automation.config import Settings
from ir_automation.finding import Finding, FindingParseError, parse_finding
from ir_automation.outcome import finish

PLAYBOOK = "failure-notify"


def handle_notification(
    event: dict[str, Any],
    settings: Settings,
    s3_client: Any,
    sns_client: Any,
) -> dict[str, Any]:
    error = event.get("error") if isinstance(event, dict) else None
    try:
        finding = parse_finding(event if isinstance(event, dict) else {})
    except FindingParseError:
        finding = _unknown_finding(settings)

    if error:
        cause = _cause(error)
        status = "failed"
        actions = ["playbook execution failed", cause] if cause else ["playbook execution failed"]
    elif finding.id == "unparsed":
        status = "failed"
        actions = ["event could not be parsed as a GuardDuty finding"]
    else:
        status = "manual_follow_up"
        actions = [f"no containment playbook for {finding.type}"]

    return finish(
        settings=settings,
        finding=finding,
        playbook=PLAYBOOK,
        status=status,
        actions=actions,
        details={"error": error} if error else {},
        s3_client=s3_client,
        sns_client=sns_client,
    )


def _cause(error: Any) -> str:
    if isinstance(error, dict):
        text = str(error.get("Cause") or error.get("Error") or "")
    else:
        text = str(error or "")
    return text[:500]


def _unknown_finding(settings: Settings) -> Finding:
    return Finding(
        id="unparsed",
        type="unknown",
        severity=0,
        account_id=settings.allowed_account_id,
        region=settings.aws_region,
        title="Unparsed event",
        description="",
        instance_id=None,
        access_key_id=None,
        user_name=None,
        user_type=None,
        bucket_names=(),
        raw={},
    )
