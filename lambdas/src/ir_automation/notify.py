"""Notify responders through SNS and, when configured, Slack."""

from __future__ import annotations

import json
import logging
import urllib.error
from typing import Any
from urllib.request import Request, urlopen

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

SNS_SUBJECT_LIMIT = 100


def sns_subject(status: str, finding_type: str) -> str:
    """SNS subjects must be ASCII and at most 100 characters."""

    raw = f"IR {status}: {finding_type}"
    ascii_text = raw.encode("ascii", "replace").decode("ascii")
    return ascii_text[:SNS_SUBJECT_LIMIT]


def publish_message(sns_client: Any, topic_arn: str, subject: str, message: dict[str, Any]) -> str:
    response = sns_client.publish(
        TopicArn=topic_arn,
        Subject=subject[:SNS_SUBJECT_LIMIT],
        Message=json.dumps(message, default=str, indent=2, sort_keys=True),
    )
    return str(response["MessageId"])


def post_slack(webhook_url: str, text: str) -> None:
    payload = json.dumps({"text": text}).encode("utf-8")
    request = Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=5) as response:
        response.read()


def slack_text(message: dict[str, Any]) -> str:
    finding = message.get("finding") or {}
    actions = message.get("actions") or []
    lines = [
        f"*Incident response* `{message.get('status')}`",
        f"Playbook: `{message.get('playbook')}`",
        f"Finding: `{finding.get('type')}` ({finding.get('id')})",
        f"Severity: {finding.get('severity')}",
    ]
    if actions:
        lines.append("Actions:")
        lines.extend(f"• {action}" for action in actions)
    return "\n".join(lines)


def resolve_slack_webhook(settings: Any, ssm_client: Any | None = None) -> str:
    """Prefer an explicit URL. Otherwise read a SecureString parameter."""

    if settings.slack_webhook_url:
        return str(settings.slack_webhook_url)
    parameter_name = settings.slack_webhook_ssm_parameter
    if not parameter_name:
        return ""
    if ssm_client is None:
        ssm_client = boto3.client("ssm", region_name=settings.aws_region)
    response = ssm_client.get_parameter(Name=parameter_name, WithDecryption=True)
    return str(response.get("Parameter", {}).get("Value") or "")


def deliver_notification(
    sns_client: Any,
    settings: Any,
    message: dict[str, Any],
    ssm_client: Any | None = None,
) -> dict[str, str | None]:
    """Publish to SNS. Slack failures are reported and do not raise."""

    result: dict[str, str | None] = {"notification_id": None, "slack_error": None}
    finding = message.get("finding") or {}
    subject = sns_subject(str(message.get("status") or "update"), str(finding.get("type") or "finding"))
    if settings.sns_topic_arn:
        result["notification_id"] = publish_message(sns_client, settings.sns_topic_arn, subject, message)

    try:
        webhook = resolve_slack_webhook(settings, ssm_client=ssm_client)
    except (ClientError, BotoCoreError) as exc:
        logger.warning("slack webhook lookup failed: %s", exc)
        result["slack_error"] = "slack webhook lookup failed"
        return result

    if not webhook:
        return result
    try:
        post_slack(webhook, slack_text(message))
    except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
        logger.warning("slack notification failed: %s", exc)
        result["slack_error"] = "slack notification failed"
    return result
