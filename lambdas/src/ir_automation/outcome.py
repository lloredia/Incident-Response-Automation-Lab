"""Shared result shape for every playbook."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

from ir_automation.config import Settings
from ir_automation.evidence import write_evidence
from ir_automation.finding import Finding
from ir_automation.notify import deliver_notification

logger = logging.getLogger(__name__)

SILENT_STATUSES = {"skipped"}


def error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))


def finish(
    *,
    settings: Settings,
    finding: Finding,
    playbook: str,
    status: str,
    actions: list[str],
    details: dict[str, Any],
    s3_client: Any,
    sns_client: Any,
    ssm_client: Any | None = None,
) -> dict[str, Any]:
    """Record evidence and notify. Storage or notification errors stay in the result."""

    payload: dict[str, Any] = {
        "status": status,
        "playbook": playbook,
        "containment_mode": settings.containment_mode,
        "actions": actions,
        "details": details,
        "finding": finding.summary(),
        "recorded_at": datetime.now(UTC).isoformat(),
        "evidence_key": None,
        "evidence_error": None,
        "notification_id": None,
        "notification_error": None,
        "slack_error": None,
    }

    if settings.evidence_bucket:
        try:
            payload["evidence_key"] = write_evidence(s3_client, settings, finding, playbook, payload)
        except ClientError as exc:
            logger.exception("evidence write failed for finding %s", finding.id)
            payload["evidence_error"] = error_code(exc) or "evidence write failed"

    if status not in SILENT_STATUSES:
        try:
            delivered = deliver_notification(sns_client, settings, payload, ssm_client=ssm_client)
        except ClientError as exc:
            logger.exception("notification failed for finding %s", finding.id)
            payload["notification_error"] = error_code(exc) or "notification failed"
        else:
            payload["notification_id"] = delivered["notification_id"]
            payload["slack_error"] = delivered["slack_error"]

    logger.info(
        "playbook=%s finding=%s type=%s status=%s",
        playbook,
        finding.id,
        finding.type,
        status,
    )
    return payload


def preflight(
    *,
    settings: Settings,
    finding: Finding,
    playbook: str,
    s3_client: Any,
    sns_client: Any,
) -> dict[str, Any] | None:
    """Return a finished result when this stack must not contain the finding."""

    if finding.severity < settings.min_severity:
        return finish(
            settings=settings,
            finding=finding,
            playbook=playbook,
            status="skipped",
            actions=[f"severity {finding.severity:g} is below the minimum {settings.min_severity:g}"],
            details={},
            s3_client=s3_client,
            sns_client=sns_client,
        )

    if settings.allowed_account_id and finding.account_id and finding.account_id != settings.allowed_account_id:
        return finish(
            settings=settings,
            finding=finding,
            playbook=playbook,
            status="skipped",
            actions=[f"ignored finding for account {finding.account_id}"],
            details={"allowed_account_id": settings.allowed_account_id},
            s3_client=s3_client,
            sns_client=sns_client,
        )

    if finding.region and finding.region != settings.aws_region:
        return finish(
            settings=settings,
            finding=finding,
            playbook=playbook,
            status="manual_follow_up",
            actions=[f"finding region {finding.region} does not match playbook region {settings.aws_region}"],
            details={},
            s3_client=s3_client,
            sns_client=sns_client,
        )
    return None
