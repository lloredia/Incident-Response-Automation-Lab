"""Lambda entrypoint for failed or unmatched findings."""

from __future__ import annotations

from typing import Any

import boto3

from ir_automation.config import Settings
from ir_automation.playbooks.notify import handle_notification


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    settings = Settings.from_env()
    return handle_notification(
        event,
        settings,
        boto3.client("s3", region_name=settings.aws_region),
        boto3.client("sns", region_name=settings.aws_region),
    )
