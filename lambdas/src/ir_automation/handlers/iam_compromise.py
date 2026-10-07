"""Lambda entrypoint for the IAM credential playbook."""

from __future__ import annotations

from typing import Any

import boto3

from ir_automation.config import Settings
from ir_automation.playbooks.iam import contain_iam


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    settings = Settings.from_env()
    return contain_iam(
        event,
        settings,
        boto3.client("iam", region_name=settings.aws_region),
        boto3.client("s3", region_name=settings.aws_region),
        boto3.client("sns", region_name=settings.aws_region),
    )
