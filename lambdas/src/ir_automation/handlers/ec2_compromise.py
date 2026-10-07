"""Lambda entrypoint for the EC2 compromise playbook."""

from __future__ import annotations

from typing import Any

import boto3

from ir_automation.config import Settings
from ir_automation.playbooks.ec2 import contain_ec2


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    settings = Settings.from_env()
    return contain_ec2(
        event,
        settings,
        boto3.client("ec2", region_name=settings.aws_region),
        boto3.client("s3", region_name=settings.aws_region),
        boto3.client("sns", region_name=settings.aws_region),
    )
