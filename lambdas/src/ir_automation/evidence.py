"""Write an immutable JSON record of what a playbook decided."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from ir_automation.config import Settings
from ir_automation.finding import Finding


def build_evidence_key(finding_id: str, playbook: str, when: datetime | None = None) -> str:
    moment = when or datetime.now(UTC)
    safe_id = re.sub(r"[^A-Za-z0-9_.:-]", "_", finding_id)[:128] or "unknown"
    safe_playbook = re.sub(r"[^A-Za-z0-9_-]", "_", playbook)[:64] or "playbook"
    return f"evidence/{moment:%Y/%m/%d}/{safe_id}/{safe_playbook}.json"


def write_evidence(
    s3_client: Any,
    settings: Settings,
    finding: Finding,
    playbook: str,
    body: dict[str, Any],
) -> str:
    """Store the playbook result. Bucket default encryption still applies."""

    key = build_evidence_key(finding.id, playbook)
    payload = dict(body)
    payload["raw_finding"] = finding.raw
    put_args: dict[str, Any] = {
        "Bucket": settings.evidence_bucket,
        "Key": key,
        "Body": json.dumps(payload, default=str, indent=2).encode("utf-8"),
        "ContentType": "application/json",
        "Metadata": {"finding-id": finding.id[:200], "playbook": playbook[:64]},
    }
    if settings.evidence_kms_key_id:
        put_args["ServerSideEncryption"] = "aws:kms"
        put_args["SSEKMSKeyId"] = settings.evidence_kms_key_id
    else:
        put_args["ServerSideEncryption"] = "AES256"
    s3_client.put_object(**put_args)
    return key
