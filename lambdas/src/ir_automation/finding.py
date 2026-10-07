"""Parse GuardDuty findings from EventBridge and Step Functions payloads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class FindingParseError(ValueError):
    """Raised when an event is not a GuardDuty finding."""


@dataclass(frozen=True)
class Finding:
    """Fields the playbooks need from a GuardDuty finding."""

    id: str
    type: str
    severity: float
    account_id: str
    region: str
    title: str
    description: str
    instance_id: str | None
    access_key_id: str | None
    user_name: str | None
    user_type: str | None
    bucket_names: tuple[str, ...]
    raw: dict[str, Any]

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "account_id": self.account_id,
            "region": self.region,
            "title": self.title,
            "description": self.description,
            "instance_id": self.instance_id,
            "access_key_id": self.access_key_id,
            "user_name": self.user_name,
            "user_type": self.user_type,
            "bucket_names": list(self.bucket_names),
        }


def playbook_for(finding_type: str) -> str:
    """Return ec2, iam, s3, or unknown for a GuardDuty finding type."""

    if ":EC2/" in finding_type:
        return "ec2"
    if ":IAMUser/" in finding_type:
        return "iam"
    if ":S3/" in finding_type:
        return "s3"
    return "unknown"


def parse_finding(event: dict[str, Any]) -> Finding:
    """Accept an EventBridge envelope, a Step Functions state, or a bare finding."""

    if not isinstance(event, dict):
        raise FindingParseError("event must be a JSON object")

    payload = event.get("Payload")
    if isinstance(payload, dict) and "detail" not in event and "type" not in event:
        return parse_finding(payload)

    detail = event.get("detail")
    account_id = str(event.get("account") or event.get("accountId") or "")
    region = str(event.get("region") or "")

    if detail is None and event.get("type") and event.get("id"):
        detail = event
        account_id = str(event.get("accountId") or account_id)
        region = str(event.get("region") or region)

    if not isinstance(detail, dict):
        raise FindingParseError("GuardDuty finding detail is missing")

    finding_id = str(detail.get("id") or "").strip()
    finding_type = str(detail.get("type") or "").strip()
    if not finding_id or not finding_type:
        raise FindingParseError("finding id and type are required")

    try:
        severity = float(detail["severity"])
    except (KeyError, TypeError, ValueError) as exc:
        raise FindingParseError("finding severity must be numeric") from exc

    resource = detail.get("resource") if isinstance(detail.get("resource"), dict) else {}
    instance_id = _instance_id(resource)
    access_key_id, user_name, user_type = _access_key(resource)
    return Finding(
        id=finding_id,
        type=finding_type,
        severity=severity,
        account_id=str(detail.get("accountId") or account_id),
        region=str(detail.get("region") or region),
        title=str(detail.get("title") or finding_type),
        description=str(detail.get("description") or ""),
        instance_id=instance_id,
        access_key_id=access_key_id,
        user_name=user_name,
        user_type=user_type,
        bucket_names=_bucket_names(resource),
        raw=detail,
    )


def _instance_id(resource: dict[str, Any]) -> str | None:
    details = resource.get("instanceDetails")
    if isinstance(details, dict):
        return _clean(details.get("instanceId"))
    return None


def _access_key(resource: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    details = resource.get("accessKeyDetails")
    if not isinstance(details, dict):
        return None, None, None
    return (
        _clean(details.get("accessKeyId")),
        _clean(details.get("userName")),
        _clean(details.get("userType")),
    )


def _bucket_names(resource: dict[str, Any]) -> tuple[str, ...]:
    details = resource.get("s3BucketDetails")
    names: list[str] = []
    if isinstance(details, list):
        for item in details:
            if isinstance(item, dict):
                name = _clean(item.get("name"))
                if name and name not in names:
                    names.append(name)
    return tuple(names)


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
