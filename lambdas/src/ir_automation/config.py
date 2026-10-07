"""Runtime settings supplied by Terraform as Lambda environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass

CONTAINMENT_MODES = ("enforce", "notify_only")


@dataclass(frozen=True)
class Settings:
    """Playbook configuration. Empty strings mean the integration is disabled."""

    evidence_bucket: str
    evidence_kms_key_id: str
    sns_topic_arn: str
    containment_mode: str
    min_severity: float
    project_name: str
    quarantine_ssh_cidr: str
    deny_all_policy_arn: str
    slack_webhook_url: str
    slack_webhook_ssm_parameter: str
    protected_buckets: frozenset[str]
    allowed_account_id: str
    aws_region: str

    @classmethod
    def from_env(cls) -> Settings:
        mode = os.environ.get("CONTAINMENT_MODE", "enforce").strip().lower()
        if mode not in CONTAINMENT_MODES:
            allowed = ", ".join(CONTAINMENT_MODES)
            raise ValueError(f"CONTAINMENT_MODE must be one of: {allowed}")

        protected = {
            name.strip().lower() for name in os.environ.get("PROTECTED_BUCKETS", "").split(",") if name.strip()
        }
        return cls(
            evidence_bucket=os.environ.get("EVIDENCE_BUCKET", "").strip(),
            evidence_kms_key_id=os.environ.get("EVIDENCE_KMS_KEY_ID", "").strip(),
            sns_topic_arn=os.environ.get("SNS_TOPIC_ARN", "").strip(),
            containment_mode=mode,
            min_severity=float(os.environ.get("MIN_SEVERITY", "1")),
            project_name=os.environ.get("PROJECT_NAME", "ir-lab").strip() or "ir-lab",
            quarantine_ssh_cidr=os.environ.get("QUARANTINE_SSH_CIDR", "").strip(),
            deny_all_policy_arn=os.environ.get("DENY_ALL_POLICY_ARN", "").strip(),
            slack_webhook_url=os.environ.get("SLACK_WEBHOOK_URL", "").strip(),
            slack_webhook_ssm_parameter=os.environ.get("SLACK_WEBHOOK_SSM_PARAMETER", "").strip(),
            protected_buckets=frozenset(protected),
            allowed_account_id=os.environ.get("ALLOWED_ACCOUNT_ID", "").strip(),
            aws_region=os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")),
        )
