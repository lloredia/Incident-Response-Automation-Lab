"""Notification helper and failure-notify playbook."""

from __future__ import annotations

import json
from urllib.error import URLError

import boto3
from botocore.stub import Stubber

from ir_automation.config import Settings
from ir_automation.notify import publish_message, sns_subject
from ir_automation.playbooks.iam import contain_iam
from ir_automation.playbooks.notify import handle_notification
from ir_automation.simulation import build_event


def test_sns_subject_is_ascii_and_bounded() -> None:
    subject = sns_subject("contained", "é" + "x" * 200)

    assert len(subject) == 100
    assert subject.isascii()
    assert subject.startswith("IR contained: ?")


def test_publish_message_uses_botocore_stub() -> None:
    client = boto3.client("sns", region_name="us-east-1")
    message = {"status": "contained"}
    body = json.dumps(message, default=str, indent=2, sort_keys=True)
    with Stubber(client) as stubber:
        stubber.add_response(
            "publish",
            {"MessageId": "mid-123"},
            expected_params={
                "TopicArn": "arn:aws:sns:us-east-1:123456789012:ir-lab",
                "Subject": "IR contained: Recon:EC2/PortProbeUnprotectedPort",
                "Message": body,
            },
        )
        message_id = publish_message(
            client,
            "arn:aws:sns:us-east-1:123456789012:ir-lab",
            "IR contained: Recon:EC2/PortProbeUnprotectedPort",
            message,
        )

    assert message_id == "mid-123"


def test_slack_failure_does_not_fail_containment(aws, sns, monkeypatch) -> None:
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example.test/services/abc")

    def explode(*_args, **_kwargs):
        raise URLError("timed out")

    monkeypatch.setattr("ir_automation.notify.urlopen", explode)
    event = build_event(
        finding_type="UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
        severity=5,
        account_id="123456789012",
        region="us-east-1",
        user_name="root",
        user_type="Root",
        finding_id="finding-slack",
    )
    result = contain_iam(event, Settings.from_env(), aws["iam"], aws["s3"], sns)

    assert result["status"] == "manual_follow_up"
    assert result["notification_id"] == "msg-1"
    assert result["slack_error"] == "slack notification failed"


def test_slack_webhook_is_read_from_ssm(aws, sns, monkeypatch) -> None:
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "")
    monkeypatch.setenv("SLACK_WEBHOOK_SSM_PARAMETER", "/ir-lab/slack-webhook")
    aws["ssm"].put_parameter(
        Name="/ir-lab/slack-webhook",
        Value="https://hooks.example.test/services/from-ssm",
        Type="SecureString",
    )
    captured: dict[str, str] = {}

    class _Response:
        def read(self) -> bytes:
            return b"ok"

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def capture(request, timeout=0):
        del timeout
        captured["url"] = request.full_url
        return _Response()

    monkeypatch.setattr("ir_automation.notify.urlopen", capture)
    event = build_event(
        finding_type="AttackSequence:IAM/CompromisedCredentials",
        severity=9,
        account_id="123456789012",
        region="us-east-1",
        finding_id="finding-unsupported",
    )

    result = handle_notification(event, Settings.from_env(), aws["s3"], sns)

    assert result["status"] == "manual_follow_up"
    assert captured["url"] == "https://hooks.example.test/services/from-ssm"


def test_failure_notification_includes_step_functions_error(aws, sns) -> None:
    event = build_event(
        finding_type="CryptoCurrency:EC2/BitcoinTool.B",
        severity=8,
        account_id="123456789012",
        region="us-east-1",
        instance_id="i-123",
        finding_id="finding-failed",
    )
    event["error"] = {"Error": "States.TaskFailed", "Cause": "boom"}

    result = handle_notification(event, Settings.from_env(), aws["s3"], sns)

    assert result["status"] == "failed"
    assert "boom" in " ".join(result["actions"])
    assert sns.calls
