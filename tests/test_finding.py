"""Parser tests for GuardDuty event shapes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.conftest import load_fixture

from ir_automation.finding import FindingParseError, parse_finding, playbook_for


def test_parse_eventbridge_envelope() -> None:
    finding = parse_finding(load_fixture("ec2_finding.json"))

    assert finding.id == "finding-ec2"
    assert finding.type == "CryptoCurrency:EC2/BitcoinTool.B!DNS"
    assert finding.severity == 8
    assert finding.account_id == "123456789012"
    assert finding.region == "us-east-1"
    assert finding.instance_id == "i-example123"
    assert playbook_for(finding.type) == "ec2"


def test_parse_bare_detail_and_iam_and_s3_fields() -> None:
    iam = parse_finding(load_fixture("iam_finding.json")["detail"])
    s3 = parse_finding(load_fixture("s3_finding.json"))

    assert iam.access_key_id == "AKIAIOSFODNN7EXAMPLE"
    assert iam.user_name == "compromised"
    assert iam.user_type == "IAMUser"
    assert playbook_for(iam.type) == "iam"
    assert s3.bucket_names == ("customer-data",)
    assert playbook_for(s3.type) == "s3"
    assert playbook_for("AttackSequence:IAM/CompromisedCredentials") == "unknown"


def test_parse_rejects_incomplete_event() -> None:
    with pytest.raises(FindingParseError):
        parse_finding({"source": "aws.guardduty"})


def test_state_machine_definition_is_json() -> None:
    template = Path("terraform/modules/step_functions/definition.asl.json.tftpl").read_text(encoding="utf-8")
    rendered = template
    for name in ("ec2_lambda_arn", "iam_lambda_arn", "s3_lambda_arn", "notify_lambda_arn"):
        rendered = rendered.replace(
            "${" + name + "}",
            "arn:aws:lambda:us-east-1:123456789012:function:test",
        )
    parsed = json.loads(rendered)
    assert parsed["StartAt"] == "RouteByFindingType"
    assert "ContainEc2" in parsed["States"]
    assert "ContainIam" in parsed["States"]
    assert "ContainS3" in parsed["States"]
