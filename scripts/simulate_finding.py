#!/usr/bin/env python3
"""Print or submit a synthetic GuardDuty finding.

The default mode prints JSON and changes nothing. ``--execute`` starts the
deployed state machine against a resource you name. Use it only in a sandbox.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lambdas" / "src"))

from ir_automation.simulation import PLAYBOOK_FINDING_TYPES, build_event  # noqa: E402


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--playbook", required=True, choices=sorted(PLAYBOOK_FINDING_TYPES))
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--account-id", default="123456789012")
    parser.add_argument("--severity", type=float, default=8)
    parser.add_argument("--instance-id")
    parser.add_argument("--user-name")
    parser.add_argument("--access-key-id")
    parser.add_argument("--bucket", action="append", dest="buckets")
    parser.add_argument("--state-machine-arn")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Start a Step Functions execution. Requires AWS credentials.",
    )
    args = parser.parse_args(argv)
    if args.playbook == "ec2" and not args.instance_id:
        parser.error("--instance-id is required for the ec2 playbook")
    if args.playbook == "iam" and not args.user_name:
        parser.error("--user-name is required for the iam playbook")
    if args.playbook == "s3" and not args.buckets:
        parser.error("at least one --bucket is required for the s3 playbook")
    if args.execute and not args.state_machine_arn:
        parser.error("--state-machine-arn is required with --execute")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    event = build_event(
        finding_type=PLAYBOOK_FINDING_TYPES[args.playbook],
        severity=args.severity,
        account_id=args.account_id,
        region=args.region,
        instance_id=args.instance_id,
        user_name=args.user_name,
        access_key_id=args.access_key_id,
        bucket_names=args.buckets,
    )
    if not args.execute:
        json.dump(event, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    if args.playbook == "ec2":
        ec2 = boto3.client("ec2", region_name=args.region)
        try:
            described = ec2.describe_instances(InstanceIds=[args.instance_id])
        except ClientError as exc:
            print(f"Refusing to execute: {exc.response['Error']['Code']}", file=sys.stderr)
            return 2
        reservations = described.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            print(f"Refusing to execute: {args.instance_id} was not found in {args.region}.", file=sys.stderr)
            return 2

    execution_name = f"sim-{event['detail']['id']}"[:80]
    response = boto3.client("stepfunctions", region_name=args.region).start_execution(
        stateMachineArn=args.state_machine_arn,
        name=execution_name,
        input=json.dumps(event),
    )
    print(response["executionArn"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
