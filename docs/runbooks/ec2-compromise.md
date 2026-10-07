# Runbook: compromised EC2 instance

## Trigger

GuardDuty finding types that contain `:EC2/`, including cryptocurrency, port probe, brute force, backdoor, and trojan findings. The EventBridge rule `gd-ec2` starts the state machine when the severity is at or above `min_severity`.

## Automated actions

In `enforce` mode the `ec2_compromise` function:

1. Describes the instance in the stack's region.
2. Creates or reuses a security group named `<project>-quarantine-<vpc-id>` in that VPC.
3. Removes the default allow-all egress rule. If `quarantine_ssh_cidr` is set, it allows TCP 22 from that CIDR only.
4. Replaces the instance security groups with the quarantine group.
5. Tags the instance `IR-Status=quarantined`, `IR-Managed=true`, and preserves `IR-OriginalSecurityGroups` on later runs.
6. Creates one EBS snapshot per attached volume for that finding ID. A replay of the same finding does not create another snapshot.
7. Writes evidence and publishes to SNS. Slack is included when a webhook parameter is configured.

`notify_only` describes the instance and records the same steps without changing it.

## What it will not do

- It does not terminate the instance, rotate credentials, or move the instance to the forensics VPC.
- It does not act on a finding whose region differs from the stack.
- A missing or sample instance produces `resource_not_found` and an alert. No security group is created for an ID that does not exist.
- Instance-store volumes cannot be snapshotted.

## Verify

```bash
aws ec2 describe-instances --instance-ids i-0123456789abcdef0 \
  --query 'Reservations[].Instances[].{Groups:SecurityGroups,Tags:Tags}'
aws ec2 describe-snapshots --owner-ids self \
  --filters Name=tag:IR-FindingId,Values=FINDING_ID
```

Read the matching object in the evidence bucket. The Step Functions execution status is `Succeeded` when the function returns, including `resource_not_found`.

## Recover a false positive

Use the security group IDs in `IR-OriginalSecurityGroups` or in the evidence object.

```bash
aws ec2 modify-instance-attribute \
  --instance-id i-0123456789abcdef0 \
  --groups sg-original
```

Remove the incident tags when the instance is back in service. Delete forensic snapshots only after the investigation is closed.

## Forensics

Create a volume from the snapshot in the forensics VPC subnet. The subnet network ACL has no allow rules, so add a temporary rule before you connect an analysis instance, and remove it afterward. The forensics security group starts with no rules for the same reason.
