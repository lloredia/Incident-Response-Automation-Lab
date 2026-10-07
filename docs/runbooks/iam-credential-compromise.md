# Runbook: compromised IAM credentials

## Trigger

GuardDuty finding types that contain `:IAMUser/`, including malicious IP calls, pen-test distributions, CloudTrail tampering, and instance-credential exfiltration. The EventBridge rule `gd-iam` applies the same severity threshold as the other rules.

## Automated actions

In `enforce` mode the `iam_compromise` function:

1. Deactivates the access key named on the finding. The key is not deleted, so it can be restored.
2. Attaches the pre-created deny-all policy to that IAM user. The function cannot attach any other policy. The role does not include `DetachUserPolicy`.
3. Writes evidence and notifies SNS.

An explicit deny on the user is evaluated immediately, including for sessions that were minted from that user.

## What it will not do

- Root findings are `manual_follow_up`. IAM cannot deny the root user. Rotate the root password and access keys by hand.
- `AssumedRole`, federated, and account principals are not modified. If the finding also has an instance ID, the evidence says to run the EC2 playbook for that instance. Instance-role credentials are not access keys.
- A sample finding names a user that does not exist. The status is `resource_not_found` and nothing in IAM changes.
- The function does not delete the user, its inline policies, or its other access keys.

## Verify

```bash
aws iam list-access-keys --user-name compromised
aws iam list-attached-user-policies --user-name compromised
```

The key status is `Inactive`. The attached policy name ends in `deny-all`.

## Recover a false positive

```bash
aws iam detach-user-policy \
  --user-name compromised \
  --policy-arn arn:aws:iam::123456789012:policy/ir-lab-deny-all

aws iam update-access-key \
  --user-name compromised \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Active
```

Reactivate the key only after you know it was not stolen. Prefer creating a new key and deleting the exposed one.

## Follow-up for instance credentials

`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` often means an instance role was used outside AWS. Deactivating an IAM user does not revoke that role. Quarantine the instance with the EC2 playbook, then investigate the role's recent CloudTrail events.
