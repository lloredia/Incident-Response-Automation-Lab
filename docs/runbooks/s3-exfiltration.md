# Runbook: S3 exfiltration or public bucket

## Trigger

GuardDuty finding types that contain `:S3/`, including exfiltration, anonymous or public bucket policy findings, and S3 discovery from a malicious IP. The EventBridge rule `gd-s3` starts the state machine.

`Policy:S3/BucketBlockPublicAccessDisabled` is low severity. It is automated only when `min_severity` is low enough to include it. `Policy:S3/BucketAnonymousAccessGranted` and `Exfiltration:S3/MaliciousIPCaller` are high.

S3 data-event findings require GuardDuty S3 protection (`enable_s3_data_events`). Bucket-policy findings come from foundational GuardDuty.

## Automated actions

In `enforce` mode the `s3_exfiltration` function, for each bucket on the finding:

1. Refuses the bucket when its name is in `PROTECTED_BUCKETS`. The lab evidence, access-log, and CloudTrail buckets are in that list, and the role also has an explicit deny for those ARNs.
2. Confirms the bucket exists.
3. Sets Block Public Access: block public ACLs, ignore public ACLs, block public policies, and restrict public buckets.
4. Adds IR tags without removing existing tags.
5. Writes evidence and notifies SNS.

`notify_only` stops after the existence check.

## What it will not do

- It does not delete objects, rewrite the bucket policy, or make the bucket private beyond Block Public Access.
- It does not change a bucket in another account.
- A sample finding names a bucket that does not exist. The status is `resource_not_found`.

Block Public Access stops new public grants. An existing public object can remain readable until you remove the public ACL or policy. Do that as a manual eradication step after you confirm the finding.

## Verify

```bash
aws s3api get-public-access-block --bucket customer-data
aws s3api get-bucket-tagging --bucket customer-data
```

All four flags are true. `IR-Status` is `public-access-blocked`.

## Recover a false positive

If the bucket was intentionally public, remove the block and the IR tags after you accept the risk:

```bash
aws s3api delete-public-access-block --bucket customer-data
```

If the bucket must stay private, leave the block in place and remove only the public ACL or bucket policy that GuardDuty reported.
