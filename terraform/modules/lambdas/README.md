# Playbooks

Four Lambda functions share one Python package and use separate IAM roles.

- `ec2_compromise` replaces an instance security group, tags it, and snapshots EBS volumes.
- `iam_compromise` deactivates the named access key and attaches only the pre-created deny-all policy.
- `s3_exfiltration` turns on all four S3 Block Public Access settings. It cannot change the lab buckets.
- `failure_notify` publishes when Step Functions has no matching playbook or a playbook raises.

`containment_mode=notify_only` records the intended action and does not call mutating APIs.
