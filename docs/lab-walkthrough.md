# Lab walkthrough

Use a sandbox account. Apply creates a GuardDuty detector, a CloudTrail trail, a KMS key, and Lambda functions that can change security groups, IAM users, and S3 public-access settings.

## 1. Prerequisites

- Terraform 1.6 or newer
- AWS CLI v2, authenticated to the sandbox account
- Python 3.12 if you want to run the unit tests or `scripts/simulate_finding.py`
- An email address you can confirm

## 2. Configure

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

- Set `notification_email`.
- Leave `min_severity = 1` for the first run so low-severity samples match.
- Leave `containment_mode = "enforce"` to perform containment, or set `notify_only` for a rehearsal that only records the intended action.
- Set `quarantine_ssh_cidr` only if an analyst must SSH to a quarantined instance. Empty means no ingress and no egress.
- If GuardDuty is already enabled in the region, set `create_guardduty_detector = false` and `existing_detector_id`.
- If you do not want a second CloudTrail trail, set `enable_cloudtrail = false`.

Do not commit `terraform.tfvars`.

## 3. Deploy

```bash
terraform init
terraform plan
terraform apply
```

Copy the outputs. Confirm the SNS email subscription from your inbox before expecting alerts.

## 4. Generate sample findings

From the repository root, with the same credentials and region:

```bash
AWS_REGION=us-east-1 ./scripts/generate_sample_findings.sh
```

GuardDuty sample findings use placeholder resource IDs. Within a few minutes you should see:

1. One Step Functions execution per matching finding. Low-severity samples are included only when `min_severity` is 1.
2. Playbook status `resource_not_found`, because the sample instance, user, and bucket do not exist.
3. An SNS email for each finding that was not skipped for severity.
4. A JSON object under `evidence/` in the evidence bucket.

This path does not isolate a real instance or disable a real key.

## 5. Optional controlled exercise

Launch a disposable instance in the lab region, for example a `t3.micro` with no important data. Then run the playbook against that instance only:

```bash
python scripts/simulate_finding.py \
  --playbook ec2 \
  --region us-east-1 \
  --account-id "$(aws sts get-caller-identity --query Account --output text)" \
  --instance-id i-0123456789abcdef0 \
  --state-machine-arn "$(terraform -chdir=terraform output -raw state_machine_arn)" \
  --execute
```

`--execute` describes the instance first and refuses to start if it does not exist. After the execution succeeds:

- The instance has one security group, named `<project>-quarantine-<vpc-id>`, with no egress.
- The instance tags include `IR-Status=quarantined` and `IR-OriginalSecurityGroups`.
- Each attached EBS volume has a snapshot tagged `IR-Purpose=forensics`.
- The evidence object lists the snapshot IDs and the original security group.

Stop or terminate the instance when you are done. Restore the original security group from the evidence object before you rely on the instance again. The EC2 runbook has the commands.

The same script can target an IAM user or a bucket you created for the exercise. Read the IAM and S3 runbooks before you do that. Deactivating a key and attaching the deny-all policy takes effect immediately.

## 6. Raise the severity filter

Set `min_severity = 4` and apply again. `Recon:EC2/PortProbeUnprotectedPort` is low and will no longer start a workflow. `CryptoCurrency:EC2/BitcoinTool.B!DNS` and `Policy:S3/BucketAnonymousAccessGranted` are high and still will.

## 7. Tear down

```bash
terraform -chdir=terraform destroy
```

The KMS key stays pending deletion for 7 days. Empty the evidence bucket first if `force_destroy` was turned off. Terminate any instance you launched for the exercise.
