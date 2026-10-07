#!/usr/bin/env bash
# Ask GuardDuty for sample findings. Samples use placeholder resource IDs.
# They exercise EventBridge, Step Functions, evidence, and notifications.
# They do not attack, scan, or modify a real workload.
set -euo pipefail

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
DETECTOR_ID="${1:-}"

if ! command -v aws >/dev/null 2>&1; then
  echo "The AWS CLI is required." >&2
  exit 1
fi

if [[ -z "${DETECTOR_ID}" ]]; then
  DETECTOR_ID="$(aws guardduty list-detectors --region "${REGION}" --query 'DetectorIds[0]' --output text)"
fi

if [[ -z "${DETECTOR_ID}" || "${DETECTOR_ID}" == "None" ]]; then
  echo "No GuardDuty detector found in ${REGION}. Apply the Terraform stack first." >&2
  exit 1
fi

aws guardduty create-sample-findings \
  --region "${REGION}" \
  --detector-id "${DETECTOR_ID}" \
  --finding-types \
    "CryptoCurrency:EC2/BitcoinTool.B!DNS" \
    "Recon:EC2/PortProbeUnprotectedPort" \
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom" \
    "Exfiltration:S3/MaliciousIPCaller" \
    "Policy:S3/BucketAnonymousAccessGranted"

echo "Sample findings requested on detector ${DETECTOR_ID} in ${REGION}."
echo "Expect playbook status resource_not_found. Sample instance, user, and bucket IDs are fictitious."
echo "Confirm the Step Functions execution, the SNS message, and a new object under evidence/ in the evidence bucket."
