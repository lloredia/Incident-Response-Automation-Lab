# Step Functions

Routes a GuardDuty finding by type to one playbook. Service exceptions are retried. Application failures are sent to the notify function and the execution is marked failed. Unmatched finding types are notified and the execution succeeds.
