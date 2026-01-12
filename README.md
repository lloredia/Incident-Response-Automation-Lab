# Incident-Response-Automation-Lab
Create an incident response scenario using AWS GuardDuty or similar detection tools. When threats are detected, trigger Lambda functions that automatically isolate compromised instances, snapshot volumes for forensics, and send notifications. Use Step Functions to orchestrate the response workflow.
Project 5: Incident Response Automation Lab
Phase 1: Detection Setup

Enable AWS GuardDuty in your account (monitors VPC flow logs, CloudTrail, DNS logs)
Alternatively, use AWS Security Hub for centralized findings
Create test scenarios: spin up an EC2 instance and simulate suspicious activity (port scanning, cryptocurrency mining indicators, unusual API calls)

Phase 2: Automated Response Workflow

Set up EventBridge rules to capture GuardDuty findings
Create Lambda functions for different response actions:

Isolate function: Modify security group to block all traffic except SSH from your IP
Snapshot function: Create EBS snapshot for forensic analysis
Notification function: Send detailed alerts via SNS/Slack
Tagging function: Apply "quarantined" tag for tracking


Use Step Functions to orchestrate: Detection → Assessment → Isolation → Snapshot → Notify
