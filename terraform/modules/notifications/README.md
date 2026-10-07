# Notifications

KMS-encrypted SNS topic for responder alerts, an optional email subscription, an optional Slack webhook in SSM Parameter Store, and a KMS-encrypted SQS dead-letter queue. A CloudWatch alarm publishes when the queue is not empty.
