# EventBridge

Three rules match GuardDuty findings by type prefix and severity, then start the incident-response state machine. Each target retries twice and sends failures to the dead-letter queue. The state machine, not the rule, chooses the playbook, so a mis-filed prefix still follows the finding type.
