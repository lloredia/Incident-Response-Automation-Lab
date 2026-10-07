# Forensics VPC

Isolated VPC with no internet gateway. The analysis subnet uses a custom network ACL that has no allow rules, so traffic is denied until an analyst adds a rule. The default security group is empty, flow logs are enabled, and nothing in this module launches an instance.
