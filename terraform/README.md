# Terraform

The root module wires GuardDuty, EventBridge, Step Functions, the playbook Lambdas, SNS, and the audit buckets.

Remote state is documented and commented in `backend.tf`. Copy `terraform.tfvars.example` to `terraform.tfvars` before apply. That file is gitignored.

```bash
terraform init
terraform plan
terraform apply
terraform destroy
```

See the repository README for the lab walkthrough, cost, and the warning that apply creates real resources.
