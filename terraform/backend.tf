# Remote state is commented so the first lab deploy can use local state.
# Create the bucket and lock table first, then uncomment this block and run:
#   terraform init -migrate-state
#
# terraform {
#   backend "s3" {
#     bucket         = "REPLACE_ME-tfstate"
#     key            = "incident-response-lab/terraform.tfstate"
#     region         = "us-east-1"
#     dynamodb_table = "REPLACE_ME-tfstate-lock"
#     encrypt        = true
#     kms_key_id     = "arn:aws:kms:us-east-1:ACCOUNT_ID:key/KEY_ID"
#   }
# }
