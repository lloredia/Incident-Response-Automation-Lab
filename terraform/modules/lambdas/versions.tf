terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.6"
    }
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.70.0"
    }
  }
}
