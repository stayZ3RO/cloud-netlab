terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state, the next step past local state. Stub kept visible on purpose:
  # create the bucket + lock table, then uncomment to use S3-backed locked state.
  #
  # backend "s3" {
  #   bucket         = "stayz3ro-aws-net-lab-tfstate"
  #   key            = "dev/network.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "stayz3ro-aws-net-lab-locks"
  #   encrypt        = true
  # }
}
