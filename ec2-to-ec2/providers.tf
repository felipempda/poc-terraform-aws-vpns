provider "aws" {
  region = var.region_a
  alias  = "provider_a"

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  region = var.region_b
  alias  = "provider_b"

  default_tags {
    tags = var.tags
  }
}

terraform {
  required_version = ">= 1.1"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.7.1"
    }
  }
}
