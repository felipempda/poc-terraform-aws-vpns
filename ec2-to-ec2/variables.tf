variable "iam_instance_profile" {
  default     = "AWSAccelerator-SessionManagerEc2Role"
  description = "EC2 IAM instance profile"
  type        = string
}

variable "region_a" {
  default = "ca-central-1"
  type    = string
}

variable "region_b" {
  default = "us-east-1"
  type    = string
}

variable "azs_a" {
  default = ["ca-central-1a", "ca-central-1b"]
  type    = list(string)
}

variable "azs_b" {
  default = ["us-east-1a", "us-east-1b"]
  type    = list(string)
}

variable "tags" {
  description = "Tags to be used on all resources"
  type        = map(string)
  default = {
    CreatedBy = "Terraform"
    Project   = "POC-VPN"
  }
}
