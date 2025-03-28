variable "vpc_id" {
  description = "VPC_ID where to create security group"
  type        = string
}

variable "ami_id" {
  description = "AMI_ID to be used. Null means latest Amazon 2023"
  default     = ""
  type        = string
}

variable "ami_latest_owners" {
  description = "AMI_ID to be used. Null means latest Amazon 2023"
  default     = ["amazon"]
  type        = set(string)
}

variable "ami_latest_names" {
  description = "AMI_ID to be used. Null means latest Amazon 2023"
  default     = ["al2023-ami-2023*x86_64"]
  type        = set(string)
}

variable "subnet_id" {
  description = "Subnet_id to be used"
  type        = string
}

variable "key_name" {
  description = "Key_name to be used"
  default     = null
  type        = string
}

variable "iam_instance_profile" {
  description = "IAM Profile to be used"
  default     = null
  type        = string
}

variable "instance_type" {
  default = "t3a.micro"
  type    = string
}

variable "tags" {
  default = {}
  type    = map(string)
}

variable "use_allocation_id" {
  description = "Use allocation_id provided in allocation_id"
  type        = bool
  default     = true
  nullable    = false
}

variable "allocation_id" {
  description = "EIP public IP association"
  type        = string
  default     = ""
  nullable    = false
}

variable "user_data_template_file_name" {
  type        = string
  default     = "none"
  description = "User data file to use. Default none. Options 'libreswan'"
}

variable "user_data_vars" {
  type        = map(string)
  description = "Map of values to be used by user_data template file"
  default     = {}
  nullable    = false
}

variable "user_data_replace_on_change" {
  type    = bool
  default = true
}

variable "source_dest_check" {
  type    = bool
  default = false
}

variable "associate_public_ip_address" {
  type    = bool
  default = true
}


################################################################################
# Security Group
################################################################################

variable "security_group_ids" {
  description = "Default security group IDs to associate with the VPC endpoints"
  type        = list(string)
  default     = []
}

variable "create_security_group" {
  description = "Determines if a security group is created"
  type        = bool
  default     = false
}

variable "security_group_name" {
  description = "Name to use on security group created. Conflicts with `security_group_name_prefix`"
  type        = string
  default     = null
}

variable "security_group_name_prefix" {
  description = "Name prefix to use on security group created. Conflicts with `security_group_name`"
  type        = string
  default     = null
}

variable "security_group_description" {
  description = "Description of the security group created"
  type        = string
  default     = null
}

variable "security_group_rules" {
  description = "Security group rules to add to the security group created"
  type        = any
  default     = {}
}

variable "security_group_tags" {
  description = "A map of additional tags to add to the security group created"
  type        = map(string)
  default     = {}
}
