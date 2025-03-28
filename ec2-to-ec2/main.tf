## VPCS
locals {
  # flow_log_file_format_default  = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status}"
  flow_log_file_format_complete = "$${account-id} $${action} $${az-id} $${bytes} $${dstaddr} $${dstport} $${end} $${flow-direction} $${instance-id} $${interface-id} $${log-status} $${packets} $${pkt-dst-aws-service} $${pkt-dstaddr} $${pkt-src-aws-service} $${pkt-srcaddr} $${protocol} $${region} $${reject-reason} $${srcaddr} $${srcport} $${start} $${sublocation-id} $${sublocation-type} $${subnet-id} $${tcp-flags} $${traffic-path} $${type} $${version} $${vpc-id}"
}

module "vpc-a" {
  source  = "terraform-aws-modules/vpc/aws"
  version = ">= 5.19.0"

  providers = {
    aws = aws.provider_a
  }

  name = "vpc-a"
  cidr = "10.88.0.0/16"

  azs                  = var.azs_a
  private_subnets      = ["10.88.1.0/24", "10.88.2.0/24", "10.88.3.0/24", "10.88.4.0/24"]
  private_subnet_names = ["subnet-vpca-apps-private-a", "subnet-vpca-apps-private-b", "subnet-vpca-endpoints-private-a", "subnet-vpca-endpoints-private-b"]
  public_subnets       = ["10.88.100.0/24", "10.88.101.0/24"]
  public_subnet_names  = ["subnet-vpca-apps-pub-a", "subnet-vpca-apps-pub-b"]

  create_igw = true
  igw_tags   = { Name = "igw-a" }

  enable_nat_gateway                   = false
  one_nat_gateway_per_az               = true
  create_database_nat_gateway_route    = true
  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true
  flow_log_file_format                 = local.flow_log_file_format_complete
}

module "vpc-b" {
  source  = "terraform-aws-modules/vpc/aws"
  version = ">= 5.19.0"

  providers = {
    aws = aws.provider_b
  }

  name = "vpc-b"
  cidr = "10.2.0.0/16"

  azs                  = var.azs_b
  private_subnets      = ["10.2.1.0/24", "10.2.2.0/24", "10.2.3.0/24", "10.2.4.0/24"]
  private_subnet_names = ["subnet-vpca-apps-private-a", "subnet-vpca-apps-private-b", "subnet-vpca-endpoints-private-a", "subnet-vpca-endpoints-private-b"]
  public_subnets       = ["10.2.100.0/24", "10.2.101.0/24"]
  public_subnet_names  = ["subnet-vpca-apps-pub-a", "subnet-vpca-apps-pub-b"]

  create_igw = true
  igw_tags   = { Name = "igw-b" }

  enable_nat_gateway                   = false
  one_nat_gateway_per_az               = true
  create_database_nat_gateway_route    = true
  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true
  flow_log_file_format                 = local.flow_log_file_format_complete
}

## Endpoints
locals {
  endpoint_base_a = {
    service             = "to_be_overwritten"
    service_type        = "Interface"
    private_dns_enabled = true
    subnet_ids          = [module.vpc-a.private_subnets[2], module.vpc-a.private_subnets[3]]
  }
  endpoint_base_b = {
    service             = "to_be_overwritten"
    service_type        = "Interface"
    private_dns_enabled = true
    subnet_ids          = [module.vpc-b.private_subnets[2], module.vpc-b.private_subnets[3]]
  }
  secret = random_string.secret.result
}

resource "random_string" "secret" {
  length           = 32
  special          = true
  override_special = "."
}

## VPC Endpoints
module "vpc-a-endpoints" {
  source  = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
  version = ">= 5.19.0"

  providers = {
    aws = aws.provider_a
  }
  vpc_id = module.vpc-a.vpc_id

  create_security_group      = true
  security_group_name        = "security-group-for-vpc-endpoints-a"
  security_group_description = "VPC endpoint security group"
  security_group_rules = {
    ingress_https = {
      description = "HTTPS from VPC-A"
      cidr_blocks = [module.vpc-a.vpc_cidr_block]
    }
    ingressB_https = {
      description = "HTTPS from VPC-B"
      cidr_blocks = [module.vpc-b.vpc_cidr_block]
    }
  }

  endpoints = {
    ec2         = merge(local.endpoint_base_a, { service = "ec2" })
    ec2messages = merge(local.endpoint_base_a, { service = "ec2messages" })
    ssm         = merge(local.endpoint_base_a, { service = "ssm" })
    ssmmessages = merge(local.endpoint_base_a, { service = "ssmmessages" })
    kms         = merge(local.endpoint_base_a, { service = "kms" }) # Necessary if your Session Manager is configured with encryption
    # Necessary if your Session Manager is configured with logs to s3
    s3 = {
      service             = "s3"
      service_type        = "Gateway"
      route_table_ids     = setunion(module.vpc-a.private_route_table_ids, module.vpc-a.public_route_table_ids)
      private_dns_enabled = true
    }
  }
}



module "vpc-b-endpoints" {
  source  = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
  version = ">= 5.19.0"

  providers = {
    aws = aws.provider_b
  }
  vpc_id = module.vpc-b.vpc_id

  create_security_group      = true
  security_group_name        = "security-group-for-vpc-endpoints-b"
  security_group_description = "VPC endpoint security group"
  security_group_rules = {
    ingress_https = {
      description = "HTTPS from VPC-A"
      cidr_blocks = [module.vpc-a.vpc_cidr_block]
    }
    ingressB_https = {
      description = "HTTPS from VPC-B"
      cidr_blocks = [module.vpc-b.vpc_cidr_block]
    }
  }

  endpoints = {
    ec2         = merge(local.endpoint_base_b, { service = "ec2" })
    ec2messages = merge(local.endpoint_base_b, { service = "ec2messages" })
    ssm         = merge(local.endpoint_base_b, { service = "ssm" })
    ssmmessages = merge(local.endpoint_base_b, { service = "ssmmessages" })
    kms         = merge(local.endpoint_base_b, { service = "kms" }) # Necessary if your Session Manager is configured with encryption
    # Necessary if your Session Manager is configured with logs to s3
    s3 = {
      service             = "s3"
      service_type        = "Gateway"
      route_table_ids     = setunion(module.vpc-b.private_route_table_ids, module.vpc-b.public_route_table_ids)
      private_dns_enabled = true
    }
  }
}


## EC2

resource "aws_eip" "vpc-a-public" {
  provider = aws.provider_a
  tags = {
    Name = "vpc-a-public"
  }
}

resource "aws_eip" "vpc-b-public" {
  provider = aws.provider_b
  tags = {
    Name = "vpc-b-public"
  }
}

module "ec2-vpn-a" {
  source = "../modules/ec2"
  providers = {
    aws = aws.provider_a
  }
  vpc_id               = module.vpc-a.vpc_id
  subnet_id            = module.vpc-a.public_subnets[0]
  iam_instance_profile = var.iam_instance_profile
  tags = {
    Name = "vpn-a"
  }
  user_data_template_file_name = "libreswan"
  user_data_vars = {
    LEFT         = "%defaultroute"
    LEFT_ID      = aws_eip.vpc-a-public.public_ip
    LEFT_SUBNET  = module.vpc-a.vpc_cidr_block
    RIGHT        = aws_eip.vpc-b-public.public_ip
    RIGHT_ID     = aws_eip.vpc-b-public.public_ip
    RIGHT_SUBNET = module.vpc-b.vpc_cidr_block
    SECRET       = local.secret
    ENABLE_LOG   = "false"
  }
  use_allocation_id           = true
  allocation_id               = aws_eip.vpc-a-public.id
  associate_public_ip_address = true
  source_dest_check           = false
  user_data_replace_on_change = true
  create_security_group       = true
  security_group_name         = "this"
  security_group_description  = "this"
  security_group_rules = {
    egress_all = {
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
      type             = "egress"
    }
    ingress_udp_500 = {
      from_port   = 500
      to_port     = 500
      protocol    = "udp"
      cidr_blocks = ["${aws_eip.vpc-b-public.public_ip}/32"]
      type        = "ingress"
    }
    ingress_udp_4500 = {
      from_port   = 4500
      to_port     = 4500
      protocol    = "udp"
      cidr_blocks = ["${aws_eip.vpc-b-public.public_ip}/32"]
      type        = "ingress"
    }
    ingress_icmp = {
      from_port   = -1
      to_port     = -1
      protocol    = "icmp"
      cidr_blocks = [module.vpc-a.vpc_cidr_block, module.vpc-b.vpc_cidr_block]
      type        = "ingress"
    }
    ingress_routing_https = {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [module.vpc-a.vpc_cidr_block, module.vpc-b.vpc_cidr_block]
      type        = "ingress"
    }
  }
}


module "ec2-vpn-b" {
  source = "../modules/ec2"
  providers = {
    aws = aws.provider_b
  }
  vpc_id               = module.vpc-b.vpc_id
  subnet_id            = module.vpc-b.public_subnets[0]
  iam_instance_profile = var.iam_instance_profile
  tags = {
    Name = "vpn-a"
  }
  user_data_template_file_name = "libreswan"
  user_data_vars = {
    LEFT         = aws_eip.vpc-a-public.public_ip
    LEFT_ID      = aws_eip.vpc-a-public.public_ip
    LEFT_SUBNET  = module.vpc-a.vpc_cidr_block
    RIGHT        = "%defaultroute"
    RIGHT_ID     = aws_eip.vpc-b-public.public_ip
    RIGHT_SUBNET = module.vpc-b.vpc_cidr_block
    SECRET       = local.secret
    ENABLE_LOG   = "false"
  }
  use_allocation_id           = true
  allocation_id               = aws_eip.vpc-b-public.id
  associate_public_ip_address = true
  source_dest_check           = false
  user_data_replace_on_change = true
  create_security_group       = true
  security_group_name         = "this"
  security_group_description  = "this"
  security_group_rules = {
    egress_all = {
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
      type             = "egress"
    }
    ingress_udp_500 = {
      from_port   = 500
      to_port     = 500
      protocol    = "udp"
      cidr_blocks = ["${aws_eip.vpc-a-public.public_ip}/32"]
      type        = "ingress"
    }
    ingress_udp_4500 = {
      from_port   = 4500
      to_port     = 4500
      protocol    = "udp"
      cidr_blocks = ["${aws_eip.vpc-a-public.public_ip}/32"]
      type        = "ingress"
    }
    ingress_icmp = {
      from_port   = -1
      to_port     = -1
      protocol    = "icmp"
      cidr_blocks = [module.vpc-a.vpc_cidr_block, module.vpc-b.vpc_cidr_block]
      type        = "ingress"
    }
    ingress_routing_https = {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [module.vpc-a.vpc_cidr_block, module.vpc-b.vpc_cidr_block]
      type        = "ingress"
    }
  }
}


module "ec2-private-a" {
  source = "../modules/ec2"
  providers = {
    aws = aws.provider_a
  }
  vpc_id               = module.vpc-a.vpc_id
  subnet_id            = module.vpc-a.private_subnets[0]
  iam_instance_profile = var.iam_instance_profile
  tags = {
    Name = "private-a"
  }
  user_data_template_file_name = "none"
  user_data_vars               = {}
  use_allocation_id            = false
  associate_public_ip_address  = false
  source_dest_check            = true
  user_data_replace_on_change  = true
  create_security_group        = true
  security_group_name          = "private-a"
  security_group_description   = "private-a"
  security_group_rules = {
    egress_all = {
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
      type             = "egress"
    }
    ingress_icmp = {
      from_port   = -1
      to_port     = -1
      protocol    = "icmp"
      cidr_blocks = [module.vpc-a.vpc_cidr_block, module.vpc-b.vpc_cidr_block]
      type        = "ingress"
    }
  }
}

module "ec2-private-b" {
  source = "../modules/ec2"
  providers = {
    aws = aws.provider_b
  }
  vpc_id               = module.vpc-b.vpc_id
  subnet_id            = module.vpc-b.private_subnets[0]
  iam_instance_profile = var.iam_instance_profile
  tags = {
    Name = "private-b"
  }
  user_data_template_file_name = "none"
  user_data_vars               = {}
  use_allocation_id            = false
  associate_public_ip_address  = false
  source_dest_check            = true
  user_data_replace_on_change  = true
  create_security_group        = true
  security_group_name          = "private-b"
  security_group_description   = "private-b"
  security_group_rules = {
    egress_all = {
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
      type             = "egress"
    }
    ingress_icmp = {
      from_port   = -1
      to_port     = -1
      protocol    = "icmp"
      cidr_blocks = [module.vpc-a.vpc_cidr_block, module.vpc-b.vpc_cidr_block]
      type        = "ingress"
    }
  }
}



## VPC Routes

resource "aws_route" "vpn-a-private" {
  provider               = aws.provider_a
  count                  = length(module.vpc-a.private_route_table_ids)
  route_table_id         = module.vpc-a.private_route_table_ids[count.index]
  network_interface_id   = module.ec2-vpn-a.network_id
  destination_cidr_block = module.vpc-b.vpc_cidr_block
}

resource "aws_route" "vpn-a-public" {
  provider               = aws.provider_a
  count                  = length(module.vpc-a.public_route_table_ids)
  route_table_id         = module.vpc-a.public_route_table_ids[count.index]
  network_interface_id   = module.ec2-vpn-a.network_id
  destination_cidr_block = module.vpc-b.vpc_cidr_block
}

resource "aws_route" "vpn-b-private" {
  provider               = aws.provider_b
  count                  = length(module.vpc-b.private_route_table_ids)
  route_table_id         = module.vpc-b.private_route_table_ids[count.index]
  network_interface_id   = module.ec2-vpn-b.network_id
  destination_cidr_block = module.vpc-a.vpc_cidr_block
}

resource "aws_route" "vpn-b-public" {
  provider               = aws.provider_b
  count                  = length(module.vpc-b.public_route_table_ids)
  route_table_id         = module.vpc-b.public_route_table_ids[count.index]
  network_interface_id   = module.ec2-vpn-b.network_id
  destination_cidr_block = module.vpc-a.vpc_cidr_block
}
