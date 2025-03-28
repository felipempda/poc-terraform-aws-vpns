output "vpc-a" {
  value       = module.vpc-a.vpc_id
  description = "VPC-A Id"
}

output "vpc-b" {
  value       = module.vpc-b.vpc_id
  description = "VPC-B Id"
}


output "vpn-a" {
  description = "VPN on VPC-A"
  value       = aws_vpn_connection.this.arn
}

output "ec2-private-a" {
  description = "EC2 on VPC-A private subnet"
  value       = module.ec2-private-a
}

output "ec2-private-b" {
  description = "EC2 on VPC-B private subnet"
  value       = module.ec2-private-b
}

output "ec2-vpn-b" {
  description = "EC2 on VPC-B public subnet"
  value       = module.ec2-vpn-b
}

output "endpoints-a" {
  description = "Endpoints on VPC-A"
  value       = local.endpoints_a_dns
}

output "region-a" {
  description = "Region A"
  value       = var.region_a
}

output "endpoints-b" {
  description = "Endpoints on VPC-B"
  value       = local.endpoints_b_dns
}

output "region-b" {
  description = "Region B"
  value       = var.region_b
}

locals {
  endpoints_a_dns = {
    for endpoint, endpoint_value in module.vpc-a-endpoints.endpoints :
    endpoint => {
      "dns_name" : length(module.vpc-a-endpoints.endpoints[endpoint].dns_entry) > 0 ? module.vpc-a-endpoints.endpoints[endpoint].dns_entry[0].dns_name : ""
      "ipv4s" : length(module.vpc-a-endpoints.endpoints[endpoint].subnet_configuration) > 0 ? [for ip in module.vpc-a-endpoints.endpoints[endpoint].subnet_configuration : lookup(ip, "ipv4", "")] : []

    }
  }
  endpoints_b_dns = {
    for endpoint, endpoint_value in module.vpc-b-endpoints.endpoints :
    endpoint => {
      "dns_name" : length(module.vpc-b-endpoints.endpoints[endpoint].dns_entry) > 0 ? module.vpc-b-endpoints.endpoints[endpoint].dns_entry[0].dns_name : ""
      "ipv4s" : length(module.vpc-b-endpoints.endpoints[endpoint].subnet_configuration) > 0 ? [for ip in module.vpc-b-endpoints.endpoints[endpoint].subnet_configuration : lookup(ip, "ipv4", "")] : []
    }
  }
}


output "test-endpoints-b-0-dns" {
  description = "Test A-B communication - 1-check IPs"
  value       = "nslookup ${local.endpoints_b_dns["ec2"].dns_name}"
}

output "test-endpoints-a-0-dns" {
  description = "Test B-A communication - 1-check IPs"
  value       = "nslookup ${local.endpoints_a_dns["ec2"].dns_name}"
}

output "test-endpoints-b-1-connect" {
  description = "Test A-B communication - 2-from A use B endpoint"
  value       = "aws ec2 describe-vpcs --query 'Vpcs[].CidrBlock' --region ${var.region_b} --endpoint-url https://${local.endpoints_b_dns["ec2"].dns_name}"
}

output "test-endpoints-a-1-connect" {
  description = "Test B-A communication - 2-from B use A endpoint"
  value       = "aws ec2 describe-vpcs --query 'Vpcs[].CidrBlock' --region ${var.region_a} --endpoint-url https://${local.endpoints_a_dns["ec2"].dns_name}"
}
