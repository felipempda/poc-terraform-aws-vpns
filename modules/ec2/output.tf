# output "ec2" {
#   value = aws_instance.this
# }

output "ec2_instance_id" {
  value       = aws_instance.this.id
  description = "Instance id"
}

output "connect_to_ec2_command" {
  value       = "aws ssm start-session --target ${aws_instance.this.id} --region ${data.aws_region.this.name}"
  description = "AWS cli command to connect via Session Manager"
}

output "network_id" {
  value       = aws_instance.this.primary_network_interface_id
  description = "Primary Network ID"
}

output "public_ip" {
  value       = var.use_allocation_id ? data.aws_eip.this[0].public_ip : aws_instance.this.public_ip
  description = "Public IP (optional)"
}

output "private_ip" {
  value       = aws_instance.this.private_ip
  description = "Private IP"
}
