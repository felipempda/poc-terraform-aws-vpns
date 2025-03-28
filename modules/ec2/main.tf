
data "aws_ami" "latest" {
  most_recent = true
  owners      = var.ami_latest_owners

  filter {
    name   = "name"
    values = var.ami_latest_names
  }
}

data "aws_region" "this" {
}


resource "aws_instance" "this" {
  ami                         = coalesce(var.ami_id, data.aws_ami.latest.id)
  instance_type               = var.instance_type
  associate_public_ip_address = var.associate_public_ip_address
  source_dest_check           = var.source_dest_check
  subnet_id                   = var.subnet_id
  key_name                    = var.key_name
  vpc_security_group_ids      = var.create_security_group ? concat(var.security_group_ids, [aws_security_group.this[0].id]) : var.security_group_ids
  iam_instance_profile        = var.iam_instance_profile
  tags                        = var.tags
  user_data                   = templatefile("${path.module}/files/${var.user_data_template_file_name}.tfpl", var.user_data_vars)
  user_data_replace_on_change = var.user_data_replace_on_change
}

data "aws_eip" "this" {
  count = var.use_allocation_id ? 1 : 0
  id    = var.allocation_id
}


resource "aws_eip_association" "this" {
  count         = var.use_allocation_id ? 1 : 0
  allocation_id = data.aws_eip.this[0].id
  instance_id   = aws_instance.this.id
}


resource "aws_security_group" "this" {
  count = var.create_security_group ? 1 : 0

  name        = var.security_group_name
  name_prefix = var.security_group_name_prefix
  description = var.security_group_description
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    var.security_group_tags,
    { "Name" = try(coalesce(var.security_group_name, var.security_group_name_prefix), "") },
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "this" {
  for_each = { for k, v in var.security_group_rules : k => v if var.create_security_group }

  # Required
  security_group_id = aws_security_group.this[0].id
  protocol          = try(each.value.protocol, "tcp")
  from_port         = try(each.value.from_port, 443)
  to_port           = try(each.value.to_port, 443)
  type              = try(each.value.type, "ingress")

  # Optional
  description              = try(each.value.description, null)
  cidr_blocks              = lookup(each.value, "cidr_blocks", null)
  ipv6_cidr_blocks         = lookup(each.value, "ipv6_cidr_blocks", null)
  prefix_list_ids          = lookup(each.value, "prefix_list_ids", null)
  self                     = try(each.value.self, null)
  source_security_group_id = lookup(each.value, "source_security_group_id", null)
}
