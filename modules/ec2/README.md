# module ec2

Create a EC2 instance with a user data script ready to install libreswan

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.79 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.79 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_eip_association.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip_association) | resource |
| [aws_instance.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance) | resource |
| [aws_security_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group_rule.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_ami.latest](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [aws_eip.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/eip) | data source |
| [aws_region.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_allocation_id"></a> [allocation\_id](#input\_allocation\_id) | EIP public IP association | `string` | `""` | no |
| <a name="input_ami_id"></a> [ami\_id](#input\_ami\_id) | AMI\_ID to be used. Null means latest Amazon 2023 | `string` | `""` | no |
| <a name="input_ami_latest_names"></a> [ami\_latest\_names](#input\_ami\_latest\_names) | AMI\_ID to be used. Null means latest Amazon 2023 | `set(string)` | <pre>[<br/>  "al2023-ami-2023*x86_64"<br/>]</pre> | no |
| <a name="input_ami_latest_owners"></a> [ami\_latest\_owners](#input\_ami\_latest\_owners) | AMI\_ID to be used. Null means latest Amazon 2023 | `set(string)` | <pre>[<br/>  "amazon"<br/>]</pre> | no |
| <a name="input_associate_public_ip_address"></a> [associate\_public\_ip\_address](#input\_associate\_public\_ip\_address) | n/a | `bool` | `true` | no |
| <a name="input_create_security_group"></a> [create\_security\_group](#input\_create\_security\_group) | Determines if a security group is created | `bool` | `false` | no |
| <a name="input_iam_instance_profile"></a> [iam\_instance\_profile](#input\_iam\_instance\_profile) | IAM Profile to be used | `string` | `null` | no |
| <a name="input_instance_type"></a> [instance\_type](#input\_instance\_type) | n/a | `string` | `"t3a.micro"` | no |
| <a name="input_key_name"></a> [key\_name](#input\_key\_name) | Key\_name to be used | `string` | `null` | no |
| <a name="input_security_group_description"></a> [security\_group\_description](#input\_security\_group\_description) | Description of the security group created | `string` | `null` | no |
| <a name="input_security_group_ids"></a> [security\_group\_ids](#input\_security\_group\_ids) | Default security group IDs to associate with the VPC endpoints | `list(string)` | `[]` | no |
| <a name="input_security_group_name"></a> [security\_group\_name](#input\_security\_group\_name) | Name to use on security group created. Conflicts with `security_group_name_prefix` | `string` | `null` | no |
| <a name="input_security_group_name_prefix"></a> [security\_group\_name\_prefix](#input\_security\_group\_name\_prefix) | Name prefix to use on security group created. Conflicts with `security_group_name` | `string` | `null` | no |
| <a name="input_security_group_rules"></a> [security\_group\_rules](#input\_security\_group\_rules) | Security group rules to add to the security group created | `any` | `{}` | no |
| <a name="input_security_group_tags"></a> [security\_group\_tags](#input\_security\_group\_tags) | A map of additional tags to add to the security group created | `map(string)` | `{}` | no |
| <a name="input_source_dest_check"></a> [source\_dest\_check](#input\_source\_dest\_check) | n/a | `bool` | `false` | no |
| <a name="input_subnet_id"></a> [subnet\_id](#input\_subnet\_id) | Subnet\_id to be used | `string` | n/a | yes |
| <a name="input_tags"></a> [tags](#input\_tags) | n/a | `map(string)` | `{}` | no |
| <a name="input_use_allocation_id"></a> [use\_allocation\_id](#input\_use\_allocation\_id) | Use allocation\_id provided in allocation\_id | `bool` | `true` | no |
| <a name="input_user_data_replace_on_change"></a> [user\_data\_replace\_on\_change](#input\_user\_data\_replace\_on\_change) | n/a | `bool` | `true` | no |
| <a name="input_user_data_template_file_name"></a> [user\_data\_template\_file\_name](#input\_user\_data\_template\_file\_name) | User data file to use. Default none. Options 'libreswan' | `string` | `"none"` | no |
| <a name="input_user_data_vars"></a> [user\_data\_vars](#input\_user\_data\_vars) | Map of values to be used by user\_data template file | `map(string)` | `{}` | no |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | VPC\_ID where to create security group | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_connect_to_ec2_command"></a> [connect\_to\_ec2\_command](#output\_connect\_to\_ec2\_command) | AWS cli command to connect via Session Manager |
| <a name="output_ec2_instance_id"></a> [ec2\_instance\_id](#output\_ec2\_instance\_id) | Instance id |
| <a name="output_network_id"></a> [network\_id](#output\_network\_id) | Primary Network ID |
| <a name="output_private_ip"></a> [private\_ip](#output\_private\_ip) | Private IP |
| <a name="output_public_ip"></a> [public\_ip](#output\_public\_ip) | Public IP (optional) |
<!-- END_TF_DOCS -->
