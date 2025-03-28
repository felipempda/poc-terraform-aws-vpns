#!/bin/bash
instance_id_a=$(terraform output -json ec2-private-a | jq -r '.ec2_instance_id' )
instance_ip_a=$(terraform output -json ec2-private-a | jq -r '.private_ip' )
instance_vpn_id_b=$(terraform output -json ec2-vpn-b | jq -r '.ec2_instance_id' )
instance_id_b=$(terraform output -json ec2-private-b | jq -r '.ec2_instance_id' )
instance_ip_b=$(terraform output -json ec2-private-b | jq -r '.private_ip' )
region_a=$(terraform output -raw region-a )
region_b=$(terraform output -raw region-b )
dns_name_ec2_a=$(terraform output -json endpoints-a | jq -r '.ec2.dns_name' )
dns_name_ec2_b=$(terraform output -json endpoints-b | jq -r '.ec2.dns_name' )
echo ""
echo ""
echo "Connecting to instance vpn-b [${instance_vpn_id_b}] to check ipsec tunnel"
aws ssm start-session --target "$instance_vpn_id_b" --region $region_b --document-name AWS-StartInteractiveCommand --parameters command="export AWS_PAGER=""; set -x; date; hostname -I; sudo ipsec status; sudo ip xfrm policy show; sudo ip xfrm state show" | grep -v -e "Exiting session with sessionId" -e "Starting session with SessionId:"
echo ""
echo ""
echo "Connecting to instance private-a [${instance_id_a}] to test connectivity with vpc-b"
aws ssm start-session --target "$instance_id_a" --region $region_a --document-name AWS-StartInteractiveCommand --parameters command="export AWS_PAGER=""; set -x; date; hostname -I; ping -c 10 $instance_ip_b; nslookup $dns_name_ec2_b;  aws ec2 describe-vpcs --region $region_b --endpoint-url https://$dns_name_ec2_b  | grep VpcId && echo it works" | grep -v -e "Exiting session with sessionId" -e "Starting session with SessionId:"
echo ""
echo ""
echo "Connecting to instance private-b [${instance_id_b}] to test connectivity with vpc-a"
aws ssm start-session --target "$instance_id_b" --region $region_b --document-name AWS-StartInteractiveCommand --parameters command="export AWS_PAGER=""; set -x; date; hostname -I; ping -c 10 $instance_ip_a; nslookup $dns_name_ec2_a;  aws ec2 describe-vpcs --region $region_a --endpoint-url https://$dns_name_ec2_a  | grep VpcId && echo it works" | grep -v -e "Exiting session with sessionId" -e "Starting session with SessionId:"
echo ""
echo ""
