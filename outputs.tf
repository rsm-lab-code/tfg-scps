
output "scp_policy_ids" {
  description = "SCP policy IDs"
  value = {
    for k, v in aws_organizations_policy.scp_policies : k => v.id
  }
}

output "scp_console_url" {
  description = "URL to manage SCPs"
  value = "https://console.aws.amazon.com/organizations/v2/home/policies/service-control-policy"
}
