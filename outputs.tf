output "scp_policy_ids" {
  description = "SCP policy IDs"
  value = {
    for k, v in aws_organizations_policy.scp_policies : k => v.id
  }
}

output "scp_policy_arns" {
  description = "SCP policy ARNs"
  value = {
    for k, v in aws_organizations_policy.scp_policies : k => v.arn
  }
}