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

output "debug_scp_vars" {
  value = {
    attach_scp_policies = var.attach_scp_policies
    scp_target_ou_id = var.scp_target_ou_id
    management_account_id = var.management_account_id
  }
}
