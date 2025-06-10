output "organization_id" {
  description = "AWS Organization ID"
  value       = data.aws_organizations_organization.main.id
}

output "deny_root_policy_id" {
  description = "ID of the deny root user policy"
  value       = var.create_deny_root_policy ? aws_organizations_policy.deny_root_user[0].id : null
}

output "cost_control_policy_id" {
  description = "ID of the cost control policy"
  value       = var.create_cost_control_policy ? aws_organizations_policy.deny_expensive_instances[0].id : null
}

output "policies_attached" {
  description = "Whether policies are attached to organization"
  value       = var.attach_policies
}

output "target_id" {
  description = "Target ID where policies are attached"
  value       = var.target_ou_id != "" ? var.target_ou_id : data.aws_organizations_organization.main.roots[0].id
}

output "scp_console_url" {
  description = "URL to manage SCPs in AWS Console"
  value       = "https://console.aws.amazon.com/organizations/v2/home/policies/service-control-policy"
}
