output "organization_id" {
  description = "AWS Organization ID"
  value       = data.aws_organizations_organization.main.id
}

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

output "policies_attached" {
  description = "Whether policies are attached"
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
