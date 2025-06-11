output "organization_id" {
  description = "AWS Organization ID"
  value       = data.aws_organizations_organization.main.id
}

# Individual policy IDs
output "iam_controls_policy_id" {
  description = "ID of the IAM controls policy"
  value       = var.create_iam_controls_policy ? aws_organizations_policy.iam_controls[0].id : null
}

output "data_storage_policy_id" {
  description = "ID of the data storage controls policy"
  value       = var.create_data_storage_policy ? aws_organizations_policy.data_storage_controls[0].id : null
}

output "logging_policy_id" {
  description = "ID of the logging protection policy"
  value       = var.create_logging_policy ? aws_organizations_policy.logging_protection[0].id : null
}

output "monitoring_policy_id" {
  description = "ID of the monitoring protection policy"
  value       = var.create_monitoring_policy ? aws_organizations_policy.monitoring_protection[0].id : null
}

output "networking_policy_id" {
  description = "ID of the networking controls policy"
  value       = var.create_networking_policy ? aws_organizations_policy.networking_controls[0].id : null
}

# Policy attachment information
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