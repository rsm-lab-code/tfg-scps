# ORGANIZATION INFO

output "organization_id" {
  description = "AWS Organization ID"
  value       = data.aws_organizations_organization.main.id
}

# TIERED POLICY IDS

output "root_baseline_policy_id" {
  description = "ID of the root baseline policy"
  value       = var.create_root_baseline_policy ? aws_organizations_policy.root_baseline[0].id : null
}

output "prod_controls_policy_id" {
  description = "ID of the production controls policy"
  value       = var.create_prod_controls_policy ? aws_organizations_policy.prod_controls[0].id : null
}

output "nonprod_controls_policy_id" {
  description = "ID of the non-production controls policy"
  value       = var.create_nonprod_controls_policy ? aws_organizations_policy.nonprod_controls[0].id : null
}

# POLICY ATTACHMENT STATUS

output "policies_attached" {
  description = "Status of policy attachments"
  value = {
    root_policies_attached    = var.attach_root_policies
    prod_policies_attached    = var.attach_prod_policies
    nonprod_policies_attached = var.attach_nonprod_policies
  }
}

# OU TARGETING INFO

output "target_ou_info" {
  description = "OU targeting information"
  value = {
    root_id      = data.aws_organizations_organization.main.roots[0].id
    prod_ou_id   = var.prod_ou_id
    nonprod_ou_id = var.nonprod_ou_id
  }
}

# SCP CONSOLE URL

output "scp_console_url" {
  description = "URL to manage SCPs in AWS Console"
  value       = "https://console.aws.amazon.com/organizations/v2/home/policies/service-control-policy"
}

# TIERED SCP SUMMARY

output "tiered_scp_summary" {
  description = "Summary of tiered SCP implementation"
  value = {
    architecture = "3-tier (Root → Prod/NonProd OUs)"
    policies_created = {
      root_baseline = var.create_root_baseline_policy
      prod_controls = var.create_prod_controls_policy
      nonprod_controls = var.create_nonprod_controls_policy
    }
    policies_attached = {
      root_attached = var.attach_root_policies
      prod_attached = var.attach_prod_policies
      nonprod_attached = var.attach_nonprod_policies
    }
    policy_hierarchy = {
      description = "Root policies apply to all accounts, OU policies add environment-specific controls"
      prod_accounts_get = ["Root Baseline", "Production Controls"]
      nonprod_accounts_get = ["Root Baseline", "NonProd Controls"]
    }
  }
}
