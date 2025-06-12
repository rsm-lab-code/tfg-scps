# Multi-OU SCP Implementation
locals {
  # Process each OU's policy files safely
  ou_policy_files = {
    for ou_name, ou_config in var.ou_configurations : ou_name => {
      all_files = ou_config.enabled ? fileset(path.root, "${ou_config.policy_directory}/*.json") : []
      # Take minimum of 5 or actual file count
      files_to_use = ou_config.enabled ? tolist(slice(sort(tolist(fileset(path.root, "${ou_config.policy_directory}/*.json"))), 0, min(5, length(fileset(path.root, "${ou_config.policy_directory}/*.json"))))) : []
    }
  }

  # Flatten all policies across all OUs
  all_policies = merge([
    for ou_name, ou_config in var.ou_configurations : 
    ou_config.enabled ? {
      for file in local.ou_policy_files[ou_name].files_to_use : 
      "${ou_name}_${replace(basename(file), ".json", "")}" => {
        file_path = file
        policy_name = replace(basename(file), ".json", "")
        ou_id = ou_config.ou_id
      }
    } : {}
  ]...)
}

# Create SCP policies
resource "aws_organizations_policy" "scp_policies" {
  provider = aws.management_account
  for_each = local.all_policies

  name        = each.value.policy_name
  description = "SCP policy ${each.value.policy_name}"
  type        = "SERVICE_CONTROL_POLICY"
  content     = file("${path.root}/${each.value.file_path}")

  tags = {
    Name      = each.value.policy_name
    Source    = each.value.file_path
    ManagedBy = "terraform"
  }
}

# Attach policies to OUs
resource "aws_organizations_policy_attachment" "scp_attachments" {
  provider  = aws.management_account
  for_each  = local.all_policies
  
  policy_id = aws_organizations_policy.scp_policies[each.key].id
  target_id = each.value.ou_id
}
