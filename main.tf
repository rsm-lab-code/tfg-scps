# Get organization information
data "aws_organizations_organization" "main" {
  provider = aws.management_account
}

# Process policy files from the policies directory
locals {
  # Get all JSON files from the policies directory
  policy_files = fileset(path.root, "policies/scp_target_ou/*.json")
  
  # Create a map of policy configurations
  policies = {
    for file in local.policy_files : 
    replace(basename(file), ".json", "") => {
      name = replace(basename(file), ".json", "")
      content = file("${path.root}/${file}")
      file_path = file
    }
  }
}

# Create SCP policies from JSON files
resource "aws_organizations_policy" "scp_policies" {
  provider = aws.management_account
  for_each = var.attach_policies ? local.policies : {}

  name        = each.value.name
  description = "SCP policy ${each.value.name}"
  type        = "SERVICE_CONTROL_POLICY"
  content     = each.value.content

  tags = {
    Name      = each.value.name
    Source    = each.value.file_path
    ManagedBy = "terraform"
  }
}

# Attach policies to the target OU
resource "aws_organizations_policy_attachment" "scp_attachments" {
  provider  = aws.management_account
  for_each  = var.attach_policies ? local.policies : {}
  
  policy_id = aws_organizations_policy.scp_policies[each.key].id
  target_id = var.target_ou_id != "" ? var.target_ou_id : data.aws_organizations_organization.main.roots[0].id
}
