# Get organization information
data "aws_organizations_organization" "main" {
  provider = aws.management_account
}

#DENY ROOT USER
resource "aws_organizations_policy" "deny_root_user" {
  provider = aws.management_account
  count    = var.create_deny_root_policy ? 1 : 0
  
  name = "DenyRootUserActions"
  type = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyRootUserActions"
        Effect = "Deny"
        Action = "*"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:PrincipalType" = "Root"
          }
        }
      }
    ]
  })

  description = "Prevent use of root user credentials"
  
  tags = {
    Name        = "DenyRootUserActions"
    Environment = "organization"
    ManagedBy   = "terraform"
  }
}

#DENY EXPENSIVE INSTANCES
resource "aws_organizations_policy" "deny_expensive_instances" {
  provider = aws.management_account
  count    = var.create_cost_control_policy ? 1 : 0
  
  name = "DenyExpensiveInstances"
  type = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyExpensiveEC2Instances"
        Effect = "Deny"
        Action = [
          "ec2:RunInstances"
        ]
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          StringEquals = {
            "ec2:InstanceType" = [
              "c5.24xlarge",
              "m5.24xlarge", 
              "r5.24xlarge",
              "x1.32xlarge"
            ]
          }
        }
      }
    ]
  })

  description = "Prevent creation of expensive EC2 instance types"
  
  tags = {
    Name        = "DenyExpensiveInstances"
    Environment = "organization"
    ManagedBy   = "terraform"
  }
}

# POLICY ATTACHMENTS 
resource "aws_organizations_policy_attachment" "deny_root_user_attachment" {
  provider  = aws.management_account
  count     = var.attach_policies && var.create_deny_root_policy ? 1 : 0
  
  policy_id = aws_organizations_policy.deny_root_user[0].id
  target_id = var.target_ou_id != "" ? var.target_ou_id : data.aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_policy_attachment" "deny_expensive_instances_attachment" {
  provider  = aws.management_account
  count     = var.attach_policies && var.create_cost_control_policy ? 1 : 0
  
  policy_id = aws_organizations_policy.deny_expensive_instances[0].id
  target_id = var.target_ou_id != "" ? var.target_ou_id : data.aws_organizations_organization.main.roots[0].id
}
