# IDENTITY AND ACCESS MANAGEMENT POLICY

resource "aws_organizations_policy" "iam_controls" {
  provider = aws.management_account
  count    = var.create_iam_controls_policy ? 1 : 0
  
  name = "IAMSecurityControls"
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
      },
      {
        Sid    = "DenyRootAccessKeyCreation"
        Effect = "Deny"
        Action = [
          "iam:CreateAccessKey"
        ]
        Resource = "arn:aws:iam::*:user/root"
      },
      {
        Sid    = "DenyWeakPasswordPolicies"
        Effect = "Deny"
        Action = [
          "iam:UpdateAccountPasswordPolicy"
        ]
        Resource = "*"
        Condition = {
          NumericLessThan = {
            "iam:MinPasswordLength" = "14"
          }
        }
      },
      {
        Sid    = "DenyFullAdminPolicies"
        Effect = "Deny"
        Action = [
          "iam:CreatePolicy",
          "iam:CreatePolicyVersion",
          "iam:AttachUserPolicy",
          "iam:AttachGroupPolicy",
          "iam:AttachRolePolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "RequireIAMInstanceRoles"
        Effect = "Deny"
        Action = [
          "ec2:RunInstances"
        ]
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          Null = {
            "ec2:IamInstanceProfile" = "true"
          }
        }
      }
    ]
  })

  description = "IAM security controls"
  
  tags = {
    Name        = "IAMSecurityControls"
    Environment = "organization"
    ManagedBy   = "terraform"
  }
}

# Policy attachment
resource "aws_organizations_policy_attachment" "iam_controls_attachment" {
  provider  = aws.management_account
  count     = var.attach_policies && var.create_iam_controls_policy ? 1 : 0
  
  policy_id = aws_organizations_policy.iam_controls[0].id
  target_id = var.target_ou_id != "" ? var.target_ou_id : data.aws_organizations_organization.main.roots[0].id
}
