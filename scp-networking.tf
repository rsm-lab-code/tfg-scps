# NETWORKING CONTROLS POLICY
resource "aws_organizations_policy" "networking_controls" {
  provider = aws.management_account
  count    = var.create_networking_policy ? 1 : 0
  
  name = "NetworkingSecurityControls"
  type = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyServerAdminPortsFromInternet"
        Effect = "Deny"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:FromPort" = ["22", "3389", "1433", "3306", "5432", "1521"]
            "ec2:IpProtocol" = "tcp"
            "ec2:cidr" = "0.0.0.0/0"
          }
        }
      },
      {
        Sid    = "RestrictDefaultSecurityGroup"
        Effect = "Deny"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:GroupName" = "default"
          }
        }
      }
    ]
  })

  description = "Networking security controls"
  
  tags = {
    Name        = "NetworkingSecurityControls"
    Environment = "organization"
    ManagedBy   = "terraform"
  }
}


resource "aws_organizations_policy_attachment" "networking_controls_attachment" {
  provider  = aws.management_account
  count     = var.attach_policies && var.create_networking_policy ? 1 : 0

  policy_id = aws_organizations_policy.networking_controls[0].id
  target_id = var.target_ou_id != "" ? var.target_ou_id : data.aws_organizations_organization.main.roots[0].id
}
