# 3. LOGGING PROTECTION POLICY
resource "aws_organizations_policy" "logging_protection" {
  provider = aws.management_account
  count    = var.create_logging_policy ? 1 : 0
  
  name = "LoggingProtectionControls"
  type = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ProtectCloudTrail"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "cloudtrail:PutEventSelectors",
          "cloudtrail:UpdateTrail"
        ]
        Resource = "*"
      },
      {
        Sid    = "EnforceCloudTrailEncryption"
        Effect = "Deny"
        Action = [
          "cloudtrail:CreateTrail",
          "cloudtrail:UpdateTrail"
        ]
        Resource = "*"
        Condition = {
          Null = {
            "cloudtrail:KMSKeyId" = "true"
          }
        }
      }
    ]
  })

  description = "Logging protection controls"
  
  tags = {
    Name        = "LoggingProtectionControls"
    Environment = "organization"
    ManagedBy   = "terraform"
  }
}


resource "aws_organizations_policy_attachment" "logging_protection_attachment" {
  provider  = aws.management_account
  count     = var.attach_policies && var.create_logging_policy ? 1 : 0

  policy_id = aws_organizations_policy.logging_protection[0].id
  target_id = var.target_ou_id != "" ? var.target_ou_id : data.aws_organizations_organization.main.roots[0].id
}

