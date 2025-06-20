# 4. MONITORING PROTECTION POLICY
resource "aws_organizations_policy" "monitoring_protection" {
  provider = aws.management_account
  count    = var.create_monitoring_policy ? 1 : 0
  
  name = "MonitoringProtectionControls"
  type = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ProtectGuardDuty"
        Effect = "Deny"
        Action = [
          "guardduty:DeleteDetector",
          "guardduty:DisassociateFromMasterAccount",
          "guardduty:DisassociateMembers",
          "guardduty:StopMonitoringMembers",
          "guardduty:UpdateDetector"
        ]
        Resource = "*"
      },
      {
        Sid    = "ProtectVPCFlowLogs"
        Effect = "Deny"
        Action = [
          "ec2:DeleteFlowLogs"
        ]
        Resource = "*"
      }
    ]
  })

  description = "Monitoring protection controls"
  
  tags = {
    Name        = "MonitoringProtectionControls"
    Environment = "organization"
    ManagedBy   = "terraform"
  }
}

resource "aws_organizations_policy_attachment" "monitoring_protection_attachment" {
  provider  = aws.management_account
  count     = var.attach_policies && var.create_monitoring_policy ? 1 : 0
  
  policy_id = aws_organizations_policy.monitoring_protection[0].id
  target_id = var.target_ou_id != "" ? var.target_ou_id : data.aws_organizations_organization.main.roots[0].id
}

