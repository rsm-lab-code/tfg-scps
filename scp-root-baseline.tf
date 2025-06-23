#Root level SCPS
resource "aws_organizations_policy" "root_baseline" {
  provider = aws.management_account
  count    = var.create_root_baseline_policy ? 1 : 0
  
  name = "RootBaselineControls"
  type = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # IAM Security Controls
      {
        Sid    = "DenyRootUserActions"
        Effect = "Deny"
        Action = "*"
        Resource = "*"
        Condition = {
          "StringEquals": {
            "aws:PrincipalType": "Root"
          }
        }
      },
      #Prevent accounts from leaving organization
      {
      "Sid": "DenyLeaveOrganization",
      "Effect": "Deny",
      "Action": "organizations:LeaveOrganization",
      "Resource": "*"
     },

     #Deny root access key creation 
      {
        Sid    = "DenyRootAccessKeyCreation"
        Effect = "Deny"
        Action = [
          "iam:CreateAccessKey"
        ]
        Resource = "arn:aws:iam::*:user/root"
      },

      #Deny Weak Password
      {
        Sid    = "DenyWeakPasswordPolicies"
        Effect = "Deny"
        Action = [
          "iam:UpdateAccountPasswordPolicy"
        ]
        Resource = "*"
        Condition = {
          "NumericLessThan": {
            "iam:MinPasswordLength": "14"
          }
        }
      },
      # Logging Protection
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
      #Enforce Cloud Trail Encrypiton 
      {
        Sid    = "EnforceCloudTrailEncryption"
        Effect = "Deny"
        Action = [
          "cloudtrail:CreateTrail",
          "cloudtrail:UpdateTrail"
        ]
        Resource = "*"
        Condition = {
          "Null": {
            "cloudtrail:KMSKeyId": "true"
          }
        }
      },
      # Protect Guard Duty 
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
      # Regional Compliance
      {
        Sid    = "RequireApprovedRegions"
        Effect = "Deny"
        NotAction = [
          "iam:*",
          "organizations:*",
          "support:*",
          "trustedadvisor:*",
          "cloudfront:*",
          "route53:*",
          "waf:*",
          "cloudtrail:LookupEvents"
        ]
        Resource = "*"
        Condition = {
          "StringNotEquals": {
            "aws:RequestedRegion": ["us-west-2", "us-east-1"]
          }
        }
      }
    ]
  })

  description = "Organization-wide baseline security controls"
  
  tags = {
    Name        = "RootBaselineControls"
    Environment = "organization"
    Level       = "root"
    ManagedBy   = "terraform"
  }
}

# Attach to root OU
resource "aws_organizations_policy_attachment" "root_baseline_attachment" {
  provider  = aws.management_account
  count     = var.attach_root_policies && var.create_root_baseline_policy ? 1 : 0
  
  policy_id = aws_organizations_policy.root_baseline[0].id
  target_id = data.aws_organizations_organization.main.roots[0].id
}
