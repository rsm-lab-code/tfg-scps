# Get organization information
data "aws_organizations_organization" "main" {
  provider = aws.management_account
}

# 1. IDENTITY AND ACCESS MANAGEMENT POLICY
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
        Condition = {
          StringEquals = {
            "iam:PolicyDocument" = "*"
          }
        }
      },
      {
        Sid    = "RequireIAMInstanceRoles"
        Effect = "Deny"
        Action = [
          "ec2:RunInstances"
        ]
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          StringNotLike = {
            "ec2:IamInstanceProfile" = "*"
          }
        }
      }
    ]
  })

  description = "IAM security controls from TFG requirements"
  
  tags = {
    Name        = "IAMSecurityControls"
    Environment = "organization"
    ManagedBy   = "terraform"
  }
}

# 2. DATA STORAGE CONTROLS POLICY
resource "aws_organizations_policy" "data_storage_controls" {
  provider = aws.management_account
  count    = var.create_data_storage_policy ? 1 : 0
  
  name = "DataStorageControls"
  type = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnforceS3EncryptionAtRest"
        Effect = "Deny"
        Action = [
          "s3:PutObject"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = [
              "AES256",
              "aws:kms"
            ]
          }
        }
      },
      {
        Sid    = "EnforceHTTPSOnlyS3"
        Effect = "Deny"
        Action = "s3:*"
        Resource = "*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "BlockPublicS3Access"
        Effect = "Deny"
        Action = [
          "s3:PutBucketAcl",
          "s3:PutBucketPolicy",
          "s3:PutObjectAcl"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = [
              "public-read",
              "public-read-write",
              "authenticated-read"
            ]
          }
        }
      },
      {
        Sid    = "EnforceEBSEncryption"
        Effect = "Deny"
        Action = [
          "ec2:CreateVolume",
          "ec2:RunInstances"
        ]
        Resource = [
          "arn:aws:ec2:*:*:volume/*"
        ]
        Condition = {
          Bool = {
            "ec2:Encrypted" = "false"
          }
        }
      },
      {
        Sid    = "EnforceRDSEncryption"
        Effect = "Deny"
        Action = [
          "rds:CreateDBInstance",
          "rds:CreateDBCluster"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "rds:StorageEncrypted" = "false"
          }
        }
      },
      {
        Sid    = "RestrictPublicRDSAccess"
        Effect = "Deny"
        Action = [
          "rds:CreateDBInstance",
          "rds:ModifyDBInstance"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "rds:PubliclyAccessible" = "true"
          }
        }
      },
      {
        Sid    = "EnforceEFSEncryption"
        Effect = "Deny"
        Action = [
          "elasticfilesystem:CreateFileSystem"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "elasticfilesystem:Encrypted" = "false"
          }
        }
      }
    ]
  })

  description = "Data storage security controls from TFG requirements"
  
  tags = {
    Name        = "DataStorageControls"
    Environment = "organization"
    ManagedBy   = "terraform"
  }
}

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
          Bool = {
            "cloudtrail:KMSKeyId" = "false"
          }
        }
      }
    ]
  })

  description = "Logging protection controls from TFG requirements"
  
  tags = {
    Name        = "LoggingProtectionControls"
    Environment = "organization"
    ManagedBy   = "terraform"
  }
}

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
        Condition = {
          Bool = {
            "guardduty:Enable" = "false"
          }
        }
      },
      {
        Sid    = "RequireVPCFlowLogging"
        Effect = "Deny"
        Action = [
          "ec2:CreateVpc"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "aws:RequestTag/VPCFlowLogsEnabled" = "false"
          }
        }
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

  description = "Monitoring protection controls from TFG requirements"
  
  tags = {
    Name        = "MonitoringProtectionControls"
    Environment = "organization"
    ManagedBy   = "terraform"
  }
}

# 5. NETWORKING CONTROLS POLICY
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
          And = [
            {
              StringEquals = {
                "ec2:FromPort" = ["22", "3389", "1433", "3306", "5432", "1521"]
              }
            },
            {
              StringEquals = {
                "ec2:IpProtocol" = "tcp"
              }
            },
            {
              StringEquals = {
                "ec2:cidr" = "0.0.0.0/0"
              }
            }
          ]
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
      },
      {
        Sid    = "RequirePrivateLink"
        Effect = "Deny"
        Action = [
          "ec2:CreateVpcEndpoint"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "ec2:VpceServiceName" = "com.amazonaws.vpce.*"
          }
        }
      },
      {
        Sid    = "EnforceTLSVersion"
        Effect = "Deny"
        Action = [
          "elasticloadbalancing:CreateListener",
          "elasticloadbalancing:ModifyListener"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "elasticloadbalancing:SecurityPolicy" = [
              "ELBSecurityPolicy-TLS-1-2-2017-01",
              "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
              "ELBSecurityPolicy-FS-1-2-Res-2020-10"
            ]
          }
        }
      }
    ]
  })

  description = "Networking security controls from TFG requirements"
  
  tags = {
    Name        = "NetworkingSecurityControls"
    Environment = "organization"
    ManagedBy   = "terraform"
  }
}

# POLICY ATTACHMENTS 
resource "aws_organizations_policy_attachment" "iam_controls_attachment" {
  provider  = aws.management_account
  count     = var.attach_policies && var.create_iam_controls_policy ? 1 : 0
  
  policy_id = aws_organizations_policy.iam_controls[0].id
  target_id = var.target_ou_id != "" ? var.target_ou_id : data.aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_policy_attachment" "data_storage_attachment" {
  provider  = aws.management_account
  count     = var.attach_policies && var.create_data_storage_policy ? 1 : 0
  
  policy_id = aws_organizations_policy.data_storage_controls[0].id
  target_id = var.target_ou_id != "" ? var.target_ou_id : data.aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_policy_attachment" "logging_protection_attachment" {
  provider  = aws.management_account
  count     = var.attach_policies && var.create_logging_policy ? 1 : 0
  
  policy_id = aws_organizations_policy.logging_protection[0].id
  target_id = var.target_ou_id != "" ? var.target_ou_id : data.aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_policy_attachment" "monitoring_protection_attachment" {
  provider  = aws.management_account
  count     = var.attach_policies && var.create_monitoring_policy ? 1 : 0
  
  policy_id = aws_organizations_policy.monitoring_protection[0].id
  target_id = var.target_ou_id != "" ? var.target_ou_id : data.aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_policy_attachment" "networking_controls_attachment" {
  provider  = aws.management_account
  count     = var.attach_policies && var.create_networking_policy ? 1 : 0
  
  policy_id = aws_organizations_policy.networking_controls[0].id
  target_id = var.target_ou_id != "" ? var.target_ou_id : data.aws_organizations_organization.main.roots[0].id
}