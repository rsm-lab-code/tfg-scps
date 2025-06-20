# scp-prod-controls
resource "aws_organizations_policy" "prod_controls" {
  provider = aws.management_account
  count    = var.create_prod_controls_policy ? 1 : 0
  
  name = "ProductionControls"
  type = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Data Storage Security
      {
        Sid    = "EnforceS3EncryptionAtRest"
        Effect = "Deny"
        Action = [
          "s3:PutObject"
        ]
        Resource = "*"
        Condition = {
          "StringNotEquals": {
            "s3:x-amz-server-side-encryption": [
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
          "Bool": {
            "aws:SecureTransport": "false"
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
      },
      # EBS/RDS Encryption
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
          "Bool": {
            "ec2:Encrypted": "false"
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
          "Bool": {
            "rds:StorageEncrypted": "false"
          }
        }
      },
      # Resource Deletion Protection
      {
        Sid    = "DenyResourceDeletionWithoutMFA"
        Effect = "Deny"
        Action = [
          "ec2:TerminateInstances",
          "rds:DeleteDBInstance",
          "rds:DeleteDBCluster",
          "s3:DeleteBucket"
        ]
        Resource = "*"
        Condition = {
          "Bool": {
            "aws:MultiFactorAuthPresent": "false"
          }
        }
      },
      # Network Security
      {
        Sid    = "DenyServerAdminPortsFromInternet"
        Effect = "Deny"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress"
        ]
        Resource = "*"
        Condition = {
          "StringEquals": {
            "ec2:FromPort": ["22", "3389", "1433", "3306", "5432", "1521"],
            "ec2:IpProtocol": "tcp",
            "ec2:cidr": "0.0.0.0/0"
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
          "StringEquals": {
            "ec2:GroupName": "default"
          }
        }
      },
      # Restrict Public RDS Access
      {
        Sid    = "RestrictPublicRDSAccess"
        Effect = "Deny"
        Action = [
          "rds:CreateDBInstance",
          "rds:ModifyDBInstance"
        ]
        Resource = "*"
        Condition = {
          "Bool": {
            "rds:PubliclyAccessible": "true"
          }
        }
      }
    ]
  })

  description = "Strict controls for production environments"
  
  tags = {
    Name        = "ProductionControls"
    Environment = "production"
    Level       = "prod-ou"
    ManagedBy   = "terraform"
  }
}

# Attach to production OU
resource "aws_organizations_policy_attachment" "prod_controls_attachment" {
  provider  = aws.management_account
  count     = var.attach_prod_policies && var.create_prod_controls_policy ? 1 : 0
  
  policy_id = aws_organizations_policy.prod_controls[0].id
  target_id = var.prod_ou_id
}
