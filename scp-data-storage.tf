# Data Storage Security Controls Policy
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

  description = "Data storage security controls"
  
  tags = {
    Name        = "DataStorageControls"
    Environment = "organization"
    ManagedBy   = "terraform"
  }
}

# Policy attachment
resource "aws_organizations_policy_attachment" "data_storage_attachment" {
  provider  = aws.management_account
  count     = var.attach_policies && var.create_data_storage_policy ? 1 : 0
  
  policy_id = aws_organizations_policy.data_storage_controls[0].id
  target_id = var.target_ou_id != "" ? var.target_ou_id : data.aws_organizations_organization.main.roots[0].id
}
