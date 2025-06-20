resource "aws_organizations_policy" "nonprod_controls" {
  provider = aws.management_account
  count    = var.create_nonprod_controls_policy ? 1 : 0
  
  name = "NonProdControls"
  type = "SERVICE_CONTROL_POLICY"
  
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Cost Control - Instance Size Limits
      {
        Sid    = "LimitExpensiveInstanceSizes"
        Effect = "Deny"
        Action = [
          "ec2:RunInstances"
        ]
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          ForAnyValue:StringLike = {
            "ec2:InstanceType" = [
              "*.2xlarge",
              "*.4xlarge",
              "*.8xlarge",
              "*.12xlarge",
              "*.16xlarge",
              "*.24xlarge",
              "*.metal"
            ]
          }
        }
      },
      # Cost Control - RDS Instance Limits
      {
        Sid    = "LimitRDSInstanceSize"
        Effect = "Deny"
        Action = [
          "rds:CreateDBInstance",
          "rds:ModifyDBInstance"
        ]
        Resource = "*"
        Condition = {
          ForAnyValue:StringLike = {
            "rds:DBInstanceClass" = [
              "*.large",
              "*.xlarge",
              "*.2xlarge",
              "*.4xlarge",
              "*.8xlarge"
            ]
          }
        }
      },
      # Tagging Requirements
      {
        Sid    = "RequireEnvironmentTags"
        Effect = "Deny"
        Action = [
          "ec2:RunInstances",
          "rds:CreateDBInstance",
          "s3:CreateBucket"
        ]
        Resource = "*"
        Condition = {
          Null = {
            "aws:RequestTag/Environment" = "true"
          }
        }
      },
      {
        Sid    = "RequireOwnerTags"
        Effect = "Deny"
        Action = [
          "ec2:RunInstances",
          "rds:CreateDBInstance"
        ]
        Resource = "*"
        Condition = {
          Null = {
            "aws:RequestTag/Owner" = "true"
          }
        }
      },
      # Development Restrictions
      {
        Sid    = "DenyProductionServices"
        Effect = "Deny"
        Action = [
          "workspaces:*",
          "directconnect:*",
          "route53domains:*"
        ]
        Resource = "*"
      },
      # Basic Data Protection (lighter than prod)
      {
        Sid    = "RequireS3VersioningOnImportantBuckets"
        Effect = "Deny"
        Action = [
          "s3:CreateBucket"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "s3:BucketName" = [
              "*prod*",
              "*backup*",
              "*archive*"
            ]
          }
        }
      },
      # Region Restrictions (allow more flexibility than prod)
      {
        Sid    = "DenyRestrictedRegions"
        Effect = "Deny"
        Action = "*"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = [
              "ap-southeast-3",
              "eu-south-1",
              "af-south-1"
            ]
          }
        }
      }
    ]
  })

  description = "Cost and resource controls for non-production environments"
  
  tags = {
    Name        = "NonProdControls"
    Environment = "nonprod"
    Level       = "nonprod-ou"
    ManagedBy   = "terraform"
  }
}

# Attach to non-production OU
resource "aws_organizations_policy_attachment" "nonprod_controls_attachment" {
  provider  = aws.management_account
  count     = var.attach_nonprod_policies && var.create_nonprod_controls_policy ? 1 : 0
  
  policy_id = aws_organizations_policy.nonprod_controls[0].id
  target_id = var.nonprod_ou_id
}
