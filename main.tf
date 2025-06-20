# Get organization information
data "aws_organizations_organization" "main" {
  provider = aws.management_account
}

